#!/usr/bin/env python3
"""Run the brokered repair canary through a real localhost TLS socket.

This is still non-authoritative and zero-cost. The broker client serializes an
HTTP/1.1 request over a verified TLS connection to a localhost test server whose
certificate is issued for provider-broker.internal. The server terminates TLS,
parses the wire request, forwards it to the existing Factory HTTP application,
and serializes the application response back over TLS. The repair itself still
uses the real hardened Docker runtime and zero-cost dry-run provider target.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import ssl
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from factory_runtime.brokered_repair import build_docker_brokered_ci_repair_runtime  # noqa: E402
from factory_runtime.detector import BaseImagePolicy  # noqa: E402
from factory_runtime.docker_provisioner import DockerProvisioningPolicy  # noqa: E402
from factory_runtime.docker_sandbox import workspace_tree_digest  # noqa: E402
from factory_runtime.provider_broker import (  # noqa: E402
    BrokerHTTPResponse,
    EphemeralBrokerCredential,
    ProviderBrokerBudget,
    load_provider_broker_binding,
)
from factory_runtime.provider_broker_http import (  # noqa: E402
    BrokerHTTPRequest,
    ReferenceProviderBrokerHTTPApplication,
)
from factory_runtime.provider_broker_service import (  # noqa: E402
    BrokerAuthContext,
    ReferenceProviderBrokerService,
)
from factory_runtime.provider_targets import (  # noqa: E402
    CatalogProviderSelectorResolver,
    DryRunProviderInvoker,
    ScriptedDryRunDecisionEngine,
    StaticProviderSelectorValueSource,
)
from factory_runtime.repair import RepairPolicy, RepairRequest, VerifiedRepairCandidate  # noqa: E402
from factory_runtime.structured_repair import StructuredRepairPolicy  # noqa: E402
from factory_runtime.trace_store_sqlite import SQLiteBrokeredRepairTraceStore  # noqa: E402

PINNED_PYTHON_IMAGE = re.compile(r"^python@sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
CANARY_TOKEN = "factory-broker-tls-canary-token-0001"
BROKER_ENDPOINT = "https://provider-broker.internal/v1/repair/decide"
BROKER_HOST = "provider-broker.internal"


class CanaryCredentialSource:
    def __init__(self) -> None:
        self.issue_count = 0

    async def issue(self, *, audience: str) -> EphemeralBrokerCredential:
        if audience != BROKER_HOST:
            raise AssertionError("TLS canary requested an unexpected credential audience")
        self.issue_count += 1
        now = datetime.now(timezone.utc)
        return EphemeralBrokerCredential(
            token=CANARY_TOKEN,
            audience=audience,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


class CanaryBearerAuthenticator:
    def __init__(self) -> None:
        self.auth_count = 0

    async def authenticate(self, token: str) -> BrokerAuthContext:
        if token != CANARY_TOKEN:
            raise AssertionError("TLS broker edge received an unexpected Bearer token")
        self.auth_count += 1
        now = datetime.now(timezone.utc)
        return BrokerAuthContext(
            subject="engineering_agent_service",
            audience=BROKER_HOST,
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=5),
        )


def _parse_content_length(headers: tuple[tuple[str, str], ...]) -> int:
    values = [value for name, value in headers if name.lower() == "content-length"]
    if len(values) != 1:
        raise RuntimeError("TLS broker request/response must have exactly one Content-Length")
    try:
        value = int(values[0])
    except ValueError as exc:
        raise RuntimeError("TLS broker Content-Length is invalid") from exc
    if value < 0 or value > 1024 * 1024:
        raise RuntimeError("TLS broker Content-Length exceeds canary bound")
    return value


class LocalTLSBrokerServer:
    def __init__(
        self,
        application: ReferenceProviderBrokerHTTPApplication,
        cert_path: Path,
        key_path: Path,
    ) -> None:
        self.application = application
        self.cert_path = cert_path
        self.key_path = key_path
        self.server: asyncio.AbstractServer | None = None
        self.port: int | None = None
        self.tls_connections = 0
        self.requests = 0
        self.errors: list[str] = []
        self.tls_versions: list[str] = []

    async def start(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert_path, self.key_path)
        self.server = await asyncio.start_server(
            self._handle,
            host="127.0.0.1",
            port=0,
            ssl=context,
            limit=256 * 1024,
        )
        sockets = self.server.sockets or []
        if len(sockets) != 1:
            raise RuntimeError("TLS broker canary expected exactly one listening socket")
        self.port = int(sockets[0].getsockname()[1])

    async def close(self) -> None:
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()
        self.server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise RuntimeError("broker server accepted a non-TLS connection")
            version = ssl_object.version()
            if version not in {"TLSv1.2", "TLSv1.3"}:
                raise RuntimeError("broker server negotiated an unsupported TLS version")
            self.tls_connections += 1
            self.tls_versions.append(version)

            header_block = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
            if len(header_block) > 64 * 1024:
                raise RuntimeError("broker TLS request headers exceed canary bound")
            lines = header_block[:-4].decode("iso-8859-1").split("\r\n")
            request_line = lines[0].split(" ")
            if len(request_line) != 3 or request_line[2] != "HTTP/1.1":
                raise RuntimeError("broker TLS request line is invalid")
            method, path, _version = request_line
            headers: list[tuple[str, str]] = []
            for line in lines[1:]:
                if ":" not in line:
                    raise RuntimeError("broker TLS request header is malformed")
                name, value = line.split(":", 1)
                headers.append((name, value.lstrip(" ")))
            header_tuple = tuple(headers)
            length = _parse_content_length(header_tuple)
            body = await asyncio.wait_for(reader.readexactly(length), timeout=10)
            self.requests += 1

            application_response = await self.application.handle(
                BrokerHTTPRequest(method=method, path=path, headers=header_tuple, body=body)
            )
            response_headers = list(application_response.headers)
            response_headers.extend(
                [
                    ("Content-Length", str(len(application_response.body))),
                    ("Connection", "close"),
                ]
            )
            reason = "OK" if application_response.status_code == 200 else "Error"
            wire = [f"HTTP/1.1 {application_response.status_code} {reason}\r\n"]
            wire.extend(f"{name}: {value}\r\n" for name, value in response_headers)
            wire.append("\r\n")
            writer.write("".join(wire).encode("iso-8859-1") + application_response.body)
            await writer.drain()
        except Exception as exc:
            self.errors.append(type(exc).__name__)
            try:
                payload = b'{"error":{"code":"tls_canary_server_error"}}'
                writer.write(
                    b"HTTP/1.1 500 Error\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Cache-Control: no-store\r\n"
                    + f"Content-Length: {len(payload)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + payload
                )
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


class TLSSocketBrokerTransport:
    def __init__(self, *, port: int, ca_path: Path) -> None:
        self.port = port
        self.ca_path = ca_path
        self.calls: list[dict[str, object]] = []
        self.tls_versions: list[str] = []

    async def post_json(self, *, endpoint, headers, body, timeout_seconds):
        if endpoint != BROKER_ENDPOINT:
            raise AssertionError("TLS canary was routed to an unapproved logical endpoint")
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or parsed.hostname != BROKER_HOST or parsed.path != "/v1/repair/decide":
            raise AssertionError("TLS canary logical broker endpoint drifted")

        context = ssl.create_default_context(cafile=str(self.ca_path))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host="127.0.0.1",
                port=self.port,
                ssl=context,
                server_hostname=BROKER_HOST,
                limit=256 * 1024,
            ),
            timeout=timeout_seconds,
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise RuntimeError("TLS broker client did not establish SSL")
            tls_version = ssl_object.version()
            if tls_version not in {"TLSv1.2", "TLSv1.3"}:
                raise RuntimeError("TLS broker client negotiated an unsupported TLS version")
            self.tls_versions.append(tls_version)

            wire_headers = [
                f"POST {parsed.path} HTTP/1.1",
                f"Host: {BROKER_HOST}",
            ]
            wire_headers.extend(f"{name}: {value}" for name, value in headers.items())
            wire_headers.extend(
                [
                    f"Content-Length: {len(body)}",
                    "Connection: close",
                    "",
                    "",
                ]
            )
            writer.write("\r\n".join(wire_headers).encode("iso-8859-1") + body)
            await writer.drain()

            status_line = (await asyncio.wait_for(reader.readline(), timeout=timeout_seconds)).decode(
                "iso-8859-1"
            ).rstrip("\r\n")
            parts = status_line.split(" ", 2)
            if len(parts) < 2 or parts[0] != "HTTP/1.1":
                raise RuntimeError("TLS broker response status line is invalid")
            status_code = int(parts[1])
            response_headers: list[tuple[str, str]] = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout_seconds)
                if line == b"\r\n":
                    break
                if not line:
                    raise RuntimeError("TLS broker response ended before headers completed")
                decoded = line.decode("iso-8859-1").rstrip("\r\n")
                if ":" not in decoded:
                    raise RuntimeError("TLS broker response header is malformed")
                name, value = decoded.split(":", 1)
                response_headers.append((name, value.lstrip(" ")))
            response_header_tuple = tuple(response_headers)
            length = _parse_content_length(response_header_tuple)
            response_body = await asyncio.wait_for(reader.readexactly(length), timeout=timeout_seconds)
            normalized = {name.lower(): value for name, value in response_headers}
            self.calls.append(
                {
                    "status_code": status_code,
                    "cache_control": normalized.get("cache-control"),
                    "content_type": normalized.get("content-type"),
                    "tls_version": tls_version,
                }
            )
            return BrokerHTTPResponse(status_code=status_code, body=response_body)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tls-cert", required=True, type=Path)
    parser.add_argument("--tls-key", required=True, type=Path)
    parser.add_argument("--tls-ca", required=True, type=Path)
    return parser.parse_args()


async def run_canary(
    workspace: Path,
    image_ref: str,
    source_commit: str,
    cert_path: Path,
    key_path: Path,
    ca_path: Path,
) -> dict[str, object]:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise RuntimeError("TLS broker repair canary workspace does not exist")
    if not PINNED_PYTHON_IMAGE.fullmatch(image_ref):
        raise RuntimeError("TLS broker repair canary image must be immutable")
    if not COMMIT.fullmatch(source_commit):
        raise RuntimeError("source commit must be an exact 40-character SHA")
    for path in (cert_path, key_path, ca_path):
        if not path.is_file():
            raise RuntimeError("TLS canary certificate material is missing")

    before_digest = workspace_tree_digest(workspace)
    original_source = (workspace / "app.py").read_text(encoding="utf-8")
    if "return 1" not in original_source:
        raise RuntimeError("TLS broker repair fixture is not in expected broken state")

    binding = load_provider_broker_binding(ROOT)
    selector = CatalogProviderSelectorResolver(
        ROOT,
        StaticProviderSelectorValueSource({"FACTORY_CODING_MODEL": "coding_primary_dry_run"}),
    )
    decision_engine = ScriptedDryRunDecisionEngine(
        decisions=[
            {"type": "read_files", "paths": ["app.py"]},
            {
                "type": "apply_edits",
                "summary": "repair canary return value over TLS",
                "edits": [
                    {"path": "app.py", "old_text": "return 1", "new_text": "return 2"}
                ],
            },
        ]
    )
    provider_invoker = DryRunProviderInvoker(decision_engine)
    service = ReferenceProviderBrokerService(ROOT, binding, selector, provider_invoker)
    authenticator = CanaryBearerAuthenticator()
    application = ReferenceProviderBrokerHTTPApplication(service, authenticator)
    server = LocalTLSBrokerServer(application, cert_path, key_path)
    await server.start()
    assert server.port is not None

    credential_source = CanaryCredentialSource()
    transport = TLSSocketBrokerTransport(port=server.port, ca_path=ca_path)
    budget = ProviderBrokerBudget(
        max_cost_usd_per_call=Decimal("0.01"),
        max_total_cost_usd=Decimal("0.02"),
    )
    image_policy = BaseImagePolicy(images=(("python:3.12", image_ref),))
    provisioning_policy = DockerProvisioningPolicy()

    try:
        with tempfile.TemporaryDirectory(prefix="factory-broker-tls-canary-") as temp:
            database_path = Path(temp) / "traces.sqlite3"
            trace_store = SQLiteBrokeredRepairTraceStore(database_path, max_records=8)
            runtime = build_docker_brokered_ci_repair_runtime(
                ROOT,
                workspace,
                image_policy,
                provisioning_policy,
                credential_source,
                transport,
                budget,
                structured_policy=StructuredRepairPolicy(max_model_turns=3),
                repair_policy=RepairPolicy(max_attempts=2),
                trace_store=trace_store,
            )
            if runtime.binding.binding_digest != binding.binding_digest:
                raise RuntimeError("TLS broker client/service binding digest mismatch")
            request = RepairRequest(
                repair_id="real-broker-tls-canary-v1",
                task_id="real-broker-tls-canary-task",
                lease_id="real-broker-tls-canary-lease",
                role_id="engineering_agent",
                source_commit=source_commit,
                command=("python", "-m", "unittest", "discover", "-s", "tests", "-v"),
                expected_provisioner_identity="factory_docker_provisioner_v1",
                expected_runner_identity="factory_docker_sandbox_v1",
                provisioning_timeout_seconds=300,
                verification_timeout_seconds=180,
            )
            outcome, artifact = await runtime.repair_with_trace(request)
            if not isinstance(outcome, VerifiedRepairCandidate):
                raise RuntimeError(f"TLS broker repair canary escalated: {outcome}")
            try:
                if workspace_tree_digest(workspace) != before_digest:
                    raise RuntimeError("authoritative TLS repair fixture changed")
                if (workspace / "app.py").read_text(encoding="utf-8") != original_source:
                    raise RuntimeError("authoritative TLS repair source changed")
                candidate_source = (outcome.workspace / "app.py").read_text(encoding="utf-8")
                if "return 2" not in candidate_source or "return 1" in candidate_source:
                    raise RuntimeError("TLS repaired candidate does not contain expected edit")
                if outcome.verification.receipt.exit_code != 0 or outcome.verification.receipt.timed_out:
                    raise RuntimeError("TLS repaired candidate failed exact-command verification")
                if len(runtime.provider_calls) != 2 or len(transport.calls) != 2:
                    raise RuntimeError("TLS broker repair did not make exactly two provider calls")
                if credential_source.issue_count != 2 or authenticator.auth_count != 2:
                    raise RuntimeError("TLS broker credential/authentication counts are inconsistent")
                if provider_invoker.invocation_count != 2 or decision_engine.decisions:
                    raise RuntimeError("TLS dry-run provider did not consume exactly two decisions")
                if server.requests != 2 or server.tls_connections != 2 or server.errors:
                    raise RuntimeError("TLS broker server request/connection accounting is inconsistent")
                if len(transport.tls_versions) != 2 or any(
                    version not in {"TLSv1.2", "TLSv1.3"} for version in transport.tls_versions
                ):
                    raise RuntimeError("TLS broker client version validation failed")
                if any(call["status_code"] != 200 for call in transport.calls):
                    raise RuntimeError("TLS broker returned a non-200 response")
                if any(call["cache_control"] != "no-store" for call in transport.calls):
                    raise RuntimeError("TLS broker response lost no-store")
                if any(call["content_type"] != "application/json" for call in transport.calls):
                    raise RuntimeError("TLS broker response content type drifted")
                if runtime.spent_usd != Decimal("0.00"):
                    raise RuntimeError("TLS zero-cost provider reported nonzero spend")
                if artifact.replay.terminal_status != "SUCCEEDED":
                    raise RuntimeError("TLS repair trace replay did not reconstruct success")
                if artifact.replay.total_provider_cost_usd != Decimal("0.00"):
                    raise RuntimeError("TLS repair trace replay reported nonzero cost")

                persisted = SQLiteBrokeredRepairTraceStore(database_path, max_records=8)
                loaded = persisted.get(artifact.trace_id)
                if loaded != artifact:
                    raise RuntimeError("TLS repair trace did not persist/reopen exactly")
                history = persisted.summarize_fingerprint(artifact.failure_fingerprint.digest)
                if history is None or history.successful_count != 1 or history.seen_count != 1:
                    raise RuntimeError("TLS repair fingerprint history is inconsistent")

                trace_text = artifact.jsonl.decode("utf-8")
                for forbidden in (CANARY_TOKEN, "return 1", "return 2", "AssertionError"):
                    if forbidden in trace_text:
                        raise RuntimeError("TLS repair trace leaked forbidden raw content")

                return {
                    "status": "PASS",
                    "provider_cost_usd": format(runtime.spent_usd, "f"),
                    "provider_calls": len(runtime.provider_calls),
                    "tls_connections": server.tls_connections,
                    "tls_versions": list(transport.tls_versions),
                    "broker_authentications": authenticator.auth_count,
                    "provider_invocations": provider_invoker.invocation_count,
                    "provider_target": "coding_primary_dry_run",
                    "repair_attempt": outcome.attempt_number,
                    "trace_id": artifact.trace_id,
                    "failure_fingerprint": artifact.failure_fingerprint.digest,
                    "authoritative_workspace_unchanged": True,
                    "candidate_verified": True,
                    "actual_tls_socket_exercised": True,
                    "tls_hostname_verified": True,
                    "paid_provider_traffic": False,
                    "factory_state_mutation": False,
                }
            finally:
                outcome.cleanup()
    finally:
        await server.close()


def main() -> int:
    args = parse_args()
    summary = asyncio.run(
        run_canary(
            args.workspace,
            args.image_ref,
            args.source_commit,
            args.tls_cert,
            args.tls_key,
            args.tls_ca,
        )
    )
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
