from __future__ import annotations

import asyncio
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.docker_sandbox import ProcessResult  # noqa: E402
from factory_runtime.liveness import (  # noqa: E402
    RuntimeControllerRequest,
    RuntimeLivenessStatus,
    RuntimeSupervisorAction,
    RuntimeWatchEvaluation,
)
from factory_runtime.runtime_supervisor import (  # noqa: E402
    DockerRuntimeResourceHandle,
    DockerRuntimeSupervisor,
    DockerRuntimeSupervisorPolicy,
    RuntimeResourceBindingError,
    RuntimeSupervisorError,
    RuntimeTerminationError,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 8, 23, 0, tzinfo=timezone.utc)
RESOURCE_ID = "a" * 64
RESOURCE_ID_2 = "b" * 64
COMMIT = "c" * 40


def handle(resource_id: str = RESOURCE_ID) -> DockerRuntimeResourceHandle:
    return DockerRuntimeResourceHandle(
        resource_id=resource_id,
        runtime_session_id="req-docker-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        runner_identity="factory_docker_sandbox_v1",
    )


def labels(resource_id: str = RESOURCE_ID) -> dict[str, str]:
    _ = resource_id
    return {
        "factory.sandbox": "true",
        "factory.runtime_session_id": "req-docker-1",
        "factory.request_id": "req-docker-1",
        "factory.task_id": "task-1",
        "factory.lease_id": "lease-1",
        "factory.role_id": "engineering_agent",
        "factory.source_commit": COMMIT,
        "factory.runner_identity": "factory_docker_sandbox_v1",
    }


def evaluation(
    *,
    status: RuntimeLivenessStatus = RuntimeLivenessStatus.STALE,
    reason: str = "RUNTIME_HEARTBEAT_STALE",
    evaluated_at: datetime = NOW,
    task_id: str = "task-1",
    lease_id: str = "lease-1",
    runtime_action: RuntimeSupervisorAction = RuntimeSupervisorAction.TERMINATE_SESSION,
    controller_request: RuntimeControllerRequest = RuntimeControllerRequest.REQUEST_RUNTIME_RESTART,
) -> RuntimeWatchEvaluation:
    return RuntimeWatchEvaluation(
        runtime_session_id="req-docker-1",
        task_id=task_id,
        lease_id=lease_id,
        status=status,
        reason_code=reason,
        controller_request=controller_request,
        runtime_action=runtime_action,
        authoritative_recovery_count=0,
        last_heartbeat_at=NOW - timedelta(seconds=130),
        last_progress_at=NOW - timedelta(seconds=300),
        evaluated_at=evaluated_at,
    )


class FakeRunner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], int]] = []

    async def run(self, argv: tuple[str, ...], *, timeout_seconds: int) -> ProcessResult:
        self.calls.append((argv, timeout_seconds))
        if not self.responses:
            raise AssertionError(f"unexpected process call: {argv}")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def inspect_response(value: dict[str, str]) -> ProcessResult:
    return ProcessResult(0, json.dumps(value).encode("utf-8"), b"")


class RuntimeSupervisorTests(unittest.TestCase):
    def test_termination_receipt_matches_schema(self):
        runner = FakeRunner(
            inspect_response(labels()),
            ProcessResult(0, RESOURCE_ID.encode(), b""),
            ProcessResult(0, b"", b""),
        )
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        receipt = asyncio.run(supervisor.terminate(handle(), evaluation(), now=NOW))
        schema = json.loads(
            (ROOT / "factory/schemas/runtime-termination-receipt.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt.to_dict())
        self.assertEqual(receipt.resource_id, RESOURCE_ID)
        self.assertEqual(runner.calls[1][0], ("docker", "rm", "-f", RESOURCE_ID))
        self.assertEqual(
            runner.calls[2][0],
            ("docker", "ps", "-aq", "--no-trunc", "--filter", f"id={RESOURCE_ID}"),
        )

    def test_healthy_evaluation_is_rejected_before_docker(self):
        runner = FakeRunner()
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        healthy = evaluation(
            status=RuntimeLivenessStatus.HEALTHY,
            reason="RUNTIME_HEALTHY",
            runtime_action=RuntimeSupervisorAction.NONE,
            controller_request=RuntimeControllerRequest.NONE,
        )
        with self.assertRaises(RuntimeTerminationError):
            asyncio.run(supervisor.terminate(handle(), healthy, now=NOW))
        self.assertEqual(runner.calls, [])

    def test_old_evaluation_is_rejected_before_docker(self):
        runner = FakeRunner()
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        stale = evaluation(evaluated_at=NOW - timedelta(seconds=61))
        with self.assertRaises(RuntimeTerminationError):
            asyncio.run(supervisor.terminate(handle(), stale, now=NOW))
        self.assertEqual(runner.calls, [])

    def test_future_evaluation_beyond_skew_is_rejected_before_docker(self):
        runner = FakeRunner()
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        future = evaluation(evaluated_at=NOW + timedelta(seconds=11))
        with self.assertRaises(RuntimeTerminationError):
            asyncio.run(supervisor.terminate(handle(), future, now=NOW))
        self.assertEqual(runner.calls, [])

    def test_evaluation_binding_mismatch_is_rejected_before_docker(self):
        runner = FakeRunner()
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        with self.assertRaises(RuntimeTerminationError):
            asyncio.run(
                supervisor.terminate(
                    handle(),
                    evaluation(lease_id="other-lease"),
                    now=NOW,
                )
            )
        self.assertEqual(runner.calls, [])

    def test_reason_status_mismatch_is_rejected_before_docker(self):
        runner = FakeRunner()
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        wrong = evaluation(status=RuntimeLivenessStatus.STUCK, reason="RUNTIME_HEARTBEAT_STALE")
        with self.assertRaises(RuntimeTerminationError):
            asyncio.run(supervisor.terminate(handle(), wrong, now=NOW))
        self.assertEqual(runner.calls, [])

    def test_missing_controller_request_is_rejected_before_docker(self):
        runner = FakeRunner()
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        wrong = evaluation(controller_request=RuntimeControllerRequest.NONE)
        with self.assertRaises(RuntimeTerminationError):
            asyncio.run(supervisor.terminate(handle(), wrong, now=NOW))
        self.assertEqual(runner.calls, [])

    def test_live_label_mismatch_prevents_remove(self):
        wrong_labels = labels()
        wrong_labels["factory.lease_id"] = "other-lease"
        runner = FakeRunner(inspect_response(wrong_labels))
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        with self.assertRaises(RuntimeResourceBindingError):
            asyncio.run(supervisor.terminate(handle(), evaluation(), now=NOW))
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0][0][1], "inspect")

    def test_uninspectable_resource_is_not_treated_as_already_gone(self):
        runner = FakeRunner(ProcessResult(1, b"", b"docker daemon unavailable"))
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        with self.assertRaises(RuntimeResourceBindingError):
            asyncio.run(supervisor.terminate(handle(), evaluation(), now=NOW))
        self.assertEqual(len(runner.calls), 1)

    def test_docker_remove_failure_fails_closed(self):
        runner = FakeRunner(
            inspect_response(labels()),
            ProcessResult(1, b"", b"remove failed"),
        )
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        with self.assertRaises(RuntimeTerminationError):
            asyncio.run(supervisor.terminate(handle(), evaluation(), now=NOW))
        self.assertEqual(len(runner.calls), 2)

    def test_post_remove_resource_presence_fails_closed(self):
        runner = FakeRunner(
            inspect_response(labels()),
            ProcessResult(0, RESOURCE_ID.encode(), b""),
            ProcessResult(0, (RESOURCE_ID + "\n").encode(), b""),
        )
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        with self.assertRaises(RuntimeTerminationError):
            asyncio.run(supervisor.terminate(handle(), evaluation(), now=NOW))

    def test_discovery_returns_only_complete_provenance_handles(self):
        runner = FakeRunner(
            ProcessResult(0, f"{RESOURCE_ID}\n{RESOURCE_ID_2}\n".encode(), b""),
            inspect_response(labels()),
            inspect_response(labels()),
        )
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        handles = asyncio.run(supervisor.discover_factory_sandboxes())
        self.assertEqual([item.resource_id for item in handles], [RESOURCE_ID, RESOURCE_ID_2])
        self.assertTrue(all(item.runtime_session_id == "req-docker-1" for item in handles))

    def test_discovery_rejects_incomplete_factory_labels(self):
        incomplete = labels()
        del incomplete["factory.source_commit"]
        runner = FakeRunner(
            ProcessResult(0, (RESOURCE_ID + "\n").encode(), b""),
            inspect_response(incomplete),
        )
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        with self.assertRaises(RuntimeResourceBindingError):
            asyncio.run(supervisor.discover_factory_sandboxes())

    def test_discovery_rejects_duplicate_resources(self):
        runner = FakeRunner(
            ProcessResult(0, f"{RESOURCE_ID}\n{RESOURCE_ID}\n".encode(), b""),
        )
        supervisor = DockerRuntimeSupervisor(process_runner=runner)
        with self.assertRaises(RuntimeSupervisorError):
            asyncio.run(supervisor.discover_factory_sandboxes())

    def test_discovery_cap_fails_closed(self):
        policy = DockerRuntimeSupervisorPolicy(max_discovery_resources=1)
        runner = FakeRunner(
            ProcessResult(0, f"{RESOURCE_ID}\n{RESOURCE_ID_2}\n".encode(), b""),
        )
        supervisor = DockerRuntimeSupervisor(policy, process_runner=runner)
        with self.assertRaises(RuntimeSupervisorError):
            asyncio.run(supervisor.discover_factory_sandboxes())

    def test_invalid_resource_id_is_rejected(self):
        with self.assertRaises(RuntimeResourceBindingError):
            DockerRuntimeResourceHandle(
                resource_id="not-a-container",
                runtime_session_id="req-docker-1",
                task_id="task-1",
                lease_id="lease-1",
                role_id="engineering_agent",
                source_commit=COMMIT,
                runner_identity="factory_docker_sandbox_v1",
            )


if __name__ == "__main__":
    unittest.main()
