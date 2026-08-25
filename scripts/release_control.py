#!/usr/bin/env python3
"""Fail-closed validation and DynamoDB transaction builders for releases.

The GitHub workflows perform network operations with the AWS and GitHub CLIs.
This module keeps every authorization, chain-of-custody, and record-building
decision deterministic and unit-testable without cloud credentials.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FACTORY_ID = "tims-software-factory"
OWNER_GITHUB_LOGIN = "timbrydges"
OWNER_GITHUB_ID = "214414801"
OWNER_IDENTITY = "tim_brydges"
OWNER_SENTINEL = "OWNER_OVERRIDE"
RELEASE_PK = f"FACTORY#{FACTORY_ID}#RELEASE"
RELEASE_IDENTITY = "github_actions_production_environment"

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
VERSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~+/=-]{0,1023}$")
RUN_ID = re.compile(r"^[0-9]+$")


class ReleaseControlError(RuntimeError):
    """A release or rollback control failed closed."""


@dataclass(frozen=True)
class Deployment:
    source_commit: str
    artifact_digest: str
    release_key: str
    object_version_id: str
    previous_source_commit: str


def _load(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ReleaseControlError(f"{path}: expected a JSON object")
    return data


def _item(response: dict[str, Any]) -> dict[str, Any]:
    candidate = response.get("Item", response)
    return candidate if isinstance(candidate, dict) else {}


def _string(item: dict[str, Any], key: str, *, required: bool = True) -> str | None:
    value = item.get(key)
    if isinstance(value, dict) and isinstance(value.get("S"), str):
        return value["S"]
    if required:
        raise ReleaseControlError(f"DynamoDB item is missing string attribute {key}")
    return None


def _number(item: dict[str, Any], key: str) -> int:
    value = item.get(key)
    try:
        return int(value["N"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseControlError(f"DynamoDB item is missing integer attribute {key}") from exc


def _s(value: str) -> dict[str, str]:
    return {"S": value}


def _parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseControlError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReleaseControlError(f"{label} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _validate_sha(value: str, label: str) -> None:
    if not SHA.fullmatch(value):
        raise ReleaseControlError(f"{label} must be an exact lowercase 40-character commit SHA")


def _validate_digest(value: str) -> None:
    if not DIGEST.fullmatch(value):
        raise ReleaseControlError("artifact digest must be sha256 followed by 64 lowercase hex characters")


def _validate_version(value: str, label: str = "S3 object version") -> None:
    if value.lower() == "null" or not VERSION_ID.fullmatch(value):
        raise ReleaseControlError(f"{label} must be a captured version from a versioned S3 bucket")


def verify_build_run(run: dict[str, Any], source_commit: str) -> None:
    """Bind the downloaded artifact to a successful protected-main build."""

    _validate_sha(source_commit, "source commit")
    repository = run.get("repository", {})
    if not isinstance(repository, dict):
        repository = {}
    required = {
        "name": "build-attest",
        "path": ".github/workflows/build-attest.yml",
        "event": "push",
        "head_branch": "main",
        "head_sha": source_commit,
        "status": "completed",
        "conclusion": "success",
    }
    if any(run.get(key) != value for key, value in required.items()):
        raise ReleaseControlError("build run is not a successful build-attest run for this main commit")
    if repository.get("full_name") != "timbrydges/timscodefactory":
        raise ReleaseControlError("build run repository binding is invalid")


def verify_dispatch_authority(
    *,
    actor: str,
    actor_id: str,
    task_id: str,
    lease_id: str,
    source_commit: str,
    state_response: dict[str, Any] | None = None,
    owner_event_response: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> str:
    """Return ``owner`` or ``agent`` after validating release authority.

    Tim's direct path has no approval step. A controller/agent path must be
    backed by a live release lease plus Tim's immutable, commit-specific owner
    authorization event.
    """

    _validate_sha(source_commit, "source commit")
    if not actor or len(actor) > 100 or not RUN_ID.fullmatch(actor_id):
        raise ReleaseControlError("GitHub actor identity is invalid")
    if actor_id == OWNER_GITHUB_ID:
        if task_id != OWNER_SENTINEL or lease_id != OWNER_SENTINEL:
            raise ReleaseControlError("Tim's direct release must use the OWNER_OVERRIDE sentinels")
        return "owner"

    if not SAFE_ID.fullmatch(task_id) or task_id == OWNER_SENTINEL:
        raise ReleaseControlError("agent release task id is invalid")
    if not SAFE_ID.fullmatch(lease_id) or lease_id == OWNER_SENTINEL:
        raise ReleaseControlError("agent release lease id is invalid")

    state_item = _item(state_response or {})
    expected_pk = f"FACTORY#{FACTORY_ID}#TASK#{task_id}"
    if _string(state_item, "PK") != expected_pk or _string(state_item, "SK") != "STATE":
        raise ReleaseControlError("task state record is absent or bound to another task")
    top_state = _string(state_item, "state")
    if top_state not in {"RELEASE_READY", "RELEASING"}:
        raise ReleaseControlError("agent release task is not release-ready")
    try:
        payload = json.loads(_string(state_item, "payload") or "")
    except json.JSONDecodeError as exc:
        raise ReleaseControlError("task state payload is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ReleaseControlError("task state payload is invalid")
    if (
        payload.get("factory_id") != FACTORY_ID
        or payload.get("task_id") != task_id
        or payload.get("state") != top_state
        or isinstance(payload.get("version"), bool)
        or not isinstance(payload.get("version"), int)
        or not isinstance(payload.get("leases"), list)
        or not all(isinstance(item, dict) for item in payload.get("leases", []))
        or not isinstance(payload.get("active_lease_ids"), list)
    ):
        raise ReleaseControlError("task state payload binding is invalid")

    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    matching = [lease for lease in payload.get("leases", []) if lease.get("lease_id") == lease_id]
    if len(matching) != 1:
        raise ReleaseControlError("active release lease is absent or ambiguous")
    lease = matching[0]
    if (
        lease.get("role_id") != "release_automation"
        or lease.get("authoritative_identity") != RELEASE_IDENTITY
        or lease.get("revoked") is not False
        or lease_id not in payload.get("active_lease_ids", [])
        or _parse_time(str(lease.get("expires_at", "")), "lease expiry") <= now
    ):
        raise ReleaseControlError("release lease is expired, revoked, or bound to the wrong identity")

    owner_event = _item(owner_event_response or {})
    if _string(owner_event, "PK") != expected_pk:
        raise ReleaseControlError("owner authorization is bound to another task")
    event_sk = _string(owner_event, "SK")
    if not event_sk or not event_sk.startswith("EVENT#"):
        raise ReleaseControlError("owner authorization event key is invalid")
    owner_version = _number(owner_event, "to_version")
    if (
        _string(owner_event, "event_type") != "OWNER_OVERRIDE"
        or _string(owner_event, "actor_identity") != OWNER_IDENTITY
        or _string(owner_event, "to_state") not in {"RELEASE_READY", "RELEASING"}
        or owner_version < 0
        or owner_version > payload["version"]
    ):
        raise ReleaseControlError("owner authorization event is invalid")
    try:
        details = json.loads(_string(owner_event, "details") or "")
    except json.JSONDecodeError as exc:
        raise ReleaseControlError("owner authorization details are invalid JSON") from exc
    if details != {"reason": f"AUTHORIZE_RELEASE:{source_commit}"}:
        raise ReleaseControlError("owner authorization is not commit-specific")
    return "agent"


def validate_current_pointer(response: dict[str, Any], expected_commit: str | None = None) -> Deployment:
    item = _item(response)
    if _string(item, "PK") != RELEASE_PK or _string(item, "SK") != "CURRENT":
        raise ReleaseControlError("current release pointer is absent or malformed")
    if _string(item, "record_type") != "CURRENT":
        raise ReleaseControlError("current release record type is invalid")
    source_commit = _string(item, "source_commit") or ""
    _validate_sha(source_commit, "current source commit")
    if expected_commit is not None and source_commit != expected_commit:
        raise ReleaseControlError("current release changed or does not match the expected rollback source")
    digest = _string(item, "artifact_sha256") or ""
    _validate_digest(digest)
    key = _string(item, "release_key") or ""
    if key != f"releases/{source_commit}/factory-control-plane.tar.gz":
        raise ReleaseControlError("current release key is not commit-bound")
    version = _string(item, "object_version_id") or ""
    _validate_version(version, "current S3 object version")
    _validate_record_provenance(item, current=True)
    return Deployment(source_commit, digest, key, version, _string(item, "previous_source_commit", required=False) or OWNER_SENTINEL)


def validate_deployment(response: dict[str, Any], expected_commit: str) -> Deployment:
    _validate_sha(expected_commit, "deployment source commit")
    item = _item(response)
    if (
        _string(item, "PK") != RELEASE_PK
        or _string(item, "SK") != f"DEPLOYMENT#{expected_commit}"
        or _string(item, "record_type") != "DEPLOYMENT"
        or _string(item, "source_commit") != expected_commit
    ):
        raise ReleaseControlError("deployment record is absent or not commit-bound")
    digest = _string(item, "artifact_sha256") or ""
    _validate_digest(digest)
    key = _string(item, "release_key") or ""
    if key != f"releases/{expected_commit}/factory-control-plane.tar.gz":
        raise ReleaseControlError("deployment release key is not commit-bound")
    version = _string(item, "object_version_id") or ""
    _validate_version(version, "deployment S3 object version")
    previous = _string(item, "previous_source_commit") or ""
    if previous != "INITIAL_RELEASE" and not SHA.fullmatch(previous):
        raise ReleaseControlError("deployment previous source commit is invalid")
    _validate_record_provenance(item, current=False)
    return Deployment(expected_commit, digest, key, version, previous)


def _validate_record_provenance(item: dict[str, Any], *, current: bool) -> None:
    actor = _string(item, "updated_by" if current else "actor")
    actor_id = _string(item, "actor_id") or ""
    mode = _string(item, "authority_mode")
    workflow_run = _string(item, "workflow_run") or ""
    timestamp = _string(item, "updated_at" if current else "released_at") or ""
    if not actor or len(actor) > 100 or not RUN_ID.fullmatch(actor_id):
        raise ReleaseControlError("release record actor provenance is invalid")
    allowed_modes = {"owner", "agent", "owner_rollback"} if current else {"owner", "agent"}
    if mode not in allowed_modes or (mode.startswith("owner") and actor_id != OWNER_GITHUB_ID):
        raise ReleaseControlError("release record authority provenance is invalid")
    if not RUN_ID.fullmatch(workflow_run):
        raise ReleaseControlError("release record workflow provenance is invalid")
    _parse_time(timestamp, "release record timestamp")


def validate_s3_head(head: dict[str, Any], deployment: Deployment) -> None:
    metadata = head.get("Metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    if (
        head.get("VersionId") != deployment.object_version_id
        or metadata.get("source-commit") != deployment.source_commit
        or metadata.get("sha256") != deployment.artifact_digest
        or head.get("ServerSideEncryption") != "AES256"
        or not isinstance(head.get("ContentLength"), int)
        or head["ContentLength"] <= 0
    ):
        raise ReleaseControlError("S3 object metadata does not match its immutable deployment record")
    checksum = head.get("ChecksumSHA256")
    try:
        checksum_hex = base64.b64decode(checksum, validate=True).hex()
    except (TypeError, ValueError) as exc:
        raise ReleaseControlError("S3 SHA-256 checksum is absent or invalid") from exc
    if f"sha256:{checksum_hex}" != deployment.artifact_digest:
        raise ReleaseControlError("S3 object checksum does not match its deployment digest")


def object_version(response: dict[str, Any]) -> str:
    version = response.get("VersionId")
    if not isinstance(version, str):
        raise ReleaseControlError("S3 put-object did not return a valid immutable VersionId")
    _validate_version(version, "S3 put-object VersionId")
    return version


def prepare_release_transaction(
    *,
    table_name: str,
    source_commit: str,
    artifact_digest: str,
    release_key: str,
    object_version_id: str,
    rollback_source_commit: str,
    actor: str,
    actor_id: str,
    authority_mode: str,
    workflow_run: str,
    released_at: str,
    current_response: dict[str, Any],
    previous_response: dict[str, Any],
    previous_head: dict[str, Any],
    uploaded_head: dict[str, Any],
) -> list[dict[str, Any]]:
    _validate_sha(source_commit, "source commit")
    _validate_digest(artifact_digest)
    if release_key != f"releases/{source_commit}/factory-control-plane.tar.gz":
        raise ReleaseControlError("release key is not bound to the source commit")
    _validate_version(object_version_id, "captured S3 object version")
    if authority_mode not in {"owner", "agent"}:
        raise ReleaseControlError("release authority mode is invalid")
    if not actor or len(actor) > 100 or not RUN_ID.fullmatch(actor_id):
        raise ReleaseControlError("GitHub actor id is invalid")
    if authority_mode == "owner" and actor_id != OWNER_GITHUB_ID:
        raise ReleaseControlError("only Tim may use owner release authority")
    if not RUN_ID.fullmatch(workflow_run):
        raise ReleaseControlError("workflow run id is invalid")
    released = _parse_time(released_at, "release time").isoformat().replace("+00:00", "Z")
    uploaded = Deployment(source_commit, artifact_digest, release_key, object_version_id, rollback_source_commit)
    validate_s3_head(uploaded_head, uploaded)

    previous_key = ""
    previous_version = ""
    current_item = _item(current_response)
    if rollback_source_commit == "INITIAL_RELEASE":
        if current_item or _item(previous_response):
            raise ReleaseControlError("INITIAL_RELEASE is valid only when no current release exists")
        current_operation: dict[str, Any] = {
            "Put": {
                "TableName": table_name,
                "Item": {},
                "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)",
            }
        }
    else:
        _validate_sha(rollback_source_commit, "rollback source commit")
        if rollback_source_commit == source_commit:
            raise ReleaseControlError("a release cannot name itself as its rollback source")
        current = validate_current_pointer(current_response, rollback_source_commit)
        previous = validate_deployment(previous_response, rollback_source_commit)
        if (
            current.artifact_digest != previous.artifact_digest
            or current.release_key != previous.release_key
            or current.object_version_id != previous.object_version_id
        ):
            raise ReleaseControlError("current pointer and previous deployment record disagree")
        validate_s3_head(previous_head, previous)
        previous_key = previous.release_key
        previous_version = previous.object_version_id
        current_operation = {
            "Update": {
                "TableName": table_name,
                "Key": {"PK": _s(RELEASE_PK), "SK": _s("CURRENT")},
                "UpdateExpression": (
                    "SET record_type=:record_type, source_commit=:source, artifact_sha256=:digest, "
                    "release_key=:release_key, object_version_id=:version, previous_source_commit=:previous, "
                    "previous_release_key=:previous_key, previous_object_version_id=:previous_version, "
                    "updated_at=:updated, updated_by=:actor, actor_id=:actor_id, "
                    "authority_mode=:mode, workflow_run=:run"
                ),
                "ConditionExpression": "source_commit=:expected_source AND object_version_id=:expected_version",
                "ExpressionAttributeValues": {
                    ":record_type": _s("CURRENT"),
                    ":source": _s(source_commit),
                    ":digest": _s(artifact_digest),
                    ":release_key": _s(release_key),
                    ":version": _s(object_version_id),
                    ":previous": _s(rollback_source_commit),
                    ":previous_key": _s(previous_key),
                    ":previous_version": _s(previous_version),
                    ":updated": _s(released),
                    ":actor": _s(actor),
                    ":actor_id": _s(actor_id),
                    ":mode": _s(authority_mode),
                    ":run": _s(workflow_run),
                    ":expected_source": _s(current.source_commit),
                    ":expected_version": _s(current.object_version_id),
                },
            }
        }

    common = {
        "source_commit": _s(source_commit),
        "artifact_sha256": _s(artifact_digest),
        "release_key": _s(release_key),
        "object_version_id": _s(object_version_id),
        "previous_source_commit": _s(rollback_source_commit),
        "released_at": _s(released),
        "actor": _s(actor),
        "actor_id": _s(actor_id),
        "authority_mode": _s(authority_mode),
        "workflow_run": _s(workflow_run),
    }
    if previous_key:
        common["previous_release_key"] = _s(previous_key)
        common["previous_object_version_id"] = _s(previous_version)
    deployment_item = {
        "PK": _s(RELEASE_PK),
        "SK": _s(f"DEPLOYMENT#{source_commit}"),
        "record_type": _s("DEPLOYMENT"),
        **common,
    }
    event_item = {
        "PK": _s(RELEASE_PK),
        "SK": _s(f"EVENT#{released}#RELEASE#{source_commit}"),
        "record_type": _s("RELEASE_EVENT"),
        "event_type": _s("RELEASE"),
        **common,
    }
    current_item_new = {
        "PK": _s(RELEASE_PK),
        "SK": _s("CURRENT"),
        "record_type": _s("CURRENT"),
        **common,
        "updated_at": _s(released),
        "updated_by": _s(actor),
    }
    if rollback_source_commit == "INITIAL_RELEASE":
        current_operation["Put"]["Item"] = current_item_new

    return [
        {
            "Put": {
                "TableName": table_name,
                "Item": deployment_item,
                "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)",
            }
        },
        {
            "Put": {
                "TableName": table_name,
                "Item": event_item,
                "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)",
            }
        },
        current_operation,
    ]


def prepare_rollback_transaction(
    *,
    table_name: str,
    target_source_commit: str,
    expected_current_source_commit: str,
    reason: str,
    actor: str,
    actor_id: str,
    workflow_run: str,
    rolled_back_at: str,
    current_response: dict[str, Any],
    target_response: dict[str, Any],
    target_head: dict[str, Any],
) -> list[dict[str, Any]]:
    if not actor or len(actor) > 100 or actor_id != OWNER_GITHUB_ID:
        raise ReleaseControlError("only Tim may dispatch the emergency rollback workflow")
    _validate_sha(target_source_commit, "rollback target source commit")
    _validate_sha(expected_current_source_commit, "expected current source commit")
    if target_source_commit == expected_current_source_commit:
        raise ReleaseControlError("rollback target must differ from the current release")
    if not reason.strip() or len(reason) > 512:
        raise ReleaseControlError("rollback reason must contain 1-512 characters")
    if not RUN_ID.fullmatch(workflow_run):
        raise ReleaseControlError("workflow run id is invalid")
    rolled_at = _parse_time(rolled_back_at, "rollback time").isoformat().replace("+00:00", "Z")

    current = validate_current_pointer(current_response, expected_current_source_commit)
    target = validate_deployment(target_response, target_source_commit)
    validate_s3_head(target_head, target)
    event_sk = f"EVENT#{rolled_at}#ROLLBACK#{workflow_run}"
    event_item = {
        "PK": _s(RELEASE_PK),
        "SK": _s(event_sk),
        "record_type": _s("ROLLBACK_EVENT"),
        "event_type": _s("ROLLBACK"),
        "from_source_commit": _s(current.source_commit),
        "from_release_key": _s(current.release_key),
        "from_object_version_id": _s(current.object_version_id),
        "target_source_commit": _s(target.source_commit),
        "target_artifact_sha256": _s(target.artifact_digest),
        "target_release_key": _s(target.release_key),
        "target_object_version_id": _s(target.object_version_id),
        "reason": _s(reason.strip()),
        "actor": _s(actor),
        "actor_id": _s(actor_id),
        "workflow_run": _s(workflow_run),
        "rolled_back_at": _s(rolled_at),
    }
    return [
        {
            "Put": {
                "TableName": table_name,
                "Item": event_item,
                "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)",
            }
        },
        {
            "Update": {
                "TableName": table_name,
                "Key": {"PK": _s(RELEASE_PK), "SK": _s("CURRENT")},
                "UpdateExpression": (
                    "SET source_commit=:target, artifact_sha256=:digest, release_key=:release_key, "
                    "object_version_id=:target_version, previous_source_commit=:from_source, "
                    "previous_release_key=:from_key, previous_object_version_id=:from_version, "
                    "updated_at=:updated, updated_by=:actor, actor_id=:actor_id, "
                    "authority_mode=:mode, workflow_run=:run, "
                    "last_event_sk=:event"
                ),
                "ConditionExpression": "source_commit=:expected_source AND object_version_id=:expected_version",
                "ExpressionAttributeValues": {
                    ":target": _s(target.source_commit),
                    ":digest": _s(target.artifact_digest),
                    ":release_key": _s(target.release_key),
                    ":target_version": _s(target.object_version_id),
                    ":from_source": _s(current.source_commit),
                    ":from_key": _s(current.release_key),
                    ":from_version": _s(current.object_version_id),
                    ":updated": _s(rolled_at),
                    ":actor": _s(actor),
                    ":actor_id": _s(actor_id),
                    ":mode": _s("owner_rollback"),
                    ":run": _s(workflow_run),
                    ":event": _s(event_sk),
                    ":expected_source": _s(current.source_commit),
                    ":expected_version": _s(current.object_version_id),
                },
            }
        },
    ]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("verify-build-run")
    build.add_argument("--run", type=Path, required=True)
    build.add_argument("--source-commit", required=True)

    authority = commands.add_parser("verify-authority")
    authority.add_argument("--actor", required=True)
    authority.add_argument("--actor-id", required=True)
    authority.add_argument("--task-id", required=True)
    authority.add_argument("--lease-id", required=True)
    authority.add_argument("--source-commit", required=True)
    authority.add_argument("--state-item", type=Path)
    authority.add_argument("--owner-event-item", type=Path)

    location = commands.add_parser("deployment-location")
    location.add_argument("--item", type=Path, required=True)
    location.add_argument("--source-commit", required=True)

    version = commands.add_parser("object-version")
    version.add_argument("--response", type=Path, required=True)

    current = commands.add_parser("verify-current")
    current.add_argument("--item", type=Path, required=True)
    current.add_argument("--source-commit", required=True)
    current.add_argument("--object-version-id", required=True)
    current.add_argument("--artifact-digest", required=True)

    release = commands.add_parser("prepare-release")
    for name in (
        "table-name", "source-commit", "artifact-digest", "release-key",
        "object-version-id", "rollback-source-commit", "actor", "actor-id",
        "authority-mode", "workflow-run", "released-at",
    ):
        release.add_argument(f"--{name}", required=True)
    release.add_argument("--current-item", type=Path, required=True)
    release.add_argument("--previous-item", type=Path, required=True)
    release.add_argument("--previous-head", type=Path, required=True)
    release.add_argument("--uploaded-head", type=Path, required=True)
    release.add_argument("--output", type=Path, required=True)

    rollback = commands.add_parser("prepare-rollback")
    for name in (
        "table-name", "target-source-commit", "expected-current-source-commit",
        "reason", "actor", "actor-id", "workflow-run", "rolled-back-at",
    ):
        rollback.add_argument(f"--{name}", required=True)
    rollback.add_argument("--current-item", type=Path, required=True)
    rollback.add_argument("--target-item", type=Path, required=True)
    rollback.add_argument("--target-head", type=Path, required=True)
    rollback.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "verify-build-run":
            verify_build_run(_load(args.run), args.source_commit)
        elif args.command == "verify-authority":
            print(
                verify_dispatch_authority(
                    actor=args.actor,
                    actor_id=args.actor_id,
                    task_id=args.task_id,
                    lease_id=args.lease_id,
                    source_commit=args.source_commit,
                    state_response=_load(args.state_item),
                    owner_event_response=_load(args.owner_event_item),
                )
            )
        elif args.command == "deployment-location":
            deployment = validate_deployment(_load(args.item), args.source_commit)
            print(deployment.release_key)
            print(deployment.object_version_id)
            print(deployment.artifact_digest)
        elif args.command == "object-version":
            print(object_version(_load(args.response)))
        elif args.command == "verify-current":
            pointer = validate_current_pointer(_load(args.item), args.source_commit)
            if (
                pointer.object_version_id != args.object_version_id
                or pointer.artifact_digest != args.artifact_digest
            ):
                raise ReleaseControlError("persisted current release does not match the completed publication")
        elif args.command == "prepare-release":
            _write_json(
                args.output,
                prepare_release_transaction(
                    table_name=args.table_name,
                    source_commit=args.source_commit,
                    artifact_digest=args.artifact_digest,
                    release_key=args.release_key,
                    object_version_id=args.object_version_id,
                    rollback_source_commit=args.rollback_source_commit,
                    actor=args.actor,
                    actor_id=args.actor_id,
                    authority_mode=args.authority_mode,
                    workflow_run=args.workflow_run,
                    released_at=args.released_at,
                    current_response=_load(args.current_item),
                    previous_response=_load(args.previous_item),
                    previous_head=_load(args.previous_head),
                    uploaded_head=_load(args.uploaded_head),
                ),
            )
        elif args.command == "prepare-rollback":
            _write_json(
                args.output,
                prepare_rollback_transaction(
                    table_name=args.table_name,
                    target_source_commit=args.target_source_commit,
                    expected_current_source_commit=args.expected_current_source_commit,
                    reason=args.reason,
                    actor=args.actor,
                    actor_id=args.actor_id,
                    workflow_run=args.workflow_run,
                    rolled_back_at=args.rolled_back_at,
                    current_response=_load(args.current_item),
                    target_response=_load(args.target_item),
                    target_head=_load(args.target_head),
                ),
            )
    except (ReleaseControlError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
