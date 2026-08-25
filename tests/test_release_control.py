from __future__ import annotations

import base64
import unittest
from datetime import datetime, timedelta, timezone

from scripts.release_control import (
    OWNER_SENTINEL,
    RELEASE_PK,
    ReleaseControlError,
    prepare_release_transaction,
    prepare_rollback_transaction,
    validate_current_pointer,
    verify_build_run,
    verify_dispatch_authority,
)


SOURCE = "a" * 40
PREVIOUS = "b" * 40
TARGET = "c" * 40
DIGEST = "sha256:" + "d" * 64
NOW = datetime(2026, 8, 25, 18, 0, tzinfo=timezone.utc)


def s(value: str) -> dict[str, str]:
    return {"S": value}


def build_run(source: str = SOURCE) -> dict:
    return {
        "name": "build-attest",
        "path": ".github/workflows/build-attest.yml",
        "event": "push",
        "head_branch": "main",
        "head_sha": source,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": "timbrydges/timscodefactory"},
    }


def task_state(*, expiry: datetime | None = None) -> dict:
    import json

    expiry = expiry or NOW + timedelta(minutes=10)
    payload = {
        "factory_id": "tims-software-factory",
        "task_id": "task-1",
        "state": "RELEASE_READY",
        "version": 8,
        "active_lease_ids": ["release-lease"],
        "leases": [
            {
                "lease_id": "release-lease",
                "role_id": "release_automation",
                "authoritative_identity": "github_actions_production_environment",
                "expires_at": expiry.isoformat(),
                "revoked": False,
            }
        ],
    }
    return {
        "Item": {
            "PK": s("FACTORY#tims-software-factory#TASK#task-1"),
            "SK": s("STATE"),
            "state": s("RELEASE_READY"),
            "payload": s(json.dumps(payload, sort_keys=True)),
        }
    }


def owner_event(source: str = SOURCE) -> dict:
    import json

    return {
        "Item": {
            "PK": s("FACTORY#tims-software-factory#TASK#task-1"),
            "SK": s("EVENT#2026-08-25T17:59:00Z#owner-release"),
            "event_type": s("OWNER_OVERRIDE"),
            "actor_identity": s("tim_brydges"),
            "to_state": s("RELEASE_READY"),
            "to_version": {"N": "7"},
            "details": s(json.dumps({"reason": f"AUTHORIZE_RELEASE:{source}"})),
        }
    }


def deployment(source: str, *, digest: str = DIGEST, version: str = "version-1") -> dict:
    return {
        "Item": {
            "PK": s(RELEASE_PK),
            "SK": s(f"DEPLOYMENT#{source}"),
            "record_type": s("DEPLOYMENT"),
            "source_commit": s(source),
            "artifact_sha256": s(digest),
            "release_key": s(f"releases/{source}/factory-control-plane.tar.gz"),
            "object_version_id": s(version),
            "previous_source_commit": s("INITIAL_RELEASE"),
            "actor": s("timbrydges"),
            "actor_id": s("214414801"),
            "authority_mode": s("owner"),
            "workflow_run": s("100"),
            "released_at": s("2026-08-25T17:00:00Z"),
        }
    }


def current(source: str, *, digest: str = DIGEST, version: str = "version-1") -> dict:
    return {
        "Item": {
            "PK": s(RELEASE_PK),
            "SK": s("CURRENT"),
            "record_type": s("CURRENT"),
            "source_commit": s(source),
            "artifact_sha256": s(digest),
            "release_key": s(f"releases/{source}/factory-control-plane.tar.gz"),
            "object_version_id": s(version),
            "previous_source_commit": s("INITIAL_RELEASE"),
            "updated_by": s("timbrydges"),
            "actor_id": s("214414801"),
            "authority_mode": s("owner"),
            "workflow_run": s("100"),
            "updated_at": s("2026-08-25T17:00:00Z"),
        }
    }


def head(source: str, *, digest: str = DIGEST, version: str = "version-1") -> dict:
    return {
        "VersionId": version,
        "ContentLength": 100,
        "ServerSideEncryption": "AES256",
        "Metadata": {"source-commit": source, "sha256": digest},
        "ChecksumSHA256": base64.b64encode(bytes.fromhex(digest.removeprefix("sha256:"))).decode(),
    }


class ReleaseControlTests(unittest.TestCase):
    def test_rc01_tim_releases_directly_without_an_approval_record(self):
        mode = verify_dispatch_authority(
            actor="timbrydges",
            actor_id="214414801",
            task_id=OWNER_SENTINEL,
            lease_id=OWNER_SENTINEL,
            source_commit=SOURCE,
        )
        self.assertEqual(mode, "owner")

    def test_rc02_non_owner_requires_active_lease_and_commit_specific_owner_event(self):
        mode = verify_dispatch_authority(
            actor="factory-controller[bot]",
            actor_id="999",
            task_id="task-1",
            lease_id="release-lease",
            source_commit=SOURCE,
            state_response=task_state(),
            owner_event_response=owner_event(),
            now=NOW,
        )
        self.assertEqual(mode, "agent")

    def test_rc03_expired_release_lease_is_rejected(self):
        with self.assertRaises(ReleaseControlError):
            verify_dispatch_authority(
                actor="factory-controller[bot]",
                actor_id="999",
                task_id="task-1",
                lease_id="release-lease",
                source_commit=SOURCE,
                state_response=task_state(expiry=NOW),
                owner_event_response=owner_event(),
                now=NOW,
            )

    def test_rc04_owner_authorization_cannot_be_replayed_for_another_commit(self):
        with self.assertRaises(ReleaseControlError):
            verify_dispatch_authority(
                actor="factory-controller[bot]",
                actor_id="999",
                task_id="task-1",
                lease_id="release-lease",
                source_commit=SOURCE,
                state_response=task_state(),
                owner_event_response=owner_event(TARGET),
                now=NOW,
            )

    def test_rc05_build_run_is_bound_to_successful_main_push(self):
        verify_build_run(build_run(), SOURCE)
        bad = build_run()
        bad["conclusion"] = "failure"
        with self.assertRaises(ReleaseControlError):
            verify_build_run(bad, SOURCE)

    def test_rc06_initial_release_records_captured_s3_version_atomically(self):
        transaction = prepare_release_transaction(
            table_name="factory-state",
            source_commit=SOURCE,
            artifact_digest=DIGEST,
            release_key=f"releases/{SOURCE}/factory-control-plane.tar.gz",
            object_version_id="captured-version",
            rollback_source_commit="INITIAL_RELEASE",
            actor="timbrydges",
            actor_id="214414801",
            authority_mode="owner",
            workflow_run="123",
            released_at="2026-08-25T18:00:00Z",
            current_response={},
            previous_response={},
            previous_head={},
            uploaded_head=head(SOURCE, version="captured-version"),
        )
        self.assertEqual(len(transaction), 3)
        deployment_item = transaction[0]["Put"]["Item"]
        self.assertEqual(deployment_item["object_version_id"]["S"], "captured-version")
        self.assertEqual(transaction[2]["Put"]["Item"]["SK"]["S"], "CURRENT")
        self.assertIn("attribute_not_exists", transaction[2]["Put"]["ConditionExpression"])

    def test_rc07_later_release_uses_compare_and_swap_against_verified_current(self):
        transaction = prepare_release_transaction(
            table_name="factory-state",
            source_commit=SOURCE,
            artifact_digest=DIGEST,
            release_key=f"releases/{SOURCE}/factory-control-plane.tar.gz",
            object_version_id="new-version",
            rollback_source_commit=PREVIOUS,
            actor="timbrydges",
            actor_id="214414801",
            authority_mode="owner",
            workflow_run="124",
            released_at="2026-08-25T18:01:00Z",
            current_response=current(PREVIOUS, version="previous-version"),
            previous_response=deployment(PREVIOUS, version="previous-version"),
            previous_head=head(PREVIOUS, version="previous-version"),
            uploaded_head=head(SOURCE, version="new-version"),
        )
        update = transaction[2]["Update"]
        self.assertIn("source_commit=:expected_source", update["ConditionExpression"])
        self.assertEqual(update["ExpressionAttributeValues"][":expected_version"]["S"], "previous-version")

    def test_rc08_release_rejects_stale_rollback_source(self):
        with self.assertRaises(ReleaseControlError):
            prepare_release_transaction(
                table_name="factory-state",
                source_commit=SOURCE,
                artifact_digest=DIGEST,
                release_key=f"releases/{SOURCE}/factory-control-plane.tar.gz",
                object_version_id="new-version",
                rollback_source_commit=PREVIOUS,
                actor="timbrydges",
                actor_id="214414801",
                authority_mode="owner",
                workflow_run="125",
                released_at="2026-08-25T18:02:00Z",
                current_response=current(TARGET),
                previous_response=deployment(PREVIOUS),
                previous_head=head(PREVIOUS),
                uploaded_head=head(SOURCE, version="new-version"),
            )

    def test_rc09_current_pointer_rejects_unversioned_object(self):
        malformed = current(SOURCE)
        malformed["Item"]["object_version_id"] = s("null")
        with self.assertRaises(ReleaseControlError):
            validate_current_pointer(malformed, SOURCE)

    def test_rc10_rollback_is_deterministic_and_owner_only(self):
        arguments = {
            "table_name": "factory-state",
            "target_source_commit": TARGET,
            "expected_current_source_commit": SOURCE,
            "reason": "restore prior verified release",
            "actor": "timbrydges",
            "actor_id": "214414801",
            "workflow_run": "126",
            "rolled_back_at": "2026-08-25T18:03:00Z",
            "current_response": current(SOURCE, version="current-version"),
            "target_response": deployment(TARGET, version="target-version"),
            "target_head": head(TARGET, version="target-version"),
        }
        first = prepare_rollback_transaction(**arguments)
        second = prepare_rollback_transaction(**arguments)
        self.assertEqual(first, second)
        update = first[1]["Update"]
        self.assertEqual(update["ExpressionAttributeValues"][":expected_version"]["S"], "current-version")
        with self.assertRaises(ReleaseControlError):
            prepare_rollback_transaction(**{**arguments, "actor_id": "999"})


if __name__ == "__main__":
    unittest.main()
