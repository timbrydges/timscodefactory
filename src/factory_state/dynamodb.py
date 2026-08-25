"""DynamoDB persistence adapter using atomic state + audit writes."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from .model import (
    ALLOWED_TRANSITIONS,
    CONTROLLER_IDENTITY,
    OWNER_IDENTITY,
    AuthorityError,
    Lease,
    StateError,
    TaskState,
)


EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$")
EVENT_TYPES = {"LEASE_ISSUED", "OWNER_OVERRIDE", "STATE_TRANSITION"}


class DynamoDBStateStore:
    def __init__(self, table_name: str, client: Any = None):
        if client is None:
            import boto3  # optional runtime dependency, supplied by the controller image

            client = boto3.client("dynamodb")
        self.table_name = table_name
        self.client = client

    def persist_transition(
        self,
        before: TaskState,
        after: TaskState,
        *,
        caller_identity: str,
        event_id: str,
        audit_event: dict[str, Any],
    ) -> None:
        if caller_identity not in {CONTROLLER_IDENTITY, OWNER_IDENTITY}:
            raise AuthorityError("only the controller or Tim, the Factory Owner, may persist authoritative state")
        if after.updated_by != caller_identity:
            raise AuthorityError("persisted state actor must match the authoritative caller")
        if before.factory_id != after.factory_id or before.task_id != after.task_id:
            raise StateError("a transition cannot change its factory or task identity")
        if after.version != before.version + 1:
            raise StateError("persisted state version must advance exactly once")
        if before.state not in ALLOWED_TRANSITIONS or after.state not in ALLOWED_TRANSITIONS:
            raise StateError("persisted state contains an unknown state")
        if not EVENT_ID.fullmatch(event_id):
            raise StateError("event id must be 1-36 safe idempotency characters")
        self._validate_audit_event(before, after, caller_identity, audit_event)
        self._validate_state_delta(before, after, caller_identity, audit_event)

        state_item = self._serialize_state(after)
        event_type = audit_event["event_type"]
        event_item = {
            "PK": {"S": f"FACTORY#{after.factory_id}#TASK#{after.task_id}"},
            "SK": {"S": f"EVENT#{after.updated_at.isoformat()}#{event_id}"},
            "event_type": {"S": event_type},
            "from_version": {"N": str(before.version)},
            "to_version": {"N": str(after.version)},
            "from_state": {"S": before.state},
            "to_state": {"S": after.state},
            "actor_identity": {"S": caller_identity},
        }
        if "details" in audit_event:
            event_item["details"] = {"S": json.dumps(audit_event["details"], sort_keys=True)}

        transaction: list[dict[str, Any]] = [
            {
                "Update": {
                    "TableName": self.table_name,
                    "Key": {
                        "PK": state_item["PK"],
                        "SK": {"S": "STATE"},
                    },
                    "UpdateExpression": "SET #s=:state, #v=:next, payload=:payload, updated_at=:updated",
                    "ConditionExpression": "attribute_not_exists(#v) OR #v=:expected",
                    "ExpressionAttributeNames": {"#s": "state", "#v": "version"},
                    "ExpressionAttributeValues": {
                        ":state": state_item["state"],
                        ":next": state_item["version"],
                        ":expected": {"N": str(before.version)},
                        ":payload": state_item["payload"],
                        ":updated": state_item["updated_at"],
                    },
                }
            },
            {
                "Put": {
                    "TableName": self.table_name,
                    "Item": event_item,
                    "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)",
                }
            },
        ]
        before_by_id = {lease.lease_id: lease for lease in before.leases}
        for lease in after.leases:
            previous = before_by_id.get(lease.lease_id)
            if previous is not None and lease == previous:
                continue
            if previous is None:
                transaction.append(
                    {
                        "Put": {
                            "TableName": self.table_name,
                            "Item": self._serialize_lease(after, lease),
                            "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)",
                        }
                    }
                )
            else:
                if not previous.active_at(after.updated_at):
                    # Expired lease rows may already have been removed by TTL;
                    # the authoritative state payload still records revocation.
                    continue
                transaction.append(
                    {
                        "Update": {
                            "TableName": self.table_name,
                            "Key": {
                                "PK": {"S": f"FACTORY#{after.factory_id}#TASK#{after.task_id}"},
                                "SK": {"S": f"LEASE#{lease.lease_id}"},
                            },
                            "UpdateExpression": "SET revoked=:revoked",
                            "ConditionExpression": (
                                "role_id=:role AND authoritative_identity=:identity "
                                "AND expires_at=:expiry AND revoked=:expected_revoked"
                            ),
                            "ExpressionAttributeValues": {
                                ":revoked": {"BOOL": lease.revoked},
                                ":role": {"S": previous.role_id},
                                ":identity": {"S": previous.authoritative_identity},
                                ":expiry": {"N": str(int(previous.expires_at.timestamp()))},
                                ":expected_revoked": {"BOOL": previous.revoked},
                            },
                        }
                    }
                )
        if len(transaction) > 100:
            raise StateError("transition exceeds DynamoDB's atomic transaction limit")
        self.client.transact_write_items(
            TransactItems=transaction,
            ClientRequestToken=event_id,
        )

    def load_state(self, factory_id: str, task_id: str) -> TaskState | None:
        response = self.client.get_item(
            TableName=self.table_name,
            Key={
                "PK": {"S": f"FACTORY#{factory_id}#TASK#{task_id}"},
                "SK": {"S": "STATE"},
            },
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not item:
            return None
        return self._deserialize_payload(item["payload"]["S"])

    @staticmethod
    def _serialize_state(state: TaskState) -> dict[str, dict[str, str]]:
        payload: dict[str, Any] = {
            "factory_id": state.factory_id,
            "task_id": state.task_id,
            "state": state.state,
            "version": state.version,
            "updated_at": state.updated_at.isoformat(),
            "updated_by": state.updated_by,
            "active_lease_ids": sorted(
                lease.lease_id for lease in state.leases if lease.active_at(state.updated_at)
            ),
            "leases": [
                {
                    "lease_id": lease.lease_id,
                    "role_id": lease.role_id,
                    "authoritative_identity": lease.authoritative_identity,
                    "expires_at": lease.expires_at.isoformat(),
                    "revoked": lease.revoked,
                }
                for lease in state.leases
            ],
            "consumed_evidence_ids": sorted(state.consumed_evidence_ids),
        }
        if state.remediation is not None:
            payload["remediation"] = state.remediation
        if state.stall is not None:
            payload["stall"] = state.stall
        return {
            "PK": {"S": f"FACTORY#{state.factory_id}#TASK#{state.task_id}"},
            "state": {"S": state.state},
            "version": {"N": str(state.version)},
            "updated_at": {"S": state.updated_at.isoformat()},
            "payload": {"S": json.dumps(payload, sort_keys=True)},
        }

    @staticmethod
    def _serialize_lease(state: TaskState, lease: Lease) -> dict[str, dict[str, str] | dict[str, bool]]:
        return {
            "PK": {"S": f"FACTORY#{state.factory_id}#TASK#{state.task_id}"},
            "SK": {"S": f"LEASE#{lease.lease_id}"},
            "lease_id": {"S": lease.lease_id},
            "role_id": {"S": lease.role_id},
            "authoritative_identity": {"S": lease.authoritative_identity},
            "expires_at": {"N": str(int(lease.expires_at.timestamp()))},
            "revoked": {"BOOL": lease.revoked},
        }

    @staticmethod
    def _deserialize_payload(payload_json: str) -> TaskState:
        payload = json.loads(payload_json)
        leases = tuple(
            Lease(
                lease_id=item["lease_id"],
                role_id=item["role_id"],
                authoritative_identity=item["authoritative_identity"],
                expires_at=datetime.fromisoformat(item["expires_at"]),
                revoked=item["revoked"],
            )
            for item in payload["leases"]
        )
        state = TaskState(
            factory_id=payload["factory_id"],
            task_id=payload["task_id"],
            state=payload["state"],
            version=payload["version"],
            updated_at=datetime.fromisoformat(payload["updated_at"]),
            updated_by=payload["updated_by"],
            leases=leases,
            consumed_evidence_ids=frozenset(payload["consumed_evidence_ids"]),
            remediation=payload.get("remediation"),
            stall=payload.get("stall"),
        )
        expected_active = sorted(
            lease.lease_id for lease in leases if lease.active_at(state.updated_at)
        )
        if payload.get("active_lease_ids") != expected_active:
            raise StateError("persisted active lease index does not match lease records")
        return state

    @staticmethod
    def _validate_audit_event(
        before: TaskState,
        after: TaskState,
        caller_identity: str,
        event: dict[str, Any],
    ) -> None:
        event_type = event.get("event_type")
        if event_type not in EVENT_TYPES:
            raise StateError("audit event type is invalid")
        expected = {
            "task_id": after.task_id,
            "from_version": before.version,
            "to_version": after.version,
            "state": after.state,
            "actor_identity": caller_identity,
            "at": after.updated_at.isoformat(),
        }
        if any(event.get(key) != value for key, value in expected.items()):
            raise StateError("audit event does not match the state transition")
        if caller_identity == OWNER_IDENTITY:
            reason = event.get("details", {}).get("reason")
            if event_type != "OWNER_OVERRIDE" or not isinstance(reason, str) or not reason.strip():
                raise StateError("owner overrides require a persisted audit reason")
        elif event_type == "OWNER_OVERRIDE":
            raise StateError("only Tim may persist an owner override event")

    @staticmethod
    def _validate_state_delta(
        before: TaskState,
        after: TaskState,
        caller_identity: str,
        event: dict[str, Any],
    ) -> None:
        event_type = event["event_type"]
        before_leases = {lease.lease_id: lease for lease in before.leases}
        after_leases = {lease.lease_id: lease for lease in after.leases}
        if len(before_leases) != len(before.leases) or len(after_leases) != len(after.leases):
            raise StateError("state contains duplicate lease ids")
        if not set(before_leases).issubset(after_leases):
            raise StateError("persisted transitions cannot remove lease history")
        for lease_id, prior in before_leases.items():
            current = after_leases[lease_id]
            if (
                current.role_id != prior.role_id
                or current.authoritative_identity != prior.authoritative_identity
                or current.expires_at != prior.expires_at
                or (prior.revoked and not current.revoked)
            ):
                raise StateError("persisted transitions cannot rewrite or reactivate leases")
        if not before.consumed_evidence_ids.issubset(after.consumed_evidence_ids):
            raise StateError("persisted transitions cannot remove consumed evidence history")

        new_lease_ids = set(after_leases) - set(before_leases)
        if event_type == "LEASE_ISSUED":
            if caller_identity != CONTROLLER_IDENTITY or after.state != before.state or len(new_lease_ids) != 1:
                raise StateError("LEASE_ISSUED must atomically add exactly one controller lease")
            if after.consumed_evidence_ids != before.consumed_evidence_ids:
                raise StateError("lease issuance cannot consume evidence")
            new_lease = after_leases[next(iter(new_lease_ids))]
            if event.get("details") != {
                "lease_id": new_lease.lease_id,
                "role_id": new_lease.role_id,
                "expires_at": new_lease.expires_at.isoformat(),
            }:
                raise StateError("lease audit details do not match the issued lease")
        elif new_lease_ids:
            raise StateError("only LEASE_ISSUED may add a lease")

        if event_type == "STATE_TRANSITION":
            if caller_identity != CONTROLLER_IDENTITY:
                raise StateError("normal state transitions require the controller")
            if after.state not in ALLOWED_TRANSITIONS.get(before.state, set()):
                raise StateError("persisted controller transition is not allowed by the state graph")
            evidence_delta = sorted(after.consumed_evidence_ids - before.consumed_evidence_ids)
            if event.get("details") != {"evidence_ids": evidence_delta}:
                raise StateError("transition audit details do not match consumed evidence")
        elif event_type == "OWNER_OVERRIDE":
            if caller_identity != OWNER_IDENTITY:
                raise StateError("owner override requires Tim's identity")
            if after.consumed_evidence_ids != before.consumed_evidence_ids:
                raise StateError("owner override cannot rewrite consumed agent evidence")
        elif event_type == "LEASE_ISSUED" and after.state != before.state:
            raise StateError("lease issuance cannot change task state")

        if event_type in {"STATE_TRANSITION", "OWNER_OVERRIDE"} and any(
            not lease.revoked for lease in after.leases
        ):
            raise StateError("state changes must revoke all delegated leases")
        if after.state == "PAUSED" and any(not lease.revoked for lease in after.leases):
            raise StateError("PAUSED state must revoke every delegated lease")
