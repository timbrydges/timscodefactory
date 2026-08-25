"""DynamoDB persistence adapter using atomic state + audit writes."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from .model import CONTROLLER_IDENTITY, OWNER_IDENTITY, AuthorityError, TaskState


class DynamoDBStateStore:
    def __init__(self, table_name: str, client: Any = None):
        if client is None:
            import boto3  # optional runtime dependency, supplied by the controller image

            client = boto3.client("dynamodb")
        self.table_name = table_name
        self.client = client

    def persist_transition(self, before: TaskState, after: TaskState, *, caller_identity: str, event_id: str) -> None:
        if caller_identity not in {CONTROLLER_IDENTITY, OWNER_IDENTITY}:
            raise AuthorityError("only the controller or Tim, the Factory Owner, may persist authoritative state")
        if after.updated_by != caller_identity:
            raise AuthorityError("persisted state actor must match the authoritative caller")
        state_item = self._serialize_state(after)
        event_item = {
            "PK": {"S": f"FACTORY#{after.factory_id}#TASK#{after.task_id}"},
            "SK": {"S": f"EVENT#{after.updated_at.isoformat()}#{event_id}"},
            "event_type": {"S": "STATE_TRANSITION"},
            "from_version": {"N": str(before.version)},
            "to_version": {"N": str(after.version)},
            "from_state": {"S": before.state},
            "to_state": {"S": after.state},
            "actor_identity": {"S": caller_identity},
        }
        self.client.transact_write_items(
            TransactItems=[
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
            ],
            ClientRequestToken=event_id,
        )

    @staticmethod
    def _serialize_state(state: TaskState) -> dict[str, dict[str, str]]:
        payload = asdict(state)
        payload["updated_at"] = state.updated_at.isoformat()
        payload["consumed_evidence_ids"] = sorted(state.consumed_evidence_ids)
        for lease in payload["leases"]:
            lease["expires_at"] = lease["expires_at"].isoformat()
        return {
            "PK": {"S": f"FACTORY#{state.factory_id}#TASK#{state.task_id}"},
            "state": {"S": state.state},
            "version": {"N": str(state.version)},
            "updated_at": {"S": state.updated_at.isoformat()},
            "payload": {"S": json.dumps(payload, sort_keys=True)},
        }
