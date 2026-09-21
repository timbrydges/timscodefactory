"""Durable at-most-once dispatch claims; no provider calls or gate advancement.

Only a trusted controller adapter may use this ledger. Project activation,
provider reservation and signed result verification remain separate mandatory
boundaries. A STARTED record with no receipt is an unknown external outcome,
never permission to retry an external side effect.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .dynamodb import DynamoDBStateStore
from .model import (COMMIT_SHA, SHA256_DIGEST, SAFE_IDENTIFIER, CONTROLLER_IDENTITY,
                    AuthorityError, FactoryStateMachine, StateError, TaskState)


@dataclass(frozen=True)
class DispatchRequest:
    lease_id: str
    source_commit: str
    contract_digest: str
    input_digest: str

    def __post_init__(self) -> None:
        for value, pattern in ((self.lease_id, SAFE_IDENTIFIER),
                               (self.source_commit, COMMIT_SHA),
                               (self.contract_digest, SHA256_DIGEST),
                               (self.input_digest, SHA256_DIGEST)):
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise StateError("invalid dispatch binding")


class DynamoDBDispatchStore:
    """One immutable work identity per task lease, with conditional claim/receipt.

    Lost responses are recovered by read(), not by repeating claim() or invoking
    a provider. No TTL is attached to dispatch records: deleting history would
    reopen work. A fresh lease is a separate authorization, not automatic retry.
    """

    def __init__(self, table_name: str, client: Any):
        self.table_name, self.client = table_name, client

    @staticmethod
    def _owner(caller_identity: str) -> None:
        if caller_identity != CONTROLLER_IDENTITY:
            raise AuthorityError("dispatch ledger writes require the controller")

    @staticmethod
    def _key(state: TaskState, request: DispatchRequest) -> dict:
        return {"PK": {"S": f"FACTORY#{state.factory_id}#TASK#{state.task_id}"},
                "SK": {"S": f"DISPATCH#{request.lease_id}"}}

    @staticmethod
    def _binding(request: DispatchRequest) -> str:
        return json.dumps(vars(request), sort_keys=True, separators=(",", ":"))

    def _state_guard(self, state: TaskState, request: DispatchRequest, now: datetime) -> dict:
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise StateError("dispatch time must be timezone-aware")
        if now < state.updated_at:
            raise StateError("dispatch state is future-dated")
        FactoryStateMachine(state).assert_dispatch_allowed(CONTROLLER_IDENTITY, request.lease_id, now=now)
        lease = next(x for x in state.leases if x.lease_id == request.lease_id)
        if lease.role_id == "release_automation":
            raise AuthorityError("production release must use the existing owner-authorized release path")
        serialized = DynamoDBStateStore._serialize_state(state)
        return {"ConditionCheck": {"TableName": self.table_name,
                "Key": {"PK": serialized["PK"], "SK": {"S": "STATE"}},
                "ConditionExpression": "#v = :v AND payload = :payload",
                "ExpressionAttributeNames": {"#v": "version"},
                "ExpressionAttributeValues": {":v": serialized["version"], ":payload": serialized["payload"]}}}

    def enqueue(self, state: TaskState, request: DispatchRequest, *, caller_identity: str, now: datetime) -> str:
        self._owner(caller_identity)
        guard = self._state_guard(state, request, now)
        key = self._key(state, request)
        # Input/commit changes cannot turn the same lease into another job.
        dispatch_id = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
        item = {**key, "dispatch_id": {"S": dispatch_id}, "binding": {"S": self._binding(request)},
                "status": {"S": "READY"}, "queued_at": {"S": now.isoformat()}}
        self.client.transact_write_items(TransactItems=[guard, {"Put": {
            "TableName": self.table_name, "Item": item,
            "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)"}}])
        return dispatch_id

    def claim(self, state: TaskState, request: DispatchRequest, *, worker_id: str,
              caller_identity: str, now: datetime) -> None:
        self._owner(caller_identity)
        if not isinstance(worker_id, str) or not SAFE_IDENTIFIER.fullmatch(worker_id):
            raise StateError("invalid worker identity")
        guard = self._state_guard(state, request, now)
        self.client.transact_write_items(TransactItems=[guard, {"Update": {
            "TableName": self.table_name, "Key": self._key(state, request),
            "UpdateExpression": "SET #s = :started, worker_id = :worker, started_at = :now",
            "ConditionExpression": "#s = :ready AND binding = :binding",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":started": {"S": "STARTED"}, ":ready": {"S": "READY"},
                ":worker": {"S": worker_id}, ":now": {"S": now.isoformat()},
                ":binding": {"S": self._binding(request)}}}}])

    def record_receipt(self, state: TaskState, request: DispatchRequest, *, worker_id: str,
                       receipt_digest: str, caller_identity: str) -> None:
        self._owner(caller_identity)
        if not isinstance(worker_id, str) or not SAFE_IDENTIFIER.fullmatch(worker_id):
            raise StateError("invalid worker identity")
        if not isinstance(receipt_digest, str) or not SHA256_DIGEST.fullmatch(receipt_digest):
            raise StateError("invalid receipt digest")
        # Late results may be recorded after pause/expiry; this never advances a gate.
        # Identical receipt writes are idempotent; conflicting results are rejected.
        self.client.update_item(TableName=self.table_name, Key=self._key(state, request),
            UpdateExpression="SET #s = :recorded, receipt_digest = :receipt",
            ConditionExpression="binding = :binding AND worker_id = :worker AND "
                "(#s = :started OR (#s = :recorded AND receipt_digest = :receipt))",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":binding": {"S": self._binding(request)},
                ":worker": {"S": worker_id}, ":started": {"S": "STARTED"},
                ":recorded": {"S": "RECEIPT_RECORDED"}, ":receipt": {"S": receipt_digest}})

    def read(self, state: TaskState, request: DispatchRequest) -> dict | None:
        item = self.client.get_item(TableName=self.table_name, Key=self._key(state, request),
                                    ConsistentRead=True).get("Item")
        if item and item.get("binding") != {"S": self._binding(request)}:
            raise StateError("dispatch lease already has different immutable inputs")
        return item
