"""Encode one reviewed acceptance job without publishing or signing anything.

The plan and two immutable receipt versions are supplied by the separate
authorization process. This command cannot manufacture either signature.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.acceptance_jobs import encode_job
from factory_runtime.autonomy import AutonomyActivation, ScheduledAutonomyJob
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import ReceiptVersions, receipt_plan_digest
from factory_runtime.worker import digest
from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
from factory_state.model import Lease, StateError

from prepare_acceptance_controller_bundle import build_bundle


PLAN_FIELDS = {'factory_id', 'task_id', 'state', 'state_version', 'lease',
               'request', 'capability_payload', 'review_payload', 'plan_digest'}
BINDING_FIELDS = {'activation_id', 'source_commit', 'contract_digest',
                  'starts_at', 'expires_at', 'builder_version_arn'}


def prepare(binding: dict, document: dict, versions: dict, input_bytes: bytes,
            contract_bytes: bytes, *, now: datetime) -> tuple[bytes, dict]:
    if (not isinstance(binding, dict) or set(binding) != BINDING_FIELDS or
            not isinstance(document, dict) or set(document) != PLAN_FIELDS or
            not isinstance(versions, dict) or set(versions) != {'owner', 'reviewer'} or
            type(document['state_version']) is not int or
            not isinstance(document['lease'], dict) or
            set(document['lease']) != set(Lease.__dataclass_fields__) or
            not isinstance(document['request'], dict) or
            set(document['request']) != set(DispatchRequest.__dataclass_fields__) or
            not isinstance(document['capability_payload'], dict) or
            not isinstance(document['review_payload'], dict)):
        raise StateError('publication plan has missing or extra fields')
    try:
        activation = AutonomyActivation(binding['activation_id'], 'tims-software-factory',
            'deterministic-text-fingerprint', binding['source_commit'],
            binding['contract_digest'], datetime.fromisoformat(binding['starts_at']),
            datetime.fromisoformat(binding['expires_at']))
        lease = Lease(**{**document['lease'],
            'expires_at': datetime.fromisoformat(document['lease']['expires_at'])})
        request = DispatchRequest(**document['request'])
        receipt_versions = ReceiptVersions(**versions)
    except (KeyError, TypeError, ValueError) as error:
        raise StateError('publication binding is malformed') from error
    activation.validate(now)
    plan = IntakePlan(document['factory_id'], document['task_id'], document['state'],
        document['state_version'], lease, request, document['capability_payload'],
        document['review_payload'])
    expected_capability = {'kind': 'capability', 'factory_id': plan.factory_id,
        'objective_id': request.objective_id, 'capability_id': request.capability_id,
        'contract_digest': request.contract_digest, 'owner_identity': 'tim_brydges'}
    expected_review = {'kind': 'scope_review', 'factory_id': plan.factory_id,
        'task_id': plan.task_id, 'binding': DynamoDBDispatchStore._binding(request),
        'verdict': 'ACCEPTED', 'reviewer_identity': 'independent_inspector_service'}
    if (set(plan.capability_payload) != set(expected_capability) |
            {'issued_at', 'expires_at', 'required_evidence', 'stop_condition'} or
            set(plan.review_payload) != set(expected_review) |
            {'issued_at', 'expires_at', 'rationale'} or
            any(plan.capability_payload.get(key) != value
                for key, value in expected_capability.items()) or
            any(plan.review_payload.get(key) != value
                for key, value in expected_review.items()) or
            any(not isinstance(value, str) or not value.strip() or len(value) > 2000
                for value in (plan.capability_payload.get('required_evidence'),
                              plan.capability_payload.get('stop_condition'),
                              plan.review_payload.get('rationale'))) or
            any(type(payload.get('issued_at')) is not int or
                type(payload.get('expires_at')) is not int or
                not payload['issued_at'] <= now.timestamp() < payload['expires_at']
                for payload in (plan.capability_payload, plan.review_payload))):
        raise StateError('publication receipts differ from exact approved scope')
    if (not isinstance(input_bytes, bytes) or not isinstance(contract_bytes, bytes) or
            (plan.factory_id, plan.task_id, plan.state) !=
                (activation.factory_id, activation.task_id, 'IMPLEMENTATION') or
            lease.role_id != 'engineering_agent' or lease.revoked or
            not now < lease.expires_at <= activation.expires_at or
            request.lease_id != lease.lease_id or
            request.source_commit != activation.source_commit or
            request.contract_digest != activation.contract_digest or
            request.contract_digest != digest(contract_bytes) or
            request.input_digest != digest(input_bytes) or
            document['plan_digest'] != receipt_plan_digest(plan) or
            any(not payload['expires_at'] <= lease.expires_at.timestamp()
                for payload in (plan.capability_payload, plan.review_payload))):
        raise StateError('publication plan differs from approved activation or is expired')
    raw = encode_job(ScheduledAutonomyJob(plan, receipt_versions, input_bytes,
                                          contract_bytes), activation.activation_id)
    # Run the exact controller decoder and matching IAM renderer before emitting
    # bytes. The placeholder version is replaced only after a real S3 upload.
    reviewed = build_bundle({**binding, 'job_version_id': 'NOT_PUBLISHED'}, raw)
    return raw, {'status': 'PREPARED_NOT_PUBLISHED',
                 'activation_id': activation.activation_id,
                 'job_object_sha256': digest(raw),
                 'receipt_plan_digest': reviewed['receipt_plan_digest'],
                 'model_calls_authorized': 0}


def main():
    if len(sys.argv) != 7:
        raise SystemExit('usage: prepare_acceptance_job.py BINDING.json PLAN.json '
                         'RECEIPT_VERSIONS.json INPUT CONTRACT OUT.json')
    raw, result = prepare(json.loads(Path(sys.argv[1]).read_text()),
        json.loads(Path(sys.argv[2]).read_text()),
        json.loads(Path(sys.argv[3]).read_text()),
        Path(sys.argv[4]).read_bytes(), Path(sys.argv[5]).read_bytes(),
        now=datetime.now(timezone.utc))
    Path(sys.argv[6]).write_bytes(raw)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
