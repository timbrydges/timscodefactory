"""Prepare exact, non-authoritative material for the independent AI Inspector.

The packet contains no verdict or signature. The Inspector must assess the
untrusted task material itself before its separate role may issue a receipt.
"""
from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.worker import digest
from prepare_acceptance_job import prepare


def build_packet(binding: dict, plan: dict, input_bytes: bytes,
                 contract_bytes: bytes, *, now: datetime) -> dict:
    # No receipt has been issued yet. These local sentinels are never written
    # to a job or accepted as evidence of owner/Inspector authorization.
    _, checked = prepare(binding, plan,
        {'owner': 'REVIEW_PACKET_ONLY', 'reviewer': 'REVIEW_PACKET_ONLY'},
        input_bytes, contract_bytes, now=now)
    return {'schema_version': '1.0', 'status': 'AWAITING_INDEPENDENT_AI_INSPECTION',
        'inspector_identity': 'independent_inspector_service',
        'required_provider_profile': 'review_adversarial',
        'activation_id': binding['activation_id'],
        'factory_id': plan['factory_id'], 'task_id': plan['task_id'],
        'source_commit': binding['source_commit'],
        'plan_digest': checked['receipt_plan_digest'],
        'input_digest': digest(input_bytes), 'contract_digest': digest(contract_bytes),
        'proposed_capability': plan['capability_payload'],
        'review_request': {
            key: plan['review_payload'][key] for key in
            ('factory_id', 'task_id', 'binding', 'reviewer_identity',
             'issued_at', 'expires_at')},
        'untrusted_material': {
            'input_base64': base64.b64encode(input_bytes).decode('ascii'),
            'contract_base64': base64.b64encode(contract_bytes).decode('ascii')},
        'review_verdict': None, 'signature': None,
        'receipt_versions': None, 'model_calls_authorized': 0}


def main():
    if len(sys.argv) != 6:
        raise SystemExit('usage: prepare_acceptance_inspector_review.py '
                         'BINDING.json PLAN.json INPUT CONTRACT OUT.json')
    packet = build_packet(json.loads(Path(sys.argv[1]).read_text()),
        json.loads(Path(sys.argv[2]).read_text()), Path(sys.argv[3]).read_bytes(),
        Path(sys.argv[4]).read_bytes(), now=datetime.now(timezone.utc))
    Path(sys.argv[5]).write_text(json.dumps(packet, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'status': packet['status'], 'plan_digest': packet['plan_digest'],
                      'model_calls_authorized': 0}))


if __name__ == '__main__':
    main()
