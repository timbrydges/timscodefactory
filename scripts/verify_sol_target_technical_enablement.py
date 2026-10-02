"""Verify the merged Sol switch against exact source and bounded evidence."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def verify(root: Path = ROOT) -> dict:
    root = Path(root)
    policy_bytes = (root / 'factory/profiles/provider-live-activation.yaml').read_bytes()
    catalog_bytes = (root / 'factory/profiles/provider-models.yaml').read_bytes()
    record = json.loads((root / 'factory/evidence/sol-target-technical-enablement-2026-09-29.json').read_text())
    contract = yaml.safe_load((root / 'factory/autonomy/operating-contract.yaml').read_text())
    policy, catalog = yaml.safe_load(policy_bytes), yaml.safe_load(catalog_bytes)
    if (record.get('status') != 'SOL_TARGET_TECHNICAL_ENABLEMENT_VERIFIED' or
            record.get('source_commit') != 'c8f3d9ed6a519d790c2fe3697fd385f55c778696' or
            record.get('pull_request') != 198 or
            record.get('owner_review_exception') !=
                'factory/evidence/owner-review-exception-2026-09-29.json' or
            record.get('target_alias') != 'coding_primary_sol_live' or
            record.get('model_id') != 'gpt-5.6-sol' or
            record.get('policy_sha256') != hashlib.sha256(policy_bytes).hexdigest() or
            record.get('catalog_sha256') != hashlib.sha256(catalog_bytes).hexdigest() or
            policy['approved_live_targets']['coding_primary_sol_live'].get('enabled') is not True or
            catalog['targets']['coding_primary_sol_live'].get('enabled') is not True or
            policy['approved_live_targets']['coding_primary_terra_live'].get('enabled') is not False or
            catalog['targets']['coding_primary_terra_live'].get('enabled') is not False or
            catalog['selectors']['FACTORY_CODING_MODEL'].get('default_target') !=
                'coding_primary_dry_run' or
            record.get('policy_target_enabled') is not True or
            record.get('catalog_target_enabled') is not True or
            record.get('challenger_enabled') is not False or
            record.get('dry_run_default_retained') is not True or
            record.get('operational_roles_enabled') is not False or
            record.get('schedule_enabled') is not False or
            record.get('model_calls') != 0 or
            record.get('production_release_authorized') is not False or
            contract['activation']['verified_gates'].get('approved_target_technical_enablement') != {
                'evidence': 'factory/evidence/sol-target-technical-enablement-2026-09-29.json'} or
            'approved_target_technical_enablement' in contract['activation']['pending_gates'] or
            contract['authority']['production_release'] != 'DENY' or
            contract['status'] not in {'OWNER_APPROVED_AWAITING_TECHNICAL_GATES',
                                       'GUARDED_COMMISSIONING'}):
        raise ValueError('Sol target technical evidence differs from exact merged source')
    return {'status': record['status'], 'source_commit': record['source_commit'],
            'model_calls': 0}


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT)))
