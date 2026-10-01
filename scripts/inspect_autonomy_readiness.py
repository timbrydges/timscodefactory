"""Read-only activation audit. Never invokes roles, reads secrets, or grants authority."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from prepare_role_deployment import ACCOUNT, ROOT, aws, source

sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.autonomy_contract import load_autonomy_operating_allowance


FUNCTIONS = {
    'builder': ('tims-factory-builder', 'FACTORY_OPERATIONAL_EXECUTION_ENABLED',
                'FACTORY_ACCEPTANCE_ACTIVATION_JSON'),
    'broker': ('tims-factory-provider-broker', 'FACTORY_ACCEPTANCE_BROKER_ENABLED',
               'FACTORY_ACCEPTANCE_ACTIVATION_JSON'),
    'controller': ('tims-software-factory-autonomy-controller:acceptance',
                   'FACTORY_AUTONOMY_CONTROLLER_ENABLED',
                   'FACTORY_ACCEPTANCE_CONTROLLER_JSON'),
}


def assess(allowance, commit, receipt, functions, schedule, *, now):
    """Report blockers, never infer authorization from an empty blocker list."""
    blockers = list(allowance.pending_gates)
    if not allowance.activation_ready:
        blockers.append('operating_contract_not_active')
    if not allowance.pricing_observed_at <= now < allowance.pricing_expires_at:
        blockers.append('builder_pricing_not_current')
    # Historical accepted evidence is not a fresh receipt for another checkout.
    if receipt.get('source_commit') != commit:
        blockers.append('reviewer_receipt_source_differs')
    try:
        expiry = datetime.fromisoformat(receipt['reviewer_receipt_expires_at'])
        valid_time = expiry.tzinfo is not None and now < expiry
    except (KeyError, TypeError, ValueError):
        valid_time = False
    if not valid_time:
        blockers.append('reviewer_receipt_expired_or_invalid')
    if (receipt.get('status') != 'INSPECTOR_REVIEW_ACCEPTED_AND_RECEIPT_PUBLISHED'
            or receipt.get('reviewer_receipt_signature_verified') is not True):
        blockers.append('reviewer_receipt_not_verified')
    summaries = {}
    for role, (_, flag, binding) in FUNCTIONS.items():
        config = functions.get(role, {})
        env = config.get('Environment', {}).get('Variables', {})
        enabled = env.get(flag) == 'true'
        configured = isinstance(env.get(binding), str) and bool(env[binding].strip())
        summaries[role] = {'enabled': enabled, 'activation_config_present': configured,
                           'timeout_seconds': config.get('Timeout')}
        if config.get('State') != 'Active':
            blockers.append(role + '_lambda_not_active')
        if not enabled:
            blockers.append(role + '_execution_disabled')
        if not configured:
            blockers.append(role + '_activation_config_missing')
    controller_timeout = functions.get('controller', {}).get('Timeout', 0)
    builder_timeout = functions.get('builder', {}).get('Timeout', 0)
    broker_timeout = functions.get('broker', {}).get('Timeout', 0)
    if (type(builder_timeout) is not int or type(broker_timeout) is not int
            or builder_timeout <= broker_timeout):
        blockers.append('builder_timeout_does_not_cover_broker')
    if (type(controller_timeout) is not int or type(builder_timeout) is not int
            or controller_timeout <= builder_timeout):
        blockers.append('controller_timeout_does_not_cover_builder')
    if schedule.get('State') != 'ENABLED':
        blockers.append('schedule_disabled')
    return {'status': 'BLOCKED' if blockers else 'REQUIRES_FINAL_BOUND_DEPLOYMENT_VERIFICATION',
            'source_commit': commit, 'observed_at': now.isoformat(),
            'blockers': sorted(set(blockers)), 'functions': summaries,
            'schedule_state': schedule.get('State'),
            'activation_authorized_by_audit': False, 'model_calls': 0,
            'secret_values_read': False,
            'limitation': 'Historical receipt metadata only; final activation also requires '
                          'exact live receipt signatures, owner receipt, job pins, IAM, '
                          'budget, state and deployed artifact verification.'}


def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: inspect_autonomy_readiness.py ACCEPTED_EVIDENCE.json OUT.json')
    commit = source()
    if aws('sts', 'get-caller-identity').get('Account') != ACCOUNT:
        raise RuntimeError('wrong AWS account')
    functions = {role: aws('lambda', 'get-function-configuration', '--function-name', name)
                 for role, (name, _, _) in FUNCTIONS.items()}
    schedule = aws('scheduler', 'get-schedule', '--name',
                   'tims-software-factory-autonomy-acceptance')
    result = assess(load_autonomy_operating_allowance(ROOT), commit,
                    json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')),
                    functions, schedule, now=datetime.now(timezone.utc))
    Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
