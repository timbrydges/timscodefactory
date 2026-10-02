"""Prepare one consistent, disabled three-component deployment without AWS IO.

Receipt version names are not proof of publication or signatures. The output
cannot activate anything; the live deployment must independently verify the
objects, signatures, state, budget, IAM, artifacts and schedule before enabling.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]

from factory_runtime.acceptance_broker import BROKER_ARN
from factory_runtime.acceptance_jobs import PinnedJobVersion, VersionedS3AcceptanceJobSource
from factory_runtime.autonomy import AutonomyActivation
from factory_runtime.autonomy_contract import load_autonomy_operating_allowance
from factory_runtime.autonomy_controller_lambda import _controller_activation
from factory_runtime.lambda_role import _builder_activation
from factory_state.model import CONTROLLER_IDENTITY, StateError, TaskState
from prepare_acceptance_controller_bundle import _LocalVersionedObject, build_bundle
from prepare_acceptance_job import prepare

SECRET = re.compile(r'arn:aws:secretsmanager:ca-central-1:666730517561:'
                    r'secret:tims-software-factory/provider/openai/acceptance-[A-Za-z0-9]{6}\Z')
FIELDS = {'activation_id', 'source_commit', 'contract_digest', 'starts_at',
          'expires_at', 'builder_version_arn', 'broker_version_arn',
          'job_version_id', 'provider_secret_arn'}


def build_activation_bundle(binding, raw, *, root=ROOT, now):
    if (not isinstance(binding, dict) or set(binding) != FIELDS or
            not isinstance(binding['broker_version_arn'], str) or
            not BROKER_ARN.fullmatch(binding['broker_version_arn']) or
            not isinstance(binding['provider_secret_arn'], str) or
            not SECRET.fullmatch(binding['provider_secret_arn']) or
            binding['job_version_id'] == 'NOT_PUBLISHED'):
        raise StateError('activation bundle requires exact published deployment bindings')
    controller_binding = {key: value for key, value in binding.items()
                          if key not in {'broker_version_arn', 'provider_secret_arn'}}
    controller = build_bundle(controller_binding, raw)
    config = controller['controller_config']
    common = {key: value for key, value in config.items()
              if key not in {'builder_version_arn', 'job_versions'}}
    activation = AutonomyActivation(**{**common,
        'starts_at': datetime.fromisoformat(common['starts_at']),
        'expires_at': datetime.fromisoformat(common['expires_at'])})
    activation.validate(now)
    pin = PinnedJobVersion(binding['job_version_id'], controller['job_object_sha256'])
    reader = _LocalVersionedObject(raw, pin.version_id)
    reader.activation_id = activation.activation_id
    document = json.loads(raw)
    state = TaskState(activation.factory_id, activation.task_id, 'IMPLEMENTATION',
                      document['state_version'], now, CONTROLLER_IDENTITY)
    job = VersionedS3AcceptanceJobSource(reader, activation,
        {'IMPLEMENTATION': pin}).load(activation.factory_id, activation.task_id, state)
    if 'NOT_PUBLISHED' in (job.receipt_versions.owner, job.receipt_versions.reviewer):
        raise StateError('activation bundle requires published receipt versions')
    plan = asdict(job.plan)
    plan['lease']['expires_at'] = job.plan.lease.expires_at.isoformat()
    plan['plan_digest'] = controller['receipt_plan_digest']
    # Reuse the publication validator: the decoder alone does not check current
    # receipt/lease expiry, accepted verdict or exact scope payload shape.
    prepare({key: value for key, value in controller_binding.items()
             if key != 'job_version_id'}, plan, asdict(job.receipt_versions),
            job.input_bytes, job.contract_bytes, now=now)
    allowance = load_autonomy_operating_allowance(root)
    if (activation.contract_digest != 'sha256:' + allowance.acceptance_contract_sha256 or
            job.contract_bytes != (root / 'factory/autonomy/acceptance-contract.json').read_bytes() or
            job.input_bytes != (root / 'factory/autonomy/acceptance-input.txt').read_bytes() or
            allowance.production_release_authorized or
            not allowance.pricing_observed_at <= now < activation.expires_at <= allowance.pricing_expires_at):
        raise StateError('activation bundle differs from exact contract, input or pricing window')
    builder = {**common, 'broker_version_arn': binding['broker_version_arn']}
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'))
    if len(encode(common)) > 2048 or len(encode(builder)) > 2048 or len(encode(config)) > 3500:
        raise StateError('activation configuration exceeds runtime size limit')
    blockers = list(allowance.pending_gates)
    if not allowance.permits_activation(activation):
        blockers.append('operating_contract_not_active')
    else:
        # Exercise the actual deployment parsers without creating clients or
        # invoking a handler. The broker uses the same common activation fields.
        _builder_activation(root, activation.source_commit, encode(builder), now)
        _controller_activation(root, activation.source_commit, encode(config), now)
    environments = {
        'broker': {'FACTORY_ACCEPTANCE_BROKER_ENABLED': 'false',
            'FACTORY_ACCEPTANCE_ACTIVATION_JSON': encode(common),
            'FACTORY_OPENAI_SECRET_ARN': binding['provider_secret_arn']},
        'builder': {'FACTORY_OPERATIONAL_EXECUTION_ENABLED': 'false',
            'FACTORY_ACCEPTANCE_ACTIVATION_JSON': encode(builder)},
        'controller': {'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false',
            'FACTORY_ACCEPTANCE_CONTROLLER_JSON': encode(config)},
    }
    if any(sum(len(k.encode()) + len(v.encode()) for k, v in env.items()) > 4096
           for env in environments.values()):
        raise StateError('activation environment exceeds Lambda size limit')
    return {'status': 'PREPARED_DISABLED_NOT_DEPLOYED',
        'source_commit': activation.source_commit, 'activation_id': activation.activation_id,
        'environment_updates': environments, 'controller_policy': controller['policy'],
        'job_object_sha256': pin.sha256, 'receipt_plan_digest': plan['plan_digest'],
        'contract_blockers': sorted(blockers), 'live_verification_required': [
            'published_job_and_receipt_versions', 'owner_and_reviewer_signatures',
            'current_task_state_and_unused_activation_budget',
            'exact_deployed_artifacts_and_role_versions', 'least_privilege_iam',
            'disabled_schedule_and_no_retry_target'],
        'model_calls_authorized': 0, 'activation_authorized': False,
        'secret_values_read': False}


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: prepare_acceptance_activation_bundle.py BINDING.json JOB.json OUT.json')
    result = build_activation_bundle(json.loads(Path(sys.argv[1]).read_text()),
        Path(sys.argv[2]).read_bytes(), now=datetime.now(timezone.utc))
    # Exclusive creation prevents a failed or repeated preparation overwriting
    # the artifact a reviewer may already be inspecting.
    with Path(sys.argv[3]).open('x', encoding='utf-8', newline='\n') as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in
        ('status', 'source_commit', 'contract_blockers', 'model_calls_authorized')}))


if __name__ == '__main__':
    main()
