"""Operator-only one-attempt entrypoint. Defaults to disabled, never a scheduler.

Approval/pin files are operator inputs, not a signature or an authorization
service. Do not expose this CLI to queue payloads, model output or a public API.
"""
import argparse
import asyncio
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.development_composition import compose_bonus_host, compose_task_host
from factory_runtime.openai_provider import ProviderPricingQuote
from factory_runtime.development_profile import read_execution_profile
from factory_runtime.repository_snapshot import read_repository_snapshot
from factory_runtime.private_source import SourceBinding
from factory_runtime import private_source_composition as private_source
from factory_runtime.task_queue import QueuedTask
from factory_runtime.worker import digest
from factory_runtime.workload_identity_response import RenewableCredentialBinding
from factory_runtime.github_identity_bootstrap import binding_from_configuration


class PinnedPricing:
    def __init__(self, data):
        self.value = ProviderPricingQuote(model_id=data['model_id'],
            input_usd_per_million_tokens=Decimal(data['input_usd_per_million_tokens']),
            output_usd_per_million_tokens=Decimal(data['output_usd_per_million_tokens']),
            effective_at=datetime.fromisoformat(data['effective_at']),
            expires_at=datetime.fromisoformat(data['expires_at']), source_id=data['source_id'])

    async def quote(self, *, target):
        return self.value  # Adapter enforces model, age, expiry and worst-case cost.


def report_result(result):
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status') == 'TICK_COMPLETED' else 1


def main(argv=None, *, credential_binding=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-approved-once', action='store_true')
    parser.add_argument('--owner-authorized', action='store_true')
    for name in ('pins', 'approval', 'pricing', 'contract', 'repository-path', 'attempt-directory'):
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--execution-profile', type=Path)
    parser.add_argument('--identity-config', type=Path)
    parser.add_argument('--identity-config-sha256')
    parser.add_argument('--source-config', type=Path)
    parser.add_argument('--source-config-sha256')
    args = parser.parse_args(argv)
    if not args.execute_approved_once:
        print(json.dumps({'status': 'DISABLED', 'credential_read': False, 'model_calls': 0}))
        return 0
    if not args.owner_authorized or any(getattr(args, name) is None for name in
            ('pins', 'approval', 'pricing', 'contract', 'attempt_directory')):
        parser.error('explicit owner authorization and all pinned inputs required')
    if ((args.repository_path is None) == (args.source_config is None)
            or (args.source_config is None) != (args.source_config_sha256 is None)):
        parser.error('exactly one source: --repository-path or a hash-pinned --source-config')
    if args.identity_config is not None or args.identity_config_sha256 is not None:
        if credential_binding is not None or args.identity_config is None or args.identity_config_sha256 is None:
            parser.error('one complete operator identity binding required')
        credential_binding = binding_from_configuration(args.identity_config, args.identity_config_sha256,
            clock=lambda:datetime.now(timezone.utc), owner_authorized=True, enabled=True)
    return report_result(asyncio.run(execute(args, credential_binding=credential_binding)))


async def execute(args, *, credential_binding=None):
    """Fixed scheduler integration; retains the same owner/pin gates."""
    if args.owner_authorized is not True:
        raise ValueError('explicit owner authorization required')
    pins = json.loads(args.pins.read_bytes())
    approval = json.loads(args.approval.read_bytes())
    # Supplied only by the trusted host, never reconstructed from packet fields.
    if credential_binding is not None:
        if (type(credential_binding) is not RenewableCredentialBinding
                or args.execution_profile is None
                or pins.get('credential_source') != credential_binding.source_pin):
            raise ValueError('trusted renewable credential binding differs from pinned inputs')
    elif pins.get('credential_source') != 'env:FACTORY_OPENAI_API_KEY':
        raise ValueError('explicit renewable credential binding required')
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True)
    if head != pins['source_commit'] or dirty or args.attempt_directory.name != pins['attempt_id']:
        raise ValueError('clean exact source and fresh named attempt directory required')
    raw = args.contract.read_bytes()
    if len(raw) > 65536 or digest(raw) != pins['contract_digest']:
        raise ValueError('contract differs from approved digest')
    spec = json.loads(raw)
    source_config = getattr(args, 'source_config', None)
    if (getattr(args, 'repository_path', None) is None) == (source_config is None):
        raise ValueError('exactly one source required')
    if source_config is None:
        snapshot = read_repository_snapshot(args.repository_path,
            repository=pins['repository'], commit=pins['target_commit'])
    else:
        # The approved pins, not the CLI, select the config and expected content.
        if (args.source_config_sha256 != pins.get('source_config_digest')
                or 'source_manifest_digest' not in pins):
            raise ValueError('private source must match approved pins')
        source = private_source.read_private_source_configuration(
            source_config, args.source_config_sha256, owner_authorized=True)
        if pins['repository'] != source.repository:
            raise ValueError('private source must match approved pins')
        source_binding = SourceBinding(pins['repository'], source.repository_id,
                                       pins['target_commit'], pins['source_manifest_digest'])
        source_binding.validate()
        snapshot = None
    task = QueuedTask(pins['attempt_id'], 'development-local', spec['task_id'],
        pins['attempt_id'], head, digest(raw), 'IMPLEMENTATION')
    profile = None
    if args.execution_profile is not None:
        with args.execution_profile.open('rb') as handle:
            profile = read_execution_profile(handle.read(16385))
        profile.validate_binding(pins=pins,
            task=task,
            contract_bytes=raw)
    elif 'execution_profile_digest' in pins:
        raise ValueError('approved execution profile file required')
    # Inspect only: never pull an image or provision dependencies.
    subprocess.run(['docker', 'image', 'inspect', pins['image_ref']], check=True,
                   capture_output=True, timeout=15)
    if snapshot is None:
        # Last local check passed; one live, never-retried acquisition per attempt.
        snapshot = private_source.acquire_private_source(source, source_binding, pins['attempt_id'],
            clock=lambda: datetime.now(timezone.utc), enabled=True, owner_authorized=True)
    composer = compose_task_host if profile is not None else compose_bonus_host
    host = composer(args.attempt_directory, approval=approval, expected_pins=pins,
        receipt_path=args.attempt_directory.with_name(args.attempt_directory.name+'.consumed.json'),
        task=task, contract_bytes=raw, snapshot=snapshot,
        pricing_source=PinnedPricing(json.loads(args.pricing.read_bytes())),
        clock=lambda: datetime.now(timezone.utc), owner_authorized=True,
        **({'profile': profile, 'credential_binding': credential_binding}
           if profile is not None else {}))
    return await host.tick()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Never print credential-bearing exception chains or raw provider bodies.
        print(json.dumps({'status': 'STOPPED', 'error_type': type(error).__name__}))
        raise SystemExit(1)
