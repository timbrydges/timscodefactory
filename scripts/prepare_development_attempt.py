"""Owner-run preparation of one pinned private-source development attempt.

Writes pins, approval, pricing and contract files into a fresh directory outside
the Factory checkout. It makes no network request, reads no credential and
calls no model. Running it records the owner's approval; it does not execute.
"""
import argparse
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.worker import digest

TASK = ROOT/'factory'/'projects'/'bonus-library-pagination'/'task.json'
FIXED = dict(model_id='gpt-5.6-sol', credential_source='env:FACTORY_OPENAI_API_KEY',
             builder_cap='0.25', reviewer_cap='0.25', total_cap='0.50',
             max_request_bytes=42020, max_output_tokens=4096)
IMAGE = re.compile(r'[^\s@]+@sha256:[0-9a-f]{64}')
ATTEMPT = re.compile(r'[a-z0-9][a-z0-9-]{0,62}')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def _price(value):
    try:
        price = Decimal(value)
    except InvalidOperation:
        raise ValueError('decimal price required') from None
    if not price.is_finite() or not Decimal('0') < price <= Decimal('1000'):
        raise ValueError('bounded positive price required')
    return str(price)


def prepare(*, output, attempt_id, image_ref, source_config_sha256, manifest,
            input_price, output_price, pricing_source, now, hours, source_commit):
    if not ATTEMPT.fullmatch(attempt_id) or not IMAGE.fullmatch(image_ref):
        raise ValueError('exact attempt id and digest-pinned image required')
    if not DIGEST.fullmatch(source_config_sha256) or not DIGEST.fullmatch(manifest):
        raise ValueError('exact source config and manifest digests required')
    if type(hours) is not int or not 1 <= hours <= 24:
        raise ValueError('approval lifetime must be 1 to 24 hours')
    if not isinstance(pricing_source, str) or not 1 <= len(pricing_source) <= 128:
        raise ValueError('bounded pricing source required')
    output = Path(output)
    if not output.is_absolute() or ROOT.resolve() in (output.resolve(), *output.resolve().parents):
        raise ValueError('absolute output directory outside the Factory checkout required')
    contract = TASK.read_bytes()
    spec = json.loads(contract)
    pins = dict(FIXED, source_commit=source_commit, contract_digest=digest(contract),
                repository=spec['repository'], target_commit=spec['target_commit'],
                image_ref=image_ref, attempt_id=attempt_id,
                source_config_digest=source_config_sha256, source_manifest_digest=manifest)
    pricing = dict(model_id=FIXED['model_id'], input_usd_per_million_tokens=_price(input_price),
                   output_usd_per_million_tokens=_price(output_price),
                   effective_at=now.isoformat(), expires_at=(now+timedelta(hours=24)).isoformat(),
                   source_id=pricing_source)
    approval = dict(pins=pins, expires_at=(now+timedelta(hours=hours)).isoformat())
    output.mkdir(exist_ok=False)
    files = dict(pins=pins, approval=approval, pricing=pricing)
    for name, value in files.items():
        (output/f'{name}.json').write_text(json.dumps(value, sort_keys=True, indent=2))
    (output/'contract.json').write_bytes(contract)
    return dict(status='PREPARED', output=str(output), attempt_id=attempt_id,
                approval_expires_at=approval['expires_at'], total_cap_usd=FIXED['total_cap'],
                contract_digest=pins['contract_digest'], source_commit=source_commit,
                model_calls=0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-authorized', action='store_true')
    for name in ('output', 'attempt-id', 'image-ref', 'source-config-sha256', 'manifest',
                 'input-price', 'output-price', 'pricing-source'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--hours', type=int, default=12)
    args = parser.parse_args(argv)
    if not args.owner_authorized:
        parser.error('explicit owner authorization required')
    head = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    if subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain'], text=True):
        raise ValueError('clean Factory checkout required')
    print(json.dumps(prepare(output=args.output, attempt_id=args.attempt_id,
        image_ref=args.image_ref, source_config_sha256=args.source_config_sha256,
        manifest=args.manifest, input_price=args.input_price, output_price=args.output_price,
        pricing_source=args.pricing_source, now=datetime.now(timezone.utc),
        hours=args.hours, source_commit=head)))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as error:
        print(json.dumps({'status': 'STOPPED', 'error_type': type(error).__name__,
                          'error': str(error)[:200]}))
        raise SystemExit(1)
