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
from factory_runtime import approved_models

PROJECTS = ROOT/'factory'/'projects'
LESSONS = ROOT/'factory'/'lessons.json'
LESSON_AUDIENCES = ('builder', 'reviewer')
TASK = PROJECTS/'bonus-library-pagination'/'task.json'
TASK_NAME = re.compile(r'bonus-library-[a-z0-9-]{1,40}')


def contract_with_lessons(task_bytes, lessons_path=LESSONS):
    """Add reviewed builder/reviewer lessons to the pinned contract; the digest covers them."""
    spec = json.loads(task_bytes)
    lessons = json.loads(Path(lessons_path).read_bytes())
    if lessons.get('schema') != 1 or type(lessons.get('lessons')) is not list:
        raise ValueError('reviewed lessons file required')
    selected = []
    for lesson in lessons['lessons']:
        if (type(lesson) is not dict or type(lesson.get('id')) is not str
                or type(lesson.get('text')) is not str or not 1 <= len(lesson['text']) <= 400
                or type(lesson.get('audience')) is not list):
            raise ValueError('invalid lesson')
        if any(a in LESSON_AUDIENCES for a in lesson['audience']):
            selected.append(f"{lesson['id']} ({'/'.join(lesson['audience'])}): {lesson['text']}")
    if 'factory_lessons' in spec or len(selected) > 30:
        raise ValueError('bounded lessons required')
    spec['factory_lessons'] = selected
    return (json.dumps(spec, indent=2) + '\n').encode('utf-8')


def task_path(name):
    if not TASK_NAME.fullmatch(name) or not (PROJECTS/name/'task.json').is_file():
        raise ValueError('known Factory task name required')
    return PROJECTS/name/'task.json'
FIXED = dict(model_id='gpt-5.6-sol', credential_source='env:FACTORY_OPENAI_API_KEY',
             builder_cap='0.50', reviewer_cap='0.25',
             # Builder worst case: 42020 B x $4/M + 16384 x $20/M = $0.4958 <= $0.50.
             # The reviewer is clamped to 4096 output tokens by the host ($0.25).
             max_request_bytes=42020, max_output_tokens=16384)
# Owner-approved large-task class: more context per request, with caps scaled to match.
# Builder worst case: 96000 B x $4/M + 16384 x $20/M = $0.7117 <= $0.75.
# Reviewer (clamped to 4096 output tokens): $0.384 + $0.0819 = $0.466 <= $0.50.
LARGE = dict(builder_cap='0.75', reviewer_cap='0.50', max_request_bytes=96000)


def limits_for(spec):
    size = spec.get('input_class', 'standard')
    if size not in ('standard', 'large'):
        raise ValueError('input_class must be standard or large')
    # Caps stay sized for the price ceiling; a cheaper approved model only lowers real spend.
    model_id, _ = approved_models.resolve(spec)
    return dict(FIXED, **(LARGE if size == 'large' else {}), model_id=model_id)


def attempt_cap(spec, repair_rounds):
    limits = limits_for(spec)
    return (Decimal(limits['builder_cap']) + Decimal(limits['reviewer_cap'])) * (1 + repair_rounds)


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


def prepare(*, output, attempt_id, image_ref, source_config_sha256, manifest=None,
            input_price, output_price, pricing_source, now, hours, source_commit,
            repair_rounds=2, task=TASK):
    if not ATTEMPT.fullmatch(attempt_id) or not IMAGE.fullmatch(image_ref):
        raise ValueError('exact attempt id and digest-pinned image required')
    contract = contract_with_lessons(Path(task).read_bytes())
    spec = json.loads(contract)
    # The task contract pins its expected source content; a caller may only restate it.
    pinned = spec.get('source_manifest_digest')
    if manifest is None:
        manifest = pinned
    if pinned is not None and manifest != pinned:
        raise ValueError('manifest differs from the task contract pin')
    if (type(manifest) is not str or not DIGEST.fullmatch(source_config_sha256)
            or not DIGEST.fullmatch(manifest)):
        raise ValueError('exact source config and manifest digests required')
    if type(repair_rounds) is not int or repair_rounds not in (0, 1, 2):
        raise ValueError('repair rounds must be 0, 1 or 2')
    if type(hours) is not int or not 1 <= hours <= 24:
        raise ValueError('approval lifetime must be 1 to 24 hours')
    if not isinstance(pricing_source, str) or not 1 <= len(pricing_source) <= 128:
        raise ValueError('bounded pricing source required')
    output = Path(output)
    if not output.is_absolute() or ROOT.resolve() in (output.resolve(), *output.resolve().parents):
        raise ValueError('absolute output directory outside the Factory checkout required')
    # Each round may spend both stage caps: 0.75 per round.
    limits = limits_for(spec)
    total = str(attempt_cap(spec, repair_rounds))
    pins = dict(limits, total_cap=total, source_commit=source_commit, contract_digest=digest(contract),
                repository=spec['repository'], target_commit=spec['target_commit'],
                image_ref=image_ref, attempt_id=attempt_id,
                source_config_digest=source_config_sha256, source_manifest_digest=manifest,
                **({'repair_rounds': repair_rounds} if repair_rounds else {}))
    _, ceiling = approved_models.resolve(spec)
    if Decimal(_price(input_price)) > ceiling['input'] or Decimal(_price(output_price)) > ceiling['output']:
        raise ValueError('price exceeds the approved maximum for this model')
    pricing = dict(model_id=limits['model_id'], input_usd_per_million_tokens=_price(input_price),
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
                approval_expires_at=approval['expires_at'], total_cap_usd=total,
                repair_rounds=repair_rounds,
                contract_digest=pins['contract_digest'], source_commit=source_commit,
                model_calls=0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-authorized', action='store_true')
    for name in ('output', 'attempt-id', 'image-ref', 'source-config-sha256',
                 'input-price', 'output-price', 'pricing-source'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--manifest')
    parser.add_argument('--task', default='bonus-library-pagination')
    parser.add_argument('--hours', type=int, default=12)
    parser.add_argument('--repair-rounds', type=int, choices=(0, 1, 2), default=2)
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
        hours=args.hours, source_commit=head, repair_rounds=args.repair_rounds,
        task=task_path(args.task))))
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
