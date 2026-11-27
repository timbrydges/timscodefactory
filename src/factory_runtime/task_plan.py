"""Feature planning: split ideas into budget-sized tasks and order them safely.

A feature is a list of ideas (``task_intake`` format, without the per-attempt
source pins, which are only known once earlier tasks have merged). ``plan``:

1. Estimates each idea's largest provider request (the review packet, which is
   the binding one) with the same calibrated formula as ``tests/test_task_fit``,
   and picks the standard or large input class.
2. Splits an idea that fits neither class into parts along its files: new
   ``src/lib`` modules first, existing files (wiring) after, each part with its own
   builder test and the criteria that target its files. A part depends on the
   part before it, because later files may import earlier ones.
3. Orders all tasks topologically. Tasks that change the same file are also
   sequenced, in feature order, so two attempts never edit one file at once.
   Unknown dependencies and cycles fail closed.

``next_ready`` returns the tasks whose dependencies have all merged, pinned to
the given main commit and manifest, ready for ``task_intake.draft``. No network
request, model call or file write happens here.
"""
import copy
import json

from . import openai_provider as op
from .task_intake import TASK_ID, validate_idea

LIMITS = {'standard': 42020, 'large': 96000}
# Same calibration as tests/test_task_fit.py (review packet estimate).
GROWTH, NEW_FILE, ESCAPING, OVERHEAD, SLACK = 2.3, 4000, 0.13, 2000, 1.08
PIN_FIELDS = ('target_commit', 'source_manifest_digest')
PLACEHOLDER = {'target_commit': '0' * 40, 'source_manifest_digest': 'sha256:' + '0' * 64}


class PlanError(ValueError):
    """The feature cannot be planned without a human decision."""


def estimated_request_bytes(idea):
    sizes = idea.get('source_file_bytes', {})
    changed = sum(sizes.get(p, 0) * GROWTH + (0 if p in sizes else NEW_FILE) for p in idea['allowed_paths'])
    spec = len(json.dumps(idea, separators=(',', ':'))) + 1500 * len(idea['acceptance'])
    return int((spec + changed * (1 + ESCAPING) + OVERHEAD) * SLACK + len(op._instructions('task_review'))
               + len(json.dumps(op._decision_schema('task_review'))))


def input_class(idea):
    size = estimated_request_bytes(idea)
    for name in ('standard', 'large'):
        if size <= LIMITS[name]:
            return name
    return None


def _targets(criterion):
    return criterion.get('module') or criterion.get('path')


def split(idea):
    """Parts of one idea, each fitting a class; raises PlanError when no split fits."""
    if input_class(idea):
        return [dict(idea, input_class=input_class(idea))]
    sizes = idea.get('source_file_bytes', {})
    files = [p for p in idea['allowed_paths'] if p != idea['builder_test']]
    # New library modules first, then existing files from smallest; wiring comes last.
    files.sort(key=lambda p: (p in sizes, not p.startswith('src/lib/'), sizes.get(p, 0), p))
    def make(group, number, *, strict=True):
        test = idea['builder_test'].removesuffix('.test.mjs') + f'-part{number}.test.mjs'
        criteria = [c for c in idea['acceptance'] if _targets(c) in group]
        if strict and not criteria:
            raise PlanError(f'no acceptance criterion targets {", ".join(group)}; add one before splitting')
        part = dict(copy.deepcopy(idea), idea_id=f"{idea['idea_id']}-part{number}",
                    allowed_paths=[*group, test], builder_test=test, acceptance=criteria,
                    source_file_bytes={p: n for p, n in sizes.items() if p in group})
        part['objective'] = f"{idea['objective'][:270]} (part {number})"
        return part
    groups, current = [], []
    for path in files:
        # Greedy: grow the part until one more file would no longer fit the large class.
        if current and input_class(make(current + [path], len(groups) + 1, strict=False)) is None:
            groups.append(current)
            current = []
        current.append(path)
    groups.append(current)
    parts = [make(group, number) for number, group in enumerate(groups, 1)]
    for number, part in enumerate(parts):
        size_class = input_class(part)
        if size_class is None:
            raise PlanError(f"{part['allowed_paths'][0]} alone is too large for one attempt")
        part['input_class'] = size_class
        deps = set(idea.get('depends_on', []))
        if number:
            deps.add(parts[number - 1]['idea_id'])
        if deps:
            part['depends_on'] = sorted(deps)
    # A dependency on the whole idea means a dependency on its last part.
    return parts


def order(ideas):
    """Deterministic topological order; same-file tasks run in feature order."""
    ids = [i['idea_id'] for i in ideas]
    if len(set(ids)) != len(ids):
        raise PlanError('duplicate task ids')
    deps = {i['idea_id']: set(i.get('depends_on', [])) for i in ideas}
    for task_id, needed in deps.items():
        unknown = needed - set(ids)
        if unknown:
            raise PlanError(f'{task_id} depends on unknown task {sorted(unknown)[0]}')
    position = {task_id: n for n, task_id in enumerate(ids)}
    owners = {}
    for idea in ideas:
        for path in idea['allowed_paths']:
            for earlier in owners.get(path, []):
                deps[idea['idea_id']].add(earlier)
            owners.setdefault(path, []).append(idea['idea_id'])
    ordered, done = [], set()
    while len(ordered) < len(ids):
        ready = sorted((t for t in ids if t not in done and deps[t] <= done), key=position.get)
        if not ready:
            raise PlanError('dependency cycle: ' + ', '.join(sorted(set(ids) - done)))
        ordered.append(ready[0])
        done.add(ready[0])
    return ordered, {t: sorted(d, key=position.get) for t, d in deps.items()}


def plan(feature):
    """Split and order a feature's ideas; returns the plan without pins or side effects."""
    if type(feature) is not dict or set(feature) != {'feature_id', 'repository', 'ideas'}:
        raise PlanError('feature needs feature_id, repository and ideas')
    if not TASK_ID.fullmatch(feature['feature_id']) or not 1 <= len(feature['ideas']) <= 20:
        raise PlanError('feature id and one to twenty ideas required')
    tasks, last_part = [], {}
    for raw in feature['ideas']:
        idea = dict(copy.deepcopy(raw), repository=feature['repository'], **PLACEHOLDER)
        validate_idea(idea)  # Same schema as intake; pins are filled in later.
        parts = split(idea)
        last_part[idea['idea_id']] = parts[-1]['idea_id']
        tasks.extend(parts)
    for task in tasks:
        if 'depends_on' in task:
            task['depends_on'] = sorted({last_part.get(d, d) for d in task['depends_on']})
    sequence, deps = order(tasks)
    by_id = {t['idea_id']: t for t in tasks}
    for task_id in sequence:
        if deps[task_id]:
            by_id[task_id]['depends_on'] = deps[task_id]
        for field in PIN_FIELDS:
            by_id[task_id].pop(field)
    return {'feature_id': feature['feature_id'], 'repository': feature['repository'],
            'order': sequence, 'tasks': [by_id[t] for t in sequence]}


def next_ready(feature_plan, *, merged, main_commit, manifest_digest):
    """Unmerged tasks whose dependencies have all merged, pinned to the current main."""
    merged = set(merged)
    ready = []
    for task in feature_plan['tasks']:
        if task['idea_id'] in merged or not set(task.get('depends_on', [])) <= merged:
            continue
        idea = dict(copy.deepcopy(task), repository=feature_plan['repository'],
                    target_commit=main_commit, source_manifest_digest=manifest_digest)
        ready.append(validate_idea(idea))
    return ready
