"""Idea intake: a short approved idea becomes a task contract with generated tests.

An idea names the objective, requirements, the files the builder may change and
machine-verifiable acceptance criteria. ``draft`` compiles it into the same task
contract the hand-written tasks use, plus a Factory-owned node:test acceptance
file generated from the criteria, and returns it as ``PENDING_APPROVAL``.
Nothing enters the build loop until ``approve`` receives the owner's exact
phrase, which binds the contract digest; ``write_approved`` then writes the task.
The module makes no network request and calls no model.
"""
import json
from pathlib import Path
import re

from factory_state.scope import canonical
from .worker import digest

PENDING, APPROVED = 'PENDING_APPROVAL', 'APPROVED'
OWNER = 'tim_brydges'
TASK_ID = re.compile(r'[a-z0-9][a-z0-9-]{2,62}')
COMMIT = re.compile(r'[0-9a-f]{40}')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
PATH = re.compile(r'(src|tests|supabase)/[A-Za-z0-9_./\[\]()-]{1,200}')
# Test paths are interpolated into the fixed sandbox command: no shell metacharacters.
TEST_PATH = re.compile(r'tests/[A-Za-z0-9_./-]{1,200}\.test\.mjs')
IDENT = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]{0,63}')
CRITERIA = {'exports': {'module', 'names'},
            'returns': {'module', 'function', 'args', 'expect'},
            'source_contains': {'path', 'text'},
            'source_excludes': {'path', 'text'}}
IDEA_FIELDS = {'idea_id', 'repository', 'target_commit', 'source_manifest_digest', 'objective',
               'requirements', 'allowed_paths', 'builder_test', 'acceptance'}
OPTIONAL = {'regression_acceptance_tests', 'source_file_bytes', 'model', 'input_class', 'depends_on'}
REVIEWER = 'claude-opus-5-5'
QA = 'gemini-3.8-flash'
CONSTRAINTS = ['No schema migrations', 'No new services', 'No credential changes',
               'No production writes', 'No network calls']


def _path(value):
    if type(value) is not str or not PATH.fullmatch(value) or '..' in value.split('/') or '//' in value:
        raise ValueError('safe repository-relative path required')
    return value


def _text(value, limit):
    if type(value) is not str or not value.strip() or len(value) > limit:
        raise ValueError('bounded nonempty text required')
    return value


def validate_idea(idea):
    if type(idea) is not dict or not IDEA_FIELDS <= set(idea) <= IDEA_FIELDS | OPTIONAL:
        raise ValueError('idea must have exactly the documented fields')
    if not TASK_ID.fullmatch(idea['idea_id']) or not COMMIT.fullmatch(idea['target_commit']):
        raise ValueError('idea id and exact target commit required')
    if not DIGEST.fullmatch(idea['source_manifest_digest']) or idea['repository'] != 'timbrydges/bonus-library':
        raise ValueError('pinned source manifest for a known repository required')
    _text(idea['objective'], 300)
    if type(idea['requirements']) is not list or not 1 <= len(idea['requirements']) <= 20:
        raise ValueError('one to twenty requirements required')
    for item in idea['requirements']:
        _text(item, 1200)
    allowed = idea['allowed_paths']
    if type(allowed) is not list or not 1 <= len(allowed) <= 8 or len(set(allowed)) != len(allowed):
        raise ValueError('one to eight distinct allowed paths required')
    for path in allowed:
        if _path(path).startswith('tests/factory-acceptance/'):
            raise ValueError('the builder may never edit Factory-owned tests')
    builder_test = _path(idea['builder_test'])
    if not TEST_PATH.fullmatch(builder_test) or builder_test not in allowed:
        raise ValueError('builder test must be an allowed tests/*.test.mjs path')
    for path in idea.get('regression_acceptance_tests', []):
        if not TEST_PATH.fullmatch(_path(path)) or not path.startswith('tests/factory-acceptance/'):
            raise ValueError('regression tests must be existing Factory-owned tests')
    criteria = idea['acceptance']
    if type(criteria) is not list or not 1 <= len(criteria) <= 40:
        raise ValueError('one to forty acceptance criteria required')
    for criterion in criteria:
        kind = criterion.get('type') if type(criterion) is dict else None
        if kind not in CRITERIA or set(criterion) != CRITERIA[kind] | {'type'}:
            raise ValueError('unknown or malformed acceptance criterion')
        if kind in ('exports', 'returns'):
            module = _path(criterion['module'])
            # Plain TypeScript modules run under node --experimental-strip-types; no aliases or JSX.
            if module not in allowed or not module.startswith('src/lib/') or not module.endswith('.ts'):
                raise ValueError('behavior criteria must target an allowed src/lib/*.ts module')
            names = criterion['names'] if kind == 'exports' else [criterion['function']]
            if type(names) is not list or not names or any(type(n) is not str or not IDENT.fullmatch(n) for n in names):
                raise ValueError('exported names must be identifiers')
            if kind == 'returns':
                if type(criterion['args']) is not list:
                    raise ValueError('returns criterion needs an argument list')
                json.dumps(criterion['args']); json.dumps(criterion['expect'])
        else:
            if _path(criterion['path']) not in allowed:
                raise ValueError('source criteria must target an allowed path')
            _text(criterion['text'], 400)
    for dependency in idea.get('depends_on', []):
        if type(dependency) is not str or not TASK_ID.fullmatch(dependency):
            raise ValueError('dependencies must be task ids')
    return idea


def _module_url(module):
    return '../../' + module


def acceptance_test(task_id, criteria):
    """A deterministic node:test file; each criterion becomes one named test."""
    modules = sorted({c['module'] for c in criteria if c['type'] in ('exports', 'returns')})
    lines = [f'// Factory-owned acceptance tests for {task_id}, generated from its approved idea.',
             '// The builder must make these pass and cannot edit them.',
             "import assert from 'node:assert/strict';",
             "import { readFileSync } from 'node:fs';",
             "import test from 'node:test';"]
    aliases = {}
    for number, module in enumerate(modules):
        aliases[module] = f'm{number}'
        lines.append(f'import * as m{number} from {json.dumps(_module_url(module))};')
    lines += ['', "const source = (path) => readFileSync(new URL('../../' + path, import.meta.url), 'utf8');", '']
    for number, c in enumerate(criteria, 1):
        kind = c['type']
        if kind == 'exports':
            name = f"{c['module']} exports {', '.join(c['names'])}"
            body = [f"  assert.notEqual({aliases[c['module']]}[{json.dumps(n)}], undefined, {json.dumps(n)});"
                    for n in c['names']]
        elif kind == 'returns':
            call = f"{c['function']}({', '.join(json.dumps(a) for a in c['args'])})"
            name = f"{call} returns {json.dumps(c['expect'])}"
            body = [f"  assert.equal(typeof {aliases[c['module']]}.{c['function']}, 'function');",
                    f"  assert.deepEqual(await {aliases[c['module']]}.{c['function']}(...{json.dumps(c['args'])}), "
                    f"{json.dumps(c['expect'])});"]
        else:
            verb = 'contains' if kind == 'source_contains' else 'does not contain'
            name = f"{c['path']} {verb} {json.dumps(c['text'])}"
            check = 'ok' if kind == 'source_contains' else 'equal'
            expr = (f"source({json.dumps(c['path'])}).includes({json.dumps(c['text'])})")
            body = [f"  assert.{check}({expr}{', false' if check == 'equal' else ''});"]
        lines += [f"test({json.dumps(f'{number}. {name}'[:300])}, async () => {{", *body, '});', '']
    return '\n'.join(lines)


def check_paths(spec):
    """Builder and acceptance test paths of an approved generated contract, re-validated."""
    paths = [spec['builder_test_path'], *(t['path'] for t in spec['acceptance_tests']),
             *spec.get('regression_acceptance_tests', [])]
    if any(type(p) is not str or not TEST_PATH.fullmatch(p) or '..' in p.split('/') for p in paths):
        raise ValueError('unsafe test path in generated contract')
    return paths[0], tuple(paths[1:])


def acceptance_path(task_id):
    return f'tests/factory-acceptance/{task_id.removeprefix("bonus-library-")}.acceptance.test.mjs'


def draft(idea):
    """Compile an idea into a PENDING_APPROVAL intake record; never writes or executes."""
    validate_idea(idea)
    task_id = 'bonus-library-' + idea['idea_id'].removeprefix('bonus-library-')
    path = acceptance_path(task_id)
    task = {
        'schema_version': 1, 'task_id': task_id, 'repository': idea['repository'],
        'objective': idea['objective'], 'status': 'OFFLINE_PREPARATION',
        'provider_strategy': 'openai_builder_anthropic_inspector_google_qa',
        'deliverable': 'Reviewable pull request with passing tests; no merge or deployment.',
        'requirements': [*idea['requirements'],
            f"Write regression tests in {idea['builder_test']}; the Factory-owned tests in {path} must pass unchanged."],
        'acceptance_tests': [{'path': path, 'content': acceptance_test(task_id, idea['acceptance'])}],
        'acceptance_tests_note': 'Generated from the approved idea; run unchanged in the sandbox after the repository checks.',
        'regression_acceptance_tests': list(idea.get('regression_acceptance_tests', [])),
        'builder_test_path': idea['builder_test'],
        'constraints': list(CONSTRAINTS),
        'execution_authorized': False, 'spending_authorized': False,
        'signing_authorized': False, 'release_authorized': False,
        'target_commit': idea['target_commit'], 'source_manifest_digest': idea['source_manifest_digest'],
        'allowed_paths': list(idea['allowed_paths']),
        'source_file_bytes': dict(idea.get('source_file_bytes', {})),
        'reviewer_model': REVIEWER,
        'qa_model': QA,
        'intake_id': idea['idea_id'],
    }
    for key in ('model', 'input_class'):
        if key in idea:
            task[key] = idea[key]
    if idea.get('depends_on'):
        task['depends_on'] = list(idea['depends_on'])
    return {'kind': 'factory_task_intake_v1', 'status': PENDING, 'idea': idea, 'task': task,
            'contract_digest': contract_digest(task), 'approved_by': None}


def contract_digest(task):
    return digest(canonical(task))


def approval_phrase(record):
    return f"Approve task {record['task']['task_id']} {record['contract_digest'][7:19]}"


def approve(record, *, phrase, owner=OWNER):
    """PENDING_APPROVAL -> APPROVED only on the owner's exact phrase for this exact contract."""
    if (type(record) is not dict or record.get('status') != PENDING
            or record.get('contract_digest') != contract_digest(record.get('task'))):
        raise ValueError('only an unaltered pending intake can be approved')
    if owner != OWNER or phrase != approval_phrase(record):
        raise ValueError('the owner\'s exact approval phrase for this contract is required')
    return {**record, 'status': APPROVED, 'approved_by': owner}


def verify_approved(record, task):
    if (type(record) is not dict or record.get('status') != APPROVED or record.get('approved_by') != OWNER
            or record.get('contract_digest') != contract_digest(task)
            or contract_digest(record.get('task')) != record['contract_digest']):
        raise ValueError('generated task is not owner-approved in this exact form')
    return True


def write_approved(record, projects):
    """Write an approved task and its intake record; never overwrites an existing task."""
    verify_approved(record, record.get('task'))
    folder = Path(projects) / record['task']['task_id']
    folder.mkdir(exist_ok=False)
    (folder / 'task.json').write_text(json.dumps(record['task'], indent=2) + '\n')
    (folder / 'intake.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return folder
