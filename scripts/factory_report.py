"""Owner learning report and cost dashboard for local Factory attempts.

Reads the key-free summaries in <runner-root>/dev-results, groups attempts by
task, totals known and uncertain spend, and diagnoses every non-approved
attempt with a known failure signature: what happened, the remedy and the
lesson that prevents it. Unknown signatures are listed as lesson candidates;
lessons change only through owner-approved pull requests.

Self-repair drafts: for every attempt that was not approved, a Markdown draft
in dev-results/repair-drafts/ states the diagnosis, the evidence from the
attempt, the proposed contract or Factory change and a ready-to-use request
for the coding assistant. Drafts are proposals only: they change no file,
open no pull request and authorize nothing. Makes no network request, reads
no credential and calls no model.
"""
import argparse
from decimal import Decimal
import html
import json
from pathlib import Path
import re
import sys

ATTEMPT = re.compile(r'(?P<task>[a-z0-9-]+?)-(?P<number>\d{3})')

# (signature, what happened, remedy, lesson id)
DIAGNOSES = {
    'approved': ('Approved by the independent reviewer.', 'Publish and verify; owner merges.', None),
    'output_token_limit': ('The model ran out of output tokens before finishing a proposal.',
        'Counted at its cap; the batch continues. Keep repairs minimal.', 'L003'),
    'request_byte_limit': ('The provider request was larger than the approved cap; nothing was sent.',
        'Shrink the shown files; tests/test_task_fit.py must pass.', 'A001'),
    'input_too_large': ('The task input exceeded a Factory size limit before any model call.',
        'Shrink the shown files or quote signatures; tests/test_task_fit.py must pass.', 'A001'),
    'escalate': ('The builder refused to guess (usually missing context).',
        'Show the modules the new code imports, or quote exact signatures.', 'A002'),
    'rejected': ('The reviewer rejected every repair round.',
        'Check whether the findings demand behaviour the contract does not specify.', 'L006'),
    'tests_failed': ('Repository checks or acceptance tests failed after every repair.',
        'Read the test output tail; confirm the contract is satisfiable (mutation-check it).', 'A003'),
    'provider_uncertain': ('A provider call failed with an unknown outcome.',
        'Check OpenAI usage before any new attempt; never replay automatically.', None),
    'binding': ('The attempt stopped while binding its inputs, before any model call.',
        'Read the printed reason; fix the task or runner configuration.', None),
    'unknown': ('No known signature matched.', 'Inspect the summary; propose a new lesson by pull request.', None),
}
PROVIDER_UNCERTAIN = {'timeout', 'protocol_failure', 'response_byte_limit', 'response_incomplete',
                      'response_failure_details', 'model_mismatch', 'refusal'}


def task_of(attempt_id):
    match = ATTEMPT.fullmatch(attempt_id or '')
    if not match:
        return 'unknown'
    task = match.group('task')
    return task if task.startswith('bonus-library-') else 'bonus-library-' + task


def signature(summary):
    outcome = summary.get('outcome') or {}
    result = outcome.get('result') or {}
    status = outcome.get('status')
    stages = summary.get('stages') or {}
    if status == 'TICK_COMPLETED':
        return 'approved'
    codes = [e.get('failure_code') for e in stages.values() if e.get('state') == 'FAILED']
    codes.append(result.get('failure_code'))
    if 'output_token_limit' in codes:
        return 'output_token_limit'
    if 'request_byte_limit' in codes:
        return 'request_byte_limit'
    if any(code in PROVIDER_UNCERTAIN for code in codes):
        return 'provider_uncertain'
    reason = str(result.get('reason') or outcome.get('reason') or '')
    if 'exceeds byte limit' in reason:
        return 'input_too_large'
    if result.get('phase') == 'BINDING' or outcome.get('error_type'):
        return 'binding'
    if any(e.get('decision_type') == 'escalate' for e in stages.values()):
        return 'escalate'
    if status == 'REJECTED':
        verdicts = [e.get('verdict') for name, e in stages.items() if name.endswith('reviewer')]
        return 'rejected' if verdicts and verdicts[-1] == 'REJECT' else 'tests_failed'
    return 'unknown'


# Proposed change per signature: what to edit before the next attempt.
PROPOSALS = {
    'output_token_limit': [
        'Split the task: new files in one task, wiring into existing files in a follow-up task (lesson A006).',
        'Show fewer or smaller existing files; prefer anchored edits over full-file rewrites.'],
    'request_byte_limit': [
        'Lower source_file_bytes by quoting signatures instead of showing whole files (lesson A001).',
        'Run tests/test_task_fit.py; use input_class "large" only if the owner accepts the higher cap.'],
    'input_too_large': [
        'Lower source_file_bytes by quoting signatures instead of showing whole files (lesson A001).',
        'Run tests/test_task_fit.py; use input_class "large" only if the owner accepts the higher cap.'],
    'escalate': [
        'Quote the exact exported names and signatures the builder asked about in the requirements (lesson A002).',
        'Or add the imported module to the shown files if it fits the size limits.'],
    'rejected': [
        'Compare each reviewer finding with the contract: add a requirement where the contract was silent (lesson L006).',
        'If a finding asks for behaviour the owner does not want, state that explicitly in the requirements.'],
    'tests_failed': [
        'Reproduce the failing check locally against the pinned commit and a reference solution (lesson A003).',
        'Mutation-check the acceptance test: the reference passes and the current code fails.'],
    'provider_uncertain': [
        'Check OpenAI usage for this attempt before anything else; never replay automatically.',
        'Only after reconciliation, approve a new attempt with a new id.'],
    'binding': [
        'Fix the task or runner configuration named in the reason (pins, manifest, image, paths).',
        'Re-run the Factory checks (validate_registry, test_task_fit) before a new attempt.'],
    'unknown': [
        'Inspect the attempt summary and add a signature to scripts/factory_report.py.',
        'Propose a lesson in factory/lessons.json through an owner-approved pull request.'],
}
DRAFT_LIMIT = 20


def _line(value, limit=400):
    text = ' '.join(str(value).split())
    return text if len(text) <= limit else text[:limit-1] + '…'


def evidence_lines(summary):
    lines = []
    outcome = summary.get('outcome') or {}
    result = outcome.get('result') or {}
    lines.append(f"Outcome: {_line(outcome.get('status'))}")
    for key in ('phase', 'reason', 'failure_code'):
        if result.get(key):
            lines.append(f'Result {key}: {_line(result[key])}')
    if outcome.get('error_type'):
        lines.append(f"Error: {_line(outcome['error_type'])} {_line(outcome.get('reason') or '')}".rstrip())
    for name, stage in (summary.get('stages') or {}).items():
        parts = [stage.get(k) for k in ('state', 'decision_type', 'verdict', 'failure_code') if stage.get(k)]
        lines.append(f"Stage {_line(name, 60)}: {_line(' '.join(map(str, parts)), 120)}")
        if stage.get('summary'):
            lines.append(f"  {_line(name, 60)} said: {_line(stage['summary'])}")
        for finding in (stage.get('findings') or [])[:DRAFT_LIMIT]:
            lines.append(f'  finding: {_line(finding)}')
    for name in ('tests', 'repair-tests', 'repair2-tests'):
        if summary.get(name):
            lines.append(f'Checks {name}: {_line(summary[name], 60)}')
    return lines


def repair_draft(summary, sig, task):
    what, remedy, lesson = DIAGNOSES[sig]
    attempt = summary['attempt_id']
    evidence = '\n'.join(f'- {line}' for line in evidence_lines(summary))
    proposals = '\n'.join(f'{n}. {text}' for n, text in enumerate(PROPOSALS.get(sig, PROPOSALS['unknown']), 1))
    return f"""# Repair draft: {attempt}

Proposal only. It changes nothing; any fix lands through an owner-approved pull request.

- Task: `{task}`
- Cause: `{sig}`{f' (lesson {lesson})' if lesson else ''}
- What happened: {what}
- Remedy: {remedy}
- Cost: US${summary.get('total_cost_usd') or '0'} (+ up to US${summary.get('uncertain_max_usd') or '0'} for failed calls)

## Evidence

{evidence}

## Proposed change

{proposals}

## Request for the coding assistant

Attempt `{attempt}` of task `{task}` stopped with cause `{sig}`. Using the evidence above and
dev-results/{attempt}.json, prepare the smallest Factory or task-contract change that addresses it,
verify it offline, and open a pull request for the owner. Do not start a new paid attempt.
"""


def write_drafts(results, attempts, summaries):
    folder = results/'repair-drafts'
    written = {}
    for item in attempts:
        if item['signature'] == 'approved' or not ATTEMPT.fullmatch(item['attempt_id']):
            continue
        folder.mkdir(exist_ok=True)
        path = folder/f"{item['attempt_id']}.md"
        path.write_text(repair_draft(summaries[item['attempt_id']], item['signature'], item['task']),
                        encoding='utf-8')
        written[item['attempt_id']] = path
    return written


def build_report(results_dir, summaries=None):
    tasks, attempts = {}, []
    spent, uncertain = Decimal(0), Decimal(0)
    for path in sorted(Path(results_dir).glob('*.json')):
        if path.name.startswith('batch-') or path.name == 'factory-report.json':
            continue
        try:
            summary = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if type(summary) is not dict or 'attempt_id' not in summary:
            continue
        if summaries is not None:
            summaries[summary['attempt_id']] = summary
        cost = Decimal(str(summary.get('total_cost_usd') or '0'))
        risk = Decimal(str(summary.get('uncertain_max_usd') or '0'))
        sig = signature(summary)
        task = task_of(summary['attempt_id'])
        spent += cost
        uncertain += risk
        entry = tasks.setdefault(task, {'attempts': 0, 'approved': 0, 'cost_usd': Decimal(0),
                                        'uncertain_usd': Decimal(0)})
        entry['attempts'] += 1
        entry['approved'] += sig == 'approved'
        entry['cost_usd'] += cost
        entry['uncertain_usd'] += risk
        what, remedy, lesson = DIAGNOSES[sig]
        attempts.append({'attempt_id': summary['attempt_id'], 'task': task, 'signature': sig,
                         'cost_usd': str(cost), 'uncertain_usd': str(risk), 'what': what,
                         'remedy': remedy, 'lesson': lesson})
    counts = {}
    for item in attempts:
        if item['signature'] != 'approved':
            counts[item['signature']] = counts.get(item['signature'], 0) + 1
    approved = sum(t['approved'] for t in tasks.values())
    return {'attempts': len(attempts), 'approved': approved,
            'first_attempt_rate': f'{approved}/{len(attempts)}' if attempts else '0/0',
            'spent_usd': str(spent), 'uncertain_usd': str(uncertain),
            'tasks': {k: {**v, 'cost_usd': str(v['cost_usd']), 'uncertain_usd': str(v['uncertain_usd'])}
                      for k, v in sorted(tasks.items())},
            'failure_signatures': dict(sorted(counts.items(), key=lambda kv: -kv[1])),
            'lesson_candidates': [a['attempt_id'] for a in attempts if a['signature'] == 'unknown'],
            'diagnoses': [a for a in attempts if a['signature'] != 'approved']}


def render_html(report):
    e = lambda value: html.escape(str(value))
    rows = ''.join(f"<tr><td>{e(k)}</td><td>{v['attempts']}</td><td>{v['approved']}</td>"
                   f"<td>${e(v['cost_usd'])}</td><td>${e(v['uncertain_usd'])}</td></tr>"
                   for k, v in report['tasks'].items())
    diag = ''.join(f"<tr><td>{e(d['attempt_id'])}</td><td>{e(d['signature'])}</td><td>{e(d['what'])}</td>"
                   f"<td>{e(d['remedy'])}</td><td>{e(d['lesson'] or '')}</td></tr>" for d in report['diagnoses'])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Factory report</title>
<style>body{{font-family:system-ui,sans-serif;margin:16px;background:#fff;color:#111}}
table{{border-collapse:collapse;width:100%;margin:12px 0}}td,th{{border:1px solid #ccc;padding:6px;text-align:left;font-size:14px}}
.k{{display:inline-block;margin-right:24px}}.k b{{font-size:22px;display:block}}</style></head><body>
<h1>Factory report</h1>
<div class="k">Spent<b>${e(report['spent_usd'])}</b></div>
<div class="k">Possible extra (failed calls)<b>${e(report['uncertain_usd'])}</b></div>
<div class="k">Approved / attempts<b>{e(report['first_attempt_rate'])}</b></div>
<h2>By task</h2><table><tr><th>Task</th><th>Attempts</th><th>Approved</th><th>Cost</th><th>Possible extra</th></tr>{rows}</table>
<h2>What went wrong and the fix</h2><table><tr><th>Attempt</th><th>Cause</th><th>What happened</th><th>Remedy</th><th>Lesson</th></tr>{diag}</table>
<p>Lessons change only through owner-approved pull requests (factory/lessons.json).</p></body></html>"""


def write_report(runner_root, out=print, highlight=()):
    results = Path(runner_root)/'dev-results'
    summaries = {}
    report = build_report(results, summaries)
    drafts = write_drafts(results, report['diagnoses'], summaries)
    (results/'factory-report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (results/'factory-report.html').write_text(render_html(report), encoding='utf-8')
    out(f"Factory report: {report['attempts']} attempts, {report['approved']} approved, "
        f"spent US${report['spent_usd']} (+ up to US${report['uncertain_usd']} uncertain). "
        f"Open {results/'factory-report.html'}")
    for attempt in highlight:
        if attempt in drafts:
            out(f'Repair draft for {attempt}: {drafts[attempt]}')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner-root', default=r'C:\FactoryRunner')
    args = parser.parse_args(argv)
    report = write_report(args.runner_root)
    for d in report['diagnoses'][-5:]:
        print(f"  {d['attempt_id']}: {d['signature']} - {d['remedy']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
