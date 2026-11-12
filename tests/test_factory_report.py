import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('factory_report', ROOT/'scripts'/'factory_report.py')
report = importlib.util.module_from_spec(spec); spec.loader.exec_module(report)


def summary(attempt, status, cost='0', uncertain='0', stages=None, result=None, **outcome):
    return {'attempt_id': attempt, 'outcome': {'status': status, 'result': result or {}, **outcome},
            'stages': stages or {}, 'total_cost_usd': cost, 'uncertain_max_usd': uncertain}


class FactoryReportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.results = self.root/'dev-results'; self.results.mkdir()

    def write(self, data, name=None):
        (self.results/(name or f"{data['attempt_id']}.json")).write_text(json.dumps(data))

    def test_signatures_match_the_real_failures_seen(self):
        cases = {
            'approved': summary('ai-cover-ui-001', 'TICK_COMPLETED', '0.09'),
            'output_token_limit': summary('ai-cover-budget-002', 'NEEDS_RECONCILIATION', '0.14', '0.50',
                stages={'repair_builder': {'state': 'FAILED', 'failure_code': 'output_token_limit'}}),
            'input_too_large': summary('ai-cover-wiring-005', 'NEEDS_RECONCILIATION',
                result={'phase': 'BINDING', 'reason': 'implementation input exceeds byte limit'}),
            'binding': summary('ai-cover-budget-001', 'STOPPED', error_type='StateError'),
            'escalate': summary('ai-cover-wiring-001', 'STOPPED', '0.03',
                stages={'builder': {'state': 'COMPLETED', 'decision_type': 'escalate'}}),
            'rejected': summary('ai-cover-budget-003', 'REJECTED', '0.34',
                stages={'reviewer': {'verdict': 'REJECT'}, 'repair2_reviewer': {'verdict': 'REJECT'}}),
            'tests_failed': summary('pagination-002', 'REJECTED', '0.20', stages={'builder': {'state': 'COMPLETED'}}),
            'provider_uncertain': summary('search-001', 'NEEDS_RECONCILIATION', '0', '0.50',
                stages={'builder': {'state': 'FAILED', 'failure_code': 'protocol_failure'}}),
        }
        for expected, data in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(report.signature(data), expected)

    def test_report_totals_tasks_and_diagnoses(self):
        self.write(summary('ai-cover-budget-002', 'NEEDS_RECONCILIATION', '0.13784400', '0.50',
            stages={'repair_builder': {'state': 'FAILED', 'failure_code': 'output_token_limit'}}))
        self.write(summary('ai-cover-budget-004', 'TICK_COMPLETED', '0.12181600'))
        self.write(summary('pagination-001', 'REJECTED', '0.10'))
        self.write({'status': 'APPROVED'}, 'batch-20261103T000000Z.json')
        (self.results/'broken.json').write_text('{')
        lines = []
        data = report.write_report(self.root, out=lines.append)
        self.assertEqual((data['attempts'], data['approved'], data['spent_usd'], data['uncertain_usd']),
                         (3, 1, '0.35966000', '0.50'))
        self.assertEqual(data['tasks']['bonus-library-ai-cover-budget']['attempts'], 2)
        self.assertIn('bonus-library-pagination', data['tasks'])
        self.assertEqual(data['diagnoses'][0]['lesson'], 'L003')
        page = (self.results/'factory-report.html').read_text()
        self.assertIn('ai-cover-budget-002', page)
        self.assertIn('Factory report', lines[0])
        # A second run ignores its own output files.
        self.assertEqual(report.write_report(self.root, out=lines.append)['attempts'], 3)

    def test_html_escapes_untrusted_text(self):
        self.write(summary('<script>-001', 'REJECTED'))
        report.write_report(self.root, out=lambda line: None)
        self.assertNotIn('<script>', (self.results/'factory-report.html').read_text())

    def test_repair_drafts_for_each_unapproved_attempt(self):
        self.write(summary('ai-cover-budget-003', 'REJECTED', '0.34',
            stages={'reviewer': {'state': 'COMPLETED', 'verdict': 'REJECT',
                                 'findings': ['Reservation is not\nreleased on failure']},
                    'repair2_reviewer': {'state': 'COMPLETED', 'verdict': 'REJECT', 'findings': []}}))
        self.write(summary('library-layout-001', 'NEEDS_RECONCILIATION', '0', '0.75',
            stages={'builder': {'state': 'FAILED', 'failure_code': 'output_token_limit'}}))
        self.write(summary('library-page-001', 'TICK_COMPLETED', '0.06'))
        lines = []
        report.write_report(self.root, out=lines.append, highlight=['library-layout-001', 'library-page-001'])
        drafts = self.results/'repair-drafts'
        self.assertEqual(sorted(p.name for p in drafts.iterdir()),
                         ['ai-cover-budget-003.md', 'library-layout-001.md'])
        rejected = (drafts/'ai-cover-budget-003.md').read_text()
        self.assertIn('Cause: `rejected` (lesson L006)', rejected)
        self.assertIn('finding: Reservation is not released on failure', rejected)
        self.assertIn('Do not start a new paid attempt', rejected)
        layout = (drafts/'library-layout-001.md').read_text()
        self.assertIn('Task: `bonus-library-library-layout`', layout)
        self.assertIn('lesson A006', layout)
        self.assertIn('Stage builder: FAILED output_token_limit', layout)
        self.assertEqual([line for line in lines if line.startswith('Repair draft')],
                         [f"Repair draft for library-layout-001: {drafts/'library-layout-001.md'}"])

    def test_every_signature_has_a_proposal(self):
        self.assertEqual(set(report.PROPOSALS), set(report.DIAGNOSES) - {'approved'})

    def test_draft_text_is_bounded_and_single_line(self):
        long = 'x' * 5000
        data = summary('pagination-009', 'REJECTED', stages={'reviewer': {
            'state': 'COMPLETED', 'verdict': 'REJECT', 'findings': [long] * 50}})
        text = report.repair_draft(data, 'rejected', 'bonus-library-pagination')
        self.assertEqual(text.count('finding:'), report.DRAFT_LIMIT)
        self.assertLess(len(text), 20 * 450 + 3000)

    def test_unsafe_attempt_ids_get_no_draft_file(self):
        self.write(summary('../escape-001', 'REJECTED'), 'escape.json')
        report.write_report(self.root, out=lambda line: None)
        self.assertFalse((self.results/'repair-drafts').exists())


if __name__ == '__main__':
    unittest.main()
