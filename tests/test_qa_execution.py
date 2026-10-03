import copy
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.qa_execution import execute, verify_process
from factory_runtime.review_preparation import prepare
from factory_state.model import StateError


class IndependentQATests(unittest.TestCase):
    def test_pinned_program_passes_independent_cases_without_authority(self):
        report = execute(ROOT)
        self.assertEqual(report['status'], 'LOCAL_QA_PASSED_UNSIGNED')
        self.assertEqual(report['case_count'], 18)
        self.assertTrue(all(case['passed'] for case in report['cases']))
        self.assertFalse(report['gate_authority'])
        self.assertFalse(report['production_release_authorized'])

    def test_tampered_material_never_executes(self):
        packet = copy.deepcopy(prepare(ROOT, role='qa'))
        packet['untrusted_material']['files']['fingerprint.py'] = 'raise SystemExit(0)'
        with patch('factory_runtime.qa_execution.subprocess.run') as run:
            with self.assertRaises(StateError): execute(ROOT, packet=packet)
            run.assert_not_called()

    def test_security_packet_and_wrong_runtime_never_execute(self):
        with patch('factory_runtime.qa_execution.subprocess.run') as run:
            with self.assertRaises(StateError): execute(ROOT, packet=prepare(ROOT,role='security'))
            with patch('factory_runtime.qa_execution.sys.version_info', (3,13,0)):
                with self.assertRaises(StateError): execute(ROOT)
            run.assert_not_called()

    def test_timeout_is_a_failed_report_not_pass_or_retry(self):
        with patch('factory_runtime.qa_execution.subprocess.run',
                   side_effect=subprocess.TimeoutExpired('redacted',5)) as run:
            report = execute(ROOT)
        self.assertEqual(report['status'], 'LOCAL_QA_FAILED_UNSIGNED')
        self.assertEqual(run.call_count, 18)
        self.assertFalse(any(case['passed'] for case in report['cases']))

    def test_partial_output_tracebacks_and_wrong_digest_fail(self):
        for result in (subprocess.CompletedProcess([],1,b'partial',b'error: invalid\n'),
                       subprocess.CompletedProcess([],1,b'',b'Traceback\n'),
                       subprocess.CompletedProcess([],0,b'',b'error: invalid\n')):
            self.assertFalse(verify_process(result))
        self.assertFalse(verify_process(subprocess.CompletedProcess([],0,b'{}\n',b''),data=b'a',valid=True))


if __name__ == '__main__': unittest.main()
