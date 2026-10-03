import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from factory_runtime import security_validation as runner
from factory_state.model import StateError

ROOT = Path(__file__).resolve().parents[1]


class SecurityValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = runner.execute(ROOT)
        cls.packet = runner.prepare(ROOT, role='security')

    def test_real_execution_preserves_findings_and_limits(self):
        report = self.report
        self.assertTrue(runner.validate_execution(report, self.packet, root=ROOT))
        self.assertEqual(report['case_count'], 5)
        self.assertEqual(len(report['findings']), 3)
        self.assertFalse(report['gate_authority'])
        self.assertFalse(report['controls']['os_sandbox_claimed'])
        self.assertNotIn('public fixture', json.dumps(report))

    def test_tampered_packet_and_wrong_runtime_never_execute(self):
        packet = copy.deepcopy(self.packet)
        packet['untrusted_material']['files']['fingerprint.py'] += '\nprint("changed")'
        with patch.object(runner, 'run_fixture') as run:
            with self.assertRaises(StateError): runner.execute(ROOT, packet=packet)
            with patch.object(runner.sys, 'version_info', (3,13)):
                with self.assertRaises(StateError): runner.execute(ROOT)
            run.assert_not_called()

    def test_timeout_has_one_attempt_per_distinct_fixture_and_fails(self):
        original = subprocess.run
        def bounded_timeout(args, **kwargs):
            if args[0] == runner.sys.executable: raise subprocess.TimeoutExpired('python',5)
            return original(args, **kwargs)
        with patch.object(runner.subprocess, 'run', side_effect=bounded_timeout) as run:
            report = runner.execute(ROOT)
        self.assertEqual(sum(c.args[0][0]==runner.sys.executable for c in run.call_args_list), 5)
        self.assertFalse(runner.validate_execution(report,self.packet,root=ROOT))
        report['status'] = 'BOUNDED_VALIDATION_PASSED'
        report['report_digest'] = runner.digest({k:v for k,v in report.items() if k!='report_digest'})
        with self.assertRaises(StateError): runner.validate_execution(report,self.packet,root=ROOT)

    def test_environment_isolated_and_process_bounded(self):
        original = subprocess.run
        with patch.dict(os.environ, {'AWS_SECRET_ACCESS_KEY':'fake','OPENAI_API_KEY':'fake'}):
            with patch.object(runner.subprocess,'run',wraps=original) as run:
                runner.execute(ROOT)
        calls=[c for c in run.call_args_list if c.args[0][0]==runner.sys.executable]
        self.assertEqual(len(calls),5)
        for call in calls:
            self.assertEqual(call.args[0][1:4],['-I','-S','-B'])
            self.assertEqual(call.kwargs['timeout'],5)
            self.assertNotIn('AWS_SECRET_ACCESS_KEY',call.kwargs['env'])
            self.assertNotIn('OPENAI_API_KEY',call.kwargs['env'])

    def test_nonregular_or_outside_path_rejected_before_process(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp); program=directory/'program.py'; program.write_text('')
            with patch.object(runner.subprocess,'run') as run:
                with self.assertRaises(StateError): runner.run_fixture(program,directory,directory)
                with self.assertRaises(StateError): runner.regular(program,directory/'other')
                with patch.object(Path,'is_symlink',return_value=True):
                    with self.assertRaises(StateError): runner.run_fixture(program,program,directory)
                run.assert_not_called()

    def test_rehashed_scope_or_findings_changes_rejected(self):
        for change in ({'findings':[]},{'controls':{}},{'gate_authority':True},{'cases':[]}):
            report={**self.report,**change}
            report['report_digest']=runner.digest({k:v for k,v in report.items() if k!='report_digest'})
            with self.assertRaises(StateError): runner.validate_execution(report,self.packet,root=ROOT)


if __name__=='__main__': unittest.main()
