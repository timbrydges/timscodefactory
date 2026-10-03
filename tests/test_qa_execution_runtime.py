import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from factory_runtime.qa_execution_runtime import handler, CANDIDATE
from factory_state.model import StateError


class ExecutionRuntimeTests(unittest.TestCase):
    def test_exact_disabled_event_executes_without_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory,'BUILD.json').write_text(json.dumps({'source_commit':'a'*40}))
            env={'LAMBDA_TASK_ROOT':directory,'FACTORY_REVIEW_ROLE':'qa',
                 'FACTORY_OPERATIONAL_EXECUTION_ENABLED':'false'}
            event={'kind':'qa_execute_unsigned','source_commit':'a'*40,'candidate_commit':CANDIDATE}
            with patch.dict(os.environ,env,clear=True), patch('factory_runtime.qa_execution_runtime.execute') as execute:
                execute.return_value={'status':'LOCAL_QA_PASSED_UNSIGNED'}
                result=handler(event,None)
                execute.assert_called_once_with(Path(directory))
                self.assertFalse(result['gate_authority'])
                self.assertEqual(result['kms_calls'],0)
                self.assertEqual(result['model_calls'],0)

    def test_role_flag_and_event_reject_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory,'BUILD.json').write_text(json.dumps({'source_commit':'a'*40}))
            env={'LAMBDA_TASK_ROOT':directory,'FACTORY_REVIEW_ROLE':'qa',
                 'FACTORY_OPERATIONAL_EXECUTION_ENABLED':'false'}
            event={'kind':'qa_execute_unsigned','source_commit':'a'*40,'candidate_commit':CANDIDATE}
            for env_change,event_change in [({'FACTORY_REVIEW_ROLE':'security'},{}),
                ({'FACTORY_OPERATIONAL_EXECUTION_ENABLED':'true'},{}),({}, {'kind':'sign'}),
                ({},{'source_commit':'b'*40}),({},{'candidate_commit':'b'*40}),({},{'extra':True})]:
                with patch.dict(os.environ,{**env,**env_change},clear=True), patch('factory_runtime.qa_execution_runtime.execute') as execute:
                    with self.assertRaises(StateError): handler({**event,**event_change},None)
                    execute.assert_not_called()


if __name__=='__main__': unittest.main()
