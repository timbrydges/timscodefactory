import unittest
import json
from subprocess import CompletedProcess
from unittest.mock import patch
from scripts.spec_state_read_probe import PK, ROLE, ReadError, read, run


class ReadProbeTests(unittest.TestCase):
    @patch('scripts.spec_state_read_probe.subprocess.run')
    def test_absent_item_empty_cli_output_is_allowed_read(self, cli):
        cli.side_effect = [
            CompletedProcess([], 0, json.dumps({'Account':'666730517561','Arn':ROLE+'fixture'}).encode(), b''),
            CompletedProcess([], 0, b'', b''),
            CompletedProcess([], 254, b'', b'An error occurred (AccessDeniedException)'),
        ]
        result = run('123-1', 'a'*40)
        self.assertTrue(result['exact_task_read_allowed'])
        self.assertFalse(result['task_exists'])
        self.assertTrue(result['other_task_read_denied'])

    @patch('scripts.spec_state_read_probe.subprocess.run')
    def test_empty_identity_or_malformed_json_remains_failure(self, cli):
        cli.return_value = CompletedProcess([], 0, b'', b'')
        with self.assertRaises(json.JSONDecodeError):
            read('sts', 'get-caller-identity', {})
        cli.return_value = CompletedProcess([], 0, b'invalid', b'')
        with self.assertRaises(json.JSONDecodeError):
            read('dynamodb', 'get-item', {})

    def setUp(self):
        self.calls=[];self.denial='AccessDeniedException';self.role=ROLE+'fixture'

    def call(self,service,operation,params):
        self.calls.append((service,operation,params))
        if service=='sts':return {'Account':'666730517561','Arn':self.role}
        if params['Key']['PK']['S']==PK:return {'Item':{'payload':{'S':'not exported'}}}
        if self.denial:raise ReadError(self.denial)
        return {}

    def test_reads_only_fixed_partition_and_exports_no_payload(self):
        result=run('123-1','a'*40,call=self.call)
        self.assertTrue(result['exact_task_read_allowed']);self.assertTrue(result['other_task_read_denied'])
        self.assertNotIn('payload',result);self.assertEqual(result['signatures'],0)
        self.assertEqual([x[1] for x in self.calls],['get-caller-identity','get-item','get-item'])
        self.assertTrue(all(x[2]['ConsistentRead'] for x in self.calls[1:]))

    def test_wrong_role_stops_before_read(self):
        self.role=ROLE.replace('spec-reviewer','owner')+'fixture'
        with self.assertRaises(ValueError):run('123-1','a'*40,call=self.call)
        self.assertEqual(len(self.calls),1)

    def test_successful_out_of_scope_read_is_failure(self):
        self.denial=None
        with self.assertRaises(ValueError):run('123-1','a'*40,call=self.call)

    def test_throttle_is_not_access_denial_evidence(self):
        self.denial='ThrottlingException'
        with self.assertRaises(ReadError):run('123-1','a'*40,call=self.call)

    def test_rerun_is_blocked(self):
        with self.assertRaises(ValueError):run('123-2','a'*40,call=self.call)
        self.assertEqual(self.calls,[])
