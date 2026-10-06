import unittest
from scripts.spec_state_read_probe import PK, ROLE, ReadError, run


class ReadProbeTests(unittest.TestCase):
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
