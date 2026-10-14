import unittest

from factory_runtime import security_access_probe as m
class Denied(Exception):
    response={'Error':{'Code':'AccessDeniedException'}}
class Client:
    def __init__(self,allowed):self.allowed=allowed;self.calls=[]
    def get_item(self,**kwargs):
        self.calls.append(kwargs)
        if kwargs['Key']['PK']['S'] not in self.allowed:raise Denied()
        return {'Item':{'state':{'S':'SECURITY_REVIEW'}}}
class Tests(unittest.TestCase):
    def test_exact_read_and_outside_denial(self):
        c=Client({m.TASK});r=m.probe({'operation':'verify-security-source-access'},c)
        self.assertEqual(r,{'exact_task':{'decision':'allowed','record_present':True},'outside_scope':{'decision':'denied'}})
        self.assertEqual(len(c.calls),2)
        self.assertTrue(all(x['TableName']==m.TABLE and x['ConsistentRead'] for x in c.calls))
    def test_wrong_source_denies_both(self):
        self.assertTrue(all(v['decision']=='denied' for v in m.probe({'operation':'verify-security-source-access'},Client(set())).values()))
    def test_invalid_event_never_reads(self):
        c=Client(set())
        with self.assertRaises(ValueError):m.probe({'operation':'other'},c)
        self.assertEqual(c.calls,[])
    def test_uncertain_failure_propagates(self):
        class Broken:
            def get_item(self,**kwargs):raise TimeoutError()
        with self.assertRaises(TimeoutError):m.probe({'operation':'verify-security-source-access'},Broken())
if __name__ == '__main__':
    unittest.main()
