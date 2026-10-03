import json
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import check_pilot002_builder_tokens as b

KEY='synthetic-openai-key-not-real'


class BuilderTokenTests(unittest.TestCase):
    def connection(self,value=None,status=200):
        response=Mock(status=status)
        response.getheader.side_effect=lambda name,default:'application/json' if name=='Content-Type' else 'identity'
        response.read.return_value=json.dumps(value or {'object':'response.input_tokens','input_tokens':2345}).encode()
        conn=Mock();conn.getresponse.return_value=response
        return conn,response

    def test_prepare_preserves_context_fields_and_performs_no_network(self):
        with patch.object(b.http.client,'HTTPSConnection') as connect:
            plan=b.prepare();connect.assert_not_called()
        full=json.loads(b.request_bytes(b.ROOT,role='builder'))
        self.assertEqual(plan['generation_request_digest'],b.sha(b.canonical(full)))
        self.assertEqual(set(plan['count_request']),{'model','instructions','input','tools','reasoning','text','truncation'})
        for key,value in plan['count_request'].items():self.assertEqual(value,full[key])
        self.assertEqual(plan['count_request_digest'],b.sha(b.canonical(plan['count_request'])))

    def test_changed_or_added_execution_controls_fail_closed(self):
        full=json.loads(b.request_bytes(b.ROOT,role='builder'))
        for changed in ({**full,'store':True},{**full,'model':'other'},{**full,'previous_response_id':'other'}):
            with patch.object(b,'request_bytes',return_value=b.canonical(changed)):
                with self.assertRaises(ValueError):b.prepare()

    def test_fixed_count_endpoint_one_call_and_sanitized_result(self):
        conn,response=self.connection();load=Mock(return_value=(KEY,'raw'));plan=b.prepare()
        with patch.object(b.http.client,'HTTPSConnection',return_value=conn) as factory:
            result=b.measure(plan,load)
        self.assertEqual(result['input_tokens'],2345);self.assertEqual(result['generation_requests'],0)
        self.assertFalse(result['cost_qualified']);self.assertNotIn(KEY,json.dumps(result))
        conn.request.assert_called_once();load.assert_called_once()
        self.assertEqual(conn.request.call_args.args,('POST','/v1/responses/input_tokens'))
        self.assertEqual(conn.request.call_args.kwargs['body'],b.canonical(plan['count_request']))
        self.assertEqual(factory.call_args.args,('api.openai.com',443))
        tls=factory.call_args.kwargs['context'];self.assertTrue(tls.check_hostname);self.assertEqual(tls.verify_mode,ssl.CERT_REQUIRED)

    def test_rejections_do_not_read_error_bodies_or_retry(self):
        for status in (301,302,401,403,429,500):
            conn,response=self.connection(status=status)
            with patch.object(b.http.client,'HTTPSConnection',return_value=conn):
                result=b.measure(b.prepare(),lambda:(KEY,'raw'))
            self.assertEqual(result['status'],'TOKEN_ENDPOINT_REJECTED')
            response.read.assert_not_called();conn.request.assert_called_once()

    def test_invalid_counts_and_duplicate_fields_fail(self):
        for value in (-1,0,True,32769,1.5,'2345'):
            conn,_=self.connection({'object':'response.input_tokens','input_tokens':value})
            with patch.object(b.http.client,'HTTPSConnection',return_value=conn):
                self.assertEqual(b.measure(b.prepare(),lambda:(KEY,'raw'))['status'],'TOKEN_MEASUREMENT_FAILED')
        conn,response=self.connection();response.read.return_value=b'{"object":"response.input_tokens","input_tokens":1,"input_tokens":2}'
        with patch.object(b.http.client,'HTTPSConnection',return_value=conn):
            self.assertEqual(b.measure(b.prepare(),lambda:(KEY,'raw'))['status'],'TOKEN_MEASUREMENT_FAILED')

    def test_network_and_credential_failures_do_not_leak(self):
        conn,_=self.connection();conn.request.side_effect=RuntimeError(KEY)
        with patch.object(b.http.client,'HTTPSConnection',return_value=conn):
            result=b.measure(b.prepare(),lambda:(KEY,'raw'))
        self.assertEqual(result['http_requests'],1);self.assertNotIn(KEY,json.dumps(result));conn.request.assert_called_once()
        with patch.object(b.http.client,'HTTPSConnection') as factory:
            result=b.measure(b.prepare(),Mock(side_effect=ValueError(KEY)))
        factory.assert_not_called();self.assertEqual(result['http_requests'],0);self.assertNotIn(KEY,json.dumps(result))

    def test_approval_digest_clean_tree_and_existing_marker_block_secret_reads(self):
        with tempfile.TemporaryDirectory() as directory,patch('boto3.Session') as session:
            out=Path(directory)/'audit.json'
            with self.assertRaises(ValueError):b.run(out,'anything')
            with self.assertRaises(ValueError):b.run(out,'wrong',approved=True)
            with patch.object(b.subprocess,'check_output',return_value=b'dirty'):
                with self.assertRaises(ValueError):b.run(out,b.prepare()['count_request_digest'],approved=True)
            out.write_text('old')
            with patch.object(b.subprocess,'check_output',side_effect=[b'','a'*40]):
                with self.assertRaises(FileExistsError):b.run(out,b.prepare()['count_request_digest'],approved=True)
            self.assertEqual(out.read_text(),'old');session.assert_not_called()


if __name__=='__main__':unittest.main()
