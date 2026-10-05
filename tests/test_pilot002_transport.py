import hashlib
import io
import logging
import ssl
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials
from factory_runtime import pilot002_transport as p
from factory_runtime.pilot002_protocols import request_bytes
from factory_runtime.pilot002_packets import builder_packet
from factory_state.model import StateError
from factory_state.scope import canonical

ROOT=Path(__file__).resolve().parents[1]
KEY='synthetic-test-key-never-valid'
AWS=ReadOnlyCredentials('SYNTHETICACCESSKEY','synthetic-secret-not-real','synthetic-session-not-real')


class Response:
    status=200
    def __init__(self,raw=b'{"synthetic":true}',headers=None):
        self.raw=raw;self.headers=headers or {'Content-Type':'application/json'};self.reads=[]
    def getheader(self,key,default=None):return self.headers.get(key,default)
    def read(self,n):self.reads.append(n);return self.raw[:n]


class Connection:
    def __init__(self,response=None,error=None):
        self.response=response or Response();self.error=error;self.calls=[];self.closed=False;self.debug=None
    def set_debuglevel(self,value):self.debug=value
    def request(self,*args,**kwargs):
        self.calls.append((args,kwargs))
        if self.error:raise self.error
    def getresponse(self):return self.response
    def close(self):self.closed=True


class TransportTests(unittest.TestCase):
    def setUp(self):
        packet=builder_packet(ROOT)
        self.builder=canonical({'task_id':packet['task_id'],'packet_digest':packet['packet_digest'],
            'files':{'fingerprint.py':'# candidate\n','tests/test_fingerprint.py':'# tests\n'}})

    def setup_role(self,role='builder',enabled=True):
        context={'role':role,**({} if role=='builder' else {'builder_response':self.builder,'candidate_commit':'a'*40})}
        body=request_bytes(ROOT,**context)
        transport=p.Pilot002Transport(ROOT,**context,enabled=enabled)
        kwargs={'request_bytes':body,'expected_request_digest':'sha256:'+hashlib.sha256(body).hexdigest(),
            'credential':AWS if role=='inspector' else KEY}
        return transport,kwargs

    def test_disabled_by_default_before_any_connection(self):
        transport,kwargs=self.setup_role(enabled=False)
        with patch.object(p.http.client,'HTTPSConnection') as connect:
            with self.assertRaisesRegex(StateError,'disabled'):transport.send_once(**kwargs)
            connect.assert_not_called()

    def test_all_three_fixed_routes_tls_and_exact_wire_bodies(self):
        import json
        for role in ('builder','inspector','qa'):
            transport,kwargs=self.setup_role(role);connection=Connection()
            with self.subTest(role=role),patch.object(p.http.client,'HTTPSConnection',return_value=connection) as connect:
                self.assertEqual(transport.send_once(**kwargs),b'{"synthetic":true}')
                host,port=connect.call_args.args
                self.assertEqual(host,p.ROUTES[role][0]);self.assertEqual(port,443)
                context=connect.call_args.kwargs['context']
                self.assertTrue(context.check_hostname);self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED)
                self.assertEqual(connect.call_args.kwargs['timeout'],90)
                self.assertEqual(connection.debug,0);self.assertTrue(connection.closed)
                self.assertEqual(len(connection.calls),1)
                args,sent=connection.calls[0]
                self.assertEqual(args,('POST',p.ROUTES[role][1]))
                expected=kwargs['request_bytes']
                if role=='inspector':
                    value=json.loads(expected);self.assertEqual(value.pop('modelId'),p.PROFILE);expected=canonical(value)
                    self.assertIn('/ca-central-1/bedrock/aws4_request',sent['headers']['Authorization'])
                    self.assertEqual(sent['headers']['X-Amz-Security-Token'],AWS.token)
                elif role=='builder':self.assertEqual(sent['headers']['Authorization'],'Bearer '+KEY)
                else:self.assertEqual(sent['headers']['x-goog-api-key'],KEY)
                self.assertEqual(sent['body'],expected)
                self.assertEqual(connection.response.reads,[p.MAX_RESPONSE_BYTES+1])

    def test_modified_request_and_digest_never_send(self):
        for field,value in (('request_bytes',b'{}'),('expected_request_digest','sha256:'+'0'*64)):
            transport,kwargs=self.setup_role();kwargs[field]=value
            with patch.object(p.http.client,'HTTPSConnection') as connect,self.assertRaises(StateError):
                transport.send_once(**kwargs)
            connect.assert_not_called()

    def test_success_and_uncertain_failure_cannot_be_retried(self):
        for error in (None,TimeoutError('secret echoed'),OSError('secret echoed')):
            transport,kwargs=self.setup_role();connection=Connection(error=error)
            with patch.object(p.http.client,'HTTPSConnection',return_value=connection) as connect:
                if error:
                    with self.assertRaisesRegex(StateError,'^Pilot 002 provider transport failed; reconcile without retry$'):
                        transport.send_once(**kwargs)
                else:transport.send_once(**kwargs)
                with self.assertRaisesRegex(StateError,'already attempted'):transport.send_once(**kwargs)
                self.assertEqual(connect.call_count,1);self.assertEqual(len(connection.calls),1)
                self.assertTrue(connection.closed)

    def test_redirects_and_error_status_discard_body(self):
        for status in (301,302,307,308,400,401,429,500,503):
            response=Response(b'sensitive error');response.status=status
            transport,kwargs=self.setup_role();connection=Connection(response)
            with self.subTest(status=status),patch.object(p.http.client,'HTTPSConnection',return_value=connection) as connect:
                with self.assertRaises(StateError):transport.send_once(**kwargs)
                self.assertEqual(connect.call_count,1);self.assertEqual(response.reads,[])

    def test_compression_content_type_and_response_bounds(self):
        responses=[Response(headers={'Content-Type':'text/html'}),
            Response(headers={'Content-Type':'application/json','Content-Encoding':'gzip'}),
            Response(b'x'*(p.MAX_RESPONSE_BYTES+1)),Response(b'')]
        for response in responses:
            transport,kwargs=self.setup_role();connection=Connection(response)
            with patch.object(p.http.client,'HTTPSConnection',return_value=connection),self.assertRaises(StateError):
                transport.send_once(**kwargs)
            self.assertTrue(connection.closed)

    def test_read_and_connection_failures_remain_terminal(self):
        for stage in ('connect','headers','read'):
            transport,kwargs=self.setup_role();connection=Connection()
            with self.subTest(stage=stage),patch.object(p.http.client,'HTTPSConnection',return_value=connection) as connect:
                if stage=='connect':connect.side_effect=OSError('credential must not escape')
                elif stage=='headers':connection.getresponse=lambda:(_ for _ in ()).throw(TimeoutError('credential must not escape'))
                else:connection.response.read=lambda n:(_ for _ in ()).throw(TimeoutError('credential must not escape'))
                with self.assertRaisesRegex(StateError,'^Pilot 002 provider transport failed; reconcile without retry$'):
                    transport.send_once(**kwargs)
                with self.assertRaisesRegex(StateError,'already attempted'):transport.send_once(**kwargs)
                self.assertEqual(connect.call_count,1)
                if stage!='connect':self.assertTrue(connection.closed)

    def test_http_status_is_bounded_and_error_body_is_never_read(self):
        for status in (302,400,401,403,429,500,503,599,'503 private',True,600):
            transport,kwargs=self.setup_role('qa');response=Response(b'private credential and provider message')
            response.status=status;connection=Connection(response)
            with self.subTest(status=status),patch.object(p.http.client,'HTTPSConnection',return_value=connection):
                with self.assertRaises(p.ProviderHTTPStatusError) as caught:transport.send_once(**kwargs)
                expected=status if type(status) is int and 300<=status<=599 else None
                self.assertEqual(caught.exception.http_status,expected)
                self.assertEqual(str(caught.exception),'Pilot 002 provider transport failed; reconcile without retry')
                self.assertEqual(response.reads,[]);self.assertTrue(connection.closed)
                with self.assertRaisesRegex(StateError,'already attempted'):transport.send_once(**kwargs)
                self.assertEqual(len(connection.calls),1)

    def test_invalid_credentials_consume_local_latch_without_network(self):
        for role,value in (('builder',KEY+'\r\nX: injected'),('qa','short'),('inspector',KEY),
                           ('inspector',ReadOnlyCredentials(AWS.access_key,AWS.secret_key,None))):
            transport,kwargs=self.setup_role(role);kwargs['credential']=value
            with patch.object(p.http.client,'HTTPSConnection') as connect:
                with self.assertRaises(StateError):transport.send_once(**kwargs)
                with self.assertRaisesRegex(StateError,'already attempted'):transport.send_once(**kwargs)
                connect.assert_not_called()

    def test_concurrent_calls_send_only_once(self):
        transport,kwargs=self.setup_role();connection=Connection()
        def invoke(_):
            try:transport.send_once(**kwargs);return True
            except StateError:return False
        with patch.object(p.http.client,'HTTPSConnection',return_value=connection) as connect,ThreadPoolExecutor(8) as pool:
            outcomes=list(pool.map(invoke,range(16)))
        self.assertEqual(sum(outcomes),1);self.assertEqual(connect.call_count,1)

    def test_quiet_sigv4_matches_sdk_without_debug_secret_output(self):
        fixed=datetime(2026,10,3,18,0,tzinfo=timezone.utc)
        host,path=p.ROUTES['inspector']
        args={'method':'POST','url':'https://'+host+path,'data':b'{}','headers':{'Host':host,'Content-Type':'application/json'}}
        expected=AWSRequest(**args)
        with patch('botocore.auth.get_current_datetime',return_value=fixed):SigV4Auth(AWS,'bedrock',p.REGION).add_auth(expected)
        output=io.StringIO();handler=logging.StreamHandler(output);logger=logging.getLogger('botocore.auth')
        old_level=logger.level;logger.setLevel(logging.DEBUG);logger.addHandler(handler)
        try:
            actual=AWSRequest(**args)
            with patch.object(p,'datetime') as clock:
                clock.now.return_value=fixed;p._QuietSigV4(AWS,'bedrock',p.REGION).add_auth(actual)
        finally:logger.removeHandler(handler);logger.setLevel(old_level)
        self.assertEqual(dict(actual.headers),dict(expected.headers))
        self.assertEqual(output.getvalue(),'')


if __name__=='__main__':unittest.main()
