import json
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import check_pilot002_provider_metadata as p
from factory_state.model import StateError

KEY='synthetic-key-not-a-real-credential'


class MetadataChecksTests(unittest.TestCase):
    def connection(self,role='builder',status=200,body=None,encoding='identity'):
        response=Mock(status=status)
        response.getheader.side_effect=lambda name,default: 'application/json' if name=='Content-Type' else encoding
        if body is None:body=json.dumps({'id':'gpt-5.6-sol','object':'model','unknown':KEY} if role=='builder' else {'name':'models/gemini-3.8-flash','unknown':KEY}).encode()
        response.read.return_value=body
        connection=Mock();connection.getresponse.return_value=response
        return connection,response

    def test_only_fixed_get_routes_and_auth_headers_no_body_or_secret_output(self):
        for role in p.ROUTES:
            connection,response=self.connection(role);load=Mock(return_value=(KEY,'raw'))
            with patch.object(p.http.client,'HTTPSConnection',return_value=connection) as factory:
                result=p.check(role,load_credential=load,enabled=True)
            self.assertEqual(result['status'],'AUTHENTICATED_MODEL_METADATA_OBSERVED')
            self.assertFalse(result['live_generation_readiness']);self.assertFalse(result['project_binding_verified'])
            self.assertEqual(result['generation_requests'],0);self.assertNotIn(KEY,json.dumps(result))
            load.assert_called_once();factory.assert_called_once();connection.request.assert_called_once()
            args=connection.request.call_args;self.assertEqual(args.args,('GET',p.ROUTES[role][1]));self.assertIsNone(args.kwargs['body'])
            self.assertNotIn('?',args.args[1]);self.assertEqual(factory.call_args.args,(p.ROUTES[role][0],443))
            self.assertEqual(args.kwargs['headers']['Authorization' if role=='builder' else 'x-goog-api-key'],('Bearer ' if role=='builder' else '')+KEY)
            tls=factory.call_args.kwargs['context'];self.assertTrue(tls.check_hostname);self.assertEqual(tls.verify_mode,ssl.CERT_REQUIRED)
            connection.close.assert_called_once()

    def test_disabled_unknown_role_and_cli_without_approval_do_nothing(self):
        load=Mock()
        with patch.object(p.http.client,'HTTPSConnection') as connect:
            for role,enabled in [('builder',False),('builder','true'),('inspector',True)]:
                with self.assertRaises(StateError):p.check(role,load_credential=load,enabled=enabled)
            with self.assertRaises(StateError):p.run('unused.json')
            load.assert_not_called();connect.assert_not_called()

    def test_credential_failure_is_sanitized_before_connection(self):
        with patch.object(p.http.client,'HTTPSConnection') as connect:
            result=p.check('builder',load_credential=Mock(side_effect=RuntimeError(KEY)),enabled=True)
        self.assertEqual(result['failed_stage'],'credential');self.assertEqual(result['http_requests'],0)
        self.assertNotIn(KEY,json.dumps(result));connect.assert_not_called()

    def test_rejections_and_redirects_are_not_read_reflected_or_retried(self):
        for status in (301,302,401,403,429,500):
            connection,response=self.connection(status=status)
            with patch.object(p.http.client,'HTTPSConnection',return_value=connection) as connect:
                result=p.check('builder',load_credential=lambda:(KEY,'raw'),enabled=True)
            self.assertEqual(result['status'],'METADATA_ENDPOINT_REJECTED');self.assertEqual(result['http_status'],status)
            connect.assert_called_once();connection.request.assert_called_once();response.read.assert_not_called()

    def test_oversize_mismatch_duplicates_and_compression_rejected(self):
        variants=[(b'x'*65537,'identity'),(b'{"id":"other","object":"model"}','identity'),
            (b'{"id":"gpt-5.6-sol","id":"other","object":"model"}','identity'),(b'{}','gzip')]
        for body,encoding in variants:
            connection,_=self.connection(body=body,encoding=encoding)
            with patch.object(p.http.client,'HTTPSConnection',return_value=connection):
                result=p.check('builder',load_credential=lambda:(KEY,'raw'),enabled=True)
            self.assertEqual(result['status'],'METADATA_CHECK_FAILED');self.assertEqual(result['failed_stage'],'response')

    def test_network_exception_never_retries_or_leaks(self):
        connection,_=self.connection();connection.request.side_effect=RuntimeError(KEY)
        with patch.object(p.http.client,'HTTPSConnection',return_value=connection) as connect:
            result=p.check('qa',load_credential=lambda:(KEY,'raw'),enabled=True)
        self.assertEqual(result['http_requests'],1);self.assertEqual(result['failed_stage'],'request')
        self.assertNotIn(KEY,json.dumps(result));connect.assert_called_once();connection.request.assert_called_once()

    def test_secret_read_requires_exact_version_and_rejects_unknown_format(self):
        for role in p.ROUTES:
            client=Mock();base={'ARN':p.SECRETS[role],'VersionId':p.VERSIONS[role]}
            for value,kind in [(KEY,'raw'),(json.dumps({'api_key':KEY}),'api_key_json')]:
                client.get_secret_value.return_value={**base,'SecretString':value}
                self.assertEqual(p.read_credential(client,role),(KEY,kind))
                client.get_secret_value.assert_called_with(SecretId=p.SECRETS[role],VersionId=p.VERSIONS[role])
            for response in ({**base,'SecretString':KEY,'VersionId':'changed'},
                             {**base,'SecretString':json.dumps({'api_key':KEY,'extra':'data'})},
                             {**base,'SecretString':KEY+'\n'}):
                client.get_secret_value.return_value=response
                with self.assertRaises(ValueError):p.read_credential(client,role)

    def test_existing_audit_output_blocks_credentials_and_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'audit.json';path.write_text('previous marker')
            with patch('boto3.Session') as session:
                with self.assertRaises(FileExistsError):p.run(path,approved=True)
                session.assert_not_called();self.assertEqual(path.read_text(),'previous marker')


if __name__=='__main__':unittest.main()
