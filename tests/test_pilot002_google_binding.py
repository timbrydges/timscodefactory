from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import check_pilot002_google_binding as b

KEY='synthetic-google-key-not-real'
NONCE='ab'*32


class GoogleBindingTests(unittest.TestCase):
    def test_fingerprint_is_domain_separated_and_validates_inputs(self):
        self.assertEqual(len(b.fingerprint(KEY,NONCE)),64)
        self.assertNotEqual(b.fingerprint(KEY,NONCE),b.fingerprint(KEY,'cd'*32))
        for key,nonce in [(KEY+'\n',NONCE),('short',NONCE),(KEY,'bad'),(None,NONCE)]:
            with self.assertRaises(ValueError):b.fingerprint(key,nonce)

    def test_approval_and_exclusive_marker_precede_reads(self):
        with tempfile.TemporaryDirectory() as d,patch.object(b,'aws_key') as read:
            path=Path(d)/'result.json'
            with self.assertRaises(ValueError):b.run('aws',NONCE,path)
            self.assertFalse(path.exists())
            path.write_text('old')
            with self.assertRaises(FileExistsError):b.run('aws',NONCE,path,approved=True)
            read.assert_not_called();self.assertEqual(path.read_text(),'old')

    def reports(self):
        with tempfile.TemporaryDirectory() as d,patch.object(b,'aws_key',return_value=KEY),patch.object(b,'google_key',return_value=KEY):
            return [b.run(side,NONCE,Path(d)/(side+'.json'),approved=True) for side in ('aws','google')]

    def test_private_outputs_compare_without_key_or_live_authority(self):
        aws,google=self.reports()
        self.assertNotIn(KEY,json.dumps([aws,google]))
        result=b.compare(aws,google)
        self.assertEqual(result['status'],'GOOGLE_CREDENTIAL_PROJECT_BOUND')
        self.assertFalse(result['billing_verified']);self.assertFalse(result['live_execution_authorized'])

    def test_mismatch_staleness_wrong_identity_and_failed_read_cannot_bind(self):
        aws,google=self.reports()
        for field,value in [('fingerprint','ff'*32),('nonce','cd'*32),('project','other'),('secret_version','other'),
                            ('status','FINGERPRINT_FAILED'),('side','aws'),
                            ('observed_at',(datetime.now(timezone.utc)-timedelta(seconds=301)).isoformat())]:
            with self.assertRaises(ValueError):b.compare(aws,{**google,field:value})

    def test_errors_are_sanitized_and_never_retried(self):
        with tempfile.TemporaryDirectory() as d,patch.object(b,'google_key',side_effect=RuntimeError(KEY)) as read:
            result=b.run('google',NONCE,Path(d)/'result.json',approved=True)
            self.assertEqual(result['status'],'FINGERPRINT_FAILED');self.assertNotIn(KEY,json.dumps(result))
            self.assertNotIn('fingerprint',result);read.assert_called_once()

    def test_google_routes_do_not_include_key_and_reject_redirects(self):
        connection=Mock();response=Mock(status=302);connection.getresponse.return_value=response
        with patch.object(b.http.client,'HTTPSConnection',return_value=connection) as factory:
            with self.assertRaises(ValueError):b.google_get('apikeys.googleapis.com','/v2/'+b.RESOURCE+'/keyString','synthetic-token')
            self.assertEqual(connection.request.call_args.args,('GET','/v2/'+b.RESOURCE+'/keyString'))
            response.read.assert_not_called();connection.request.assert_called_once()
            tls=factory.call_args.kwargs['context'];self.assertTrue(tls.check_hostname);self.assertEqual(tls.verify_mode,ssl.CERT_REQUIRED)
            with self.assertRaises(ValueError):b.google_get('other.example','/key','synthetic-token')
            factory.assert_called_once()

    def test_google_project_and_key_identity_checked_before_secret(self):
        project={'projectId':b.PROJECT,'projectNumber':b.NUMBER,'lifecycleState':'ACTIVE'}
        metadata={'name':b.RESOURCE,'displayName':'Tims Software Factory QA'}
        with patch.object(b.subprocess,'run',return_value=Mock(returncode=0,stdout='synthetic-token\n')) as auth:
            with patch.object(b,'google_get',side_effect=[project,metadata,{'keyString':KEY}]) as get:
                self.assertEqual(b.google_key(),KEY);self.assertEqual(get.call_count,3)
                self.assertNotIn(KEY,str(auth.call_args));self.assertTrue(auth.call_args.kwargs['capture_output'])
            with patch.object(b,'google_get',return_value={**project,'projectNumber':'wrong'}) as get:
                with self.assertRaises(ValueError):b.google_key()
                get.assert_called_once()

    def test_aws_read_pins_account_arn_and_version(self):
        session=Mock();sts=Mock();secrets=Mock()
        session.client.side_effect=lambda service,**kwargs:sts if service=='sts' else secrets
        sts.get_caller_identity.return_value={'Account':'666730517561'}
        secrets.get_secret_value.return_value={'ARN':b.SECRET,'VersionId':b.VERSION,'SecretString':KEY}
        with patch('boto3.Session',return_value=session):
            self.assertEqual(b.aws_key(),KEY)
            secrets.get_secret_value.assert_called_once_with(SecretId=b.SECRET,VersionId=b.VERSION)
            sts.get_caller_identity.return_value={'Account':'wrong'}
            secrets.reset_mock()
            with self.assertRaises(ValueError):b.aws_key()
            secrets.get_secret_value.assert_not_called()


if __name__=='__main__':unittest.main()
