import base64
import copy
import hashlib
import unittest
from datetime import timedelta
from unittest.mock import Mock,patch

import test_qa_recovery001_authorization as auth
import test_pilot002_transport as transport
from factory_runtime import qa_recovery001_entrypoint as p
from factory_runtime.qa_recovery001 import PK,TABLE
from factory_runtime.pilot002_packets import review_packet,REVIEW_BINDINGS
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical
from factory_state.signers import public_key_der


class RecoveryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fx=auth.RecoveryAuthorizationTests();self.fx.setUp();a=self.fx.args
        self.now=a['now'];epoch=int(self.now.timestamp());pem=a['trusted_keys'][OWNER_IDENTITY]
        plan=self.fx.plan
        self.doc={'schema_version':'1.0','kind':'qa_recovery001_activation',
            'source_commit':a['source_commit'],'candidate_commit':a['candidate_commit'],
            'builder_response_base64':base64.b64encode(a['builder_response']).decode(),
            'qualification':plan['activation']['qualification'],'readiness':a['readiness'],
            'credential':copy.deepcopy(p.GOOGLE_ROUTE),'capture_failed_review_response':True,
            'signer_registry':{'schema_version':'1.0','enabled':True,'signers':[{'identity':OWNER_IDENTITY,
                'public_key_pem':pem.decode(),'fingerprint':'sha256:'+hashlib.sha256(public_key_der(pem)).hexdigest(),
                'enrollment_commit':'a'*40,'not_before':epoch-1,'expires_at':epoch+3600,'revoked':False}]}}
        self.env={p.ENABLED:'true','AWS_REGION':p.REGION,'AWS_LAMBDA_FUNCTION_NAME':p.FUNCTION}
        self.encode();self.context=Mock(invoked_function_arn='arn:aws:lambda:'+p.REGION+':'+p.ACCOUNT+':function:'+p.FUNCTION)
        self.context.get_remaining_time_in_millis.return_value=150000
        self.event={'kind':'qa_recovery001_run_once','allowance':self.fx.sign()}
        self.events=[];self.rows={};self.db=Mock()
        def put(**kw):
            self.assertEqual(kw['TableName'],TABLE);self.assertEqual(kw['Item']['PK'],{'S':PK})
            self.assertEqual(kw['ConditionExpression'],'attribute_not_exists(PK)')
            self.events.append('claim')
            if PK in self.rows:raise RuntimeError('already used')
            self.rows[PK]=kw['Item']
        self.db.put_item.side_effect=put
        self.db.update_item.side_effect=lambda **kw:self.events.append('complete')
        self.session=Mock()
        self.secret=Mock()
        self.session.client.return_value=self.secret
        self.secret.get_secret_value.side_effect=lambda **kw:(self.events.append('credential') or {'ARN':p.GOOGLE_ROUTE['secret_arn'],'VersionId':p.GOOGLE_ROUTE['version_id'],'SecretString':transport.KEY})
        packet=review_packet(auth.ROOT,role='qa',builder_response=a['builder_response'],candidate_commit=a['candidate_commit'])
        text=canonical({**{k:packet[k] for k in REVIEW_BINDINGS},'verdict':'ACCEPTED','rationale':'Synthetic offline review.','findings':[]}).decode()
        self.raw=canonical({'modelVersion':packet['model_id'],'candidates':[{'content':{'role':'model','parts':[{'text':text}]},'finishReason':'STOP','index':0}],
            'usageMetadata':{'promptTokenCount':100,'candidatesTokenCount':30,'totalTokenCount':130}})
        self.connection=transport.Connection(transport.Response(self.raw))
        original=self.connection.request
        self.connection.request=Mock(side_effect=lambda *args,**kw:(self.events.append('send'),original(*args,**kw))[-1])

    def test_provider_status_survives_boundary_without_body_or_retry(self):
        self.connection.response.status=503
        self.connection.response.raw=b'private provider message and credential'
        with self.assertRaisesRegex(StateError,r'^QA recovery stopped at provider \(HTTP 503\); reconcile without retry$'):
            self.run_event()
        self.assertEqual(self.events,['claim','credential','send'])
        self.assertEqual(self.connection.response.reads,[])
        self.assertEqual(self.rows[PK]['reservation_status'],{'S':'HELD'})
        self.assertTrue(self.connection.closed)
        with self.assertRaisesRegex(StateError,'reservation'):self.run_event()
        self.assertEqual(self.events.count('send'),1)

    def encode(self):
        self.raw_doc=canonical(self.doc);self.env[p.ACTIVATION_SHA]=hashlib.sha256(self.raw_doc).hexdigest()

    def read(self,root,name,limit):
        return self.raw_doc if name==p.ACTIVATION else canonical({'source_commit':self.fx.args['source_commit']})

    def run_event(self):
        with patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session',return_value=self.session),\
                patch.object(p,'_client',side_effect=lambda session,service:self.db if service=='dynamodb' else self.secret),\
                patch.object(transport.p.http.client,'HTTPSConnection',return_value=self.connection):
            return p.dispatch(self.event,self.context,root=auth.ROOT,env=self.env,clock=lambda:self.now)

    def test_real_signature_protocol_and_separate_claim_send_once(self):
        result=self.run_event()
        self.assertEqual(result['status'],'QA_RECOVERY001_COMPLETED_UNSIGNED')
        self.assertEqual(self.events,['claim','credential','send','complete'])
        self.assertFalse(result['gate_authority']);self.assertFalse(result['production_release_authorized'])
        self.assertEqual(self.rows[PK]['reserved_micro_usd'],{'N':'250000'})
        self.assertEqual(result['actual_micro_usd'],0)
        self.secret.get_secret_value.assert_called_once_with(SecretId=p.GOOGLE_ROUTE['secret_arn'],VersionId=p.GOOGLE_ROUTE['version_id'])
        self.assertEqual(self.session.client.call_args.kwargs['config'].retries['total_max_attempts'],1)
        with self.assertRaisesRegex(StateError,'reservation'):self.run_event()
        self.assertEqual(len(self.connection.calls),1)

    def test_disabled_precedes_files_clients_and_signatures(self):
        for flag in (None,False,'false'):
            with patch.object(p,'_read') as read,patch.object(p,'_aws_session') as session:
                with self.assertRaisesRegex(StateError,'disabled'):
                    p.dispatch(None,None,root=None,env={p.ENABLED:flag},clock=None)
                read.assert_not_called();session.assert_not_called()

    def test_bad_runtime_identity_alias_and_short_timeout_precede_reads(self):
        original=self.context.invoked_function_arn
        for arn in (original+':1',original.replace(p.FUNCTION,'tims-factory-pilot-002-qa'),original.replace(p.REGION,'us-east-1')):
            self.context.invoked_function_arn=arn
            with patch.object(p,'_read') as read:
                with self.assertRaises(StateError):self.run_event_without_patches()
                read.assert_not_called()
        self.context.invoked_function_arn=original;self.context.get_remaining_time_in_millis.return_value=119999
        with patch.object(p,'_read') as read:
            with self.assertRaises(StateError):self.run_event_without_patches()
            read.assert_not_called()

    def run_event_without_patches(self):
        return p.dispatch(self.event,self.context,root=auth.ROOT,env=self.env,clock=lambda:self.now)

    def test_old_allowance_or_event_configuration_cannot_create_clients(self):
        original=copy.deepcopy(self.event)
        for event in ({**original,'qualification':self.doc['qualification']},
                      {**original,'allowance':self.fx.sign(self.fx.old)},
                      {**original,'kind':'pilot002_run_once'}):
            self.event=event
            with patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session') as session:
                with self.assertRaises(StateError):self.run_event_without_patches()
                session.assert_not_called()

    def test_activation_capture_candidate_source_and_registry_are_pinned(self):
        original=copy.deepcopy(self.doc)
        for mutate in (lambda d:d.update(capture_failed_review_response=False),
                       lambda d:d.update(candidate_commit='0'*40),lambda d:d.update(source_commit='0'*40),
                       lambda d:d.update(credential={'kind':'secretsmanager'}),
                       lambda d:d['signer_registry']['signers'][0].update(revoked=True)):
            self.doc=copy.deepcopy(original);mutate(self.doc);self.encode()
            with patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session') as session:
                with self.assertRaises(StateError):self.run_event_without_patches()
                session.assert_not_called()

    def test_failed_review_retained_without_acceptance_or_second_send(self):
        self.connection.response=transport.Response(b'{"invalid":"synthetic"}')
        result=self.run_event()
        self.assertEqual(result['status'],'QA_RECOVERY001_FAILED_NO_RETRY')
        self.assertEqual(base64.b64decode(result['provider_response_base64']),b'{"invalid":"synthetic"}')
        self.assertFalse(result['accepted_review']);self.assertFalse(result['attempt_reusable'])
        self.db.update_item.assert_not_called()
        with self.assertRaisesRegex(StateError,'reservation'):self.run_event()
        self.assertEqual(len(self.connection.calls),1)

    def test_provider_error_is_sanitized_and_consumes_attempt(self):
        self.connection.response=transport.Response(b'private-secret-error');self.connection.response.status=503
        with self.assertRaisesRegex(StateError,'provider') as caught:self.run_event()
        self.assertNotIn('private-secret-error',str(caught.exception))
        with self.assertRaisesRegex(StateError,'reservation'):self.run_event()
        self.assertEqual(len(self.connection.calls),1);self.db.update_item.assert_not_called()

    def test_paid_or_linked_billing_qualification_never_constructs_clients(self):
        original=copy.deepcopy(self.doc)
        for change in ('rate','billing'):
            self.doc=copy.deepcopy(original)
            if change=='rate':self.doc['qualification']['input_micro_usd_per_million']=1
            else:self.doc['qualification']['billing_observation']['billing_account_linked']=True
            self.encode()
            with patch.object(p,'_read',side_effect=self.read),patch.object(p,'_aws_session') as session:
                with self.assertRaises(StateError):self.run_event_without_patches()
                session.assert_not_called()

    def test_wrong_secret_version_consumes_hold_without_sending(self):
        self.secret.get_secret_value.side_effect=None
        self.secret.get_secret_value.return_value={'ARN':p.GOOGLE_ROUTE['secret_arn'],'VersionId':'wrong','SecretString':transport.KEY}
        with self.assertRaisesRegex(StateError,'credential'):self.run_event()
        self.assertEqual(len(self.rows),1);self.assertEqual(len(self.connection.calls),0)

    def test_expiry_after_credential_stops_before_transport(self):
        def credential(**kw):self.now+=timedelta(hours=2);return {'ARN':p.GOOGLE_ROUTE['secret_arn'],'VersionId':p.GOOGLE_ROUTE['version_id'],'SecretString':transport.KEY}
        self.secret.get_secret_value.side_effect=credential
        with self.assertRaisesRegex(StateError,'expiry_before_provider'):self.run_event()
        self.assertEqual(len(self.rows),1);self.assertEqual(len(self.connection.calls),0)

    def test_uncertain_claim_never_loads_provider_credential_or_sends(self):
        self.db.put_item.side_effect=TimeoutError('private-secret-error')
        with self.assertRaisesRegex(StateError,'reservation'):self.run_event()
        self.secret.get_secret_value.assert_not_called()
        self.assertEqual(len(self.connection.calls),0);self.db.put_item.assert_called_once()

    def test_credential_failure_keeps_hold_without_transport(self):
        self.secret.get_secret_value.side_effect=RuntimeError('private-secret-error')
        with self.assertRaisesRegex(StateError,'credential') as caught:self.run_event()
        self.assertNotIn('private-secret-error',str(caught.exception))
        self.assertEqual(len(self.rows),1);self.assertEqual(len(self.connection.calls),0)
        with self.assertRaisesRegex(StateError,'reservation'):self.run_event()
        self.secret.get_secret_value.assert_called_once()

    def test_uncertain_completion_returns_evidence_but_does_not_resend(self):
        self.db.update_item.side_effect=TimeoutError('private-secret-error')
        result=self.run_event()
        self.assertEqual(result['failure_stage'],'completion')
        self.assertFalse(result['accepted_review']);self.assertNotIn('private-secret-error',canonical(result).decode())
        with self.assertRaisesRegex(StateError,'reservation'):self.run_event()
        self.assertEqual(len(self.connection.calls),1);self.db.update_item.assert_called_once()


if __name__=='__main__':unittest.main()
