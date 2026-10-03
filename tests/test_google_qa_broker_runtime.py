import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
import test_google_qa_workflow as fixtures
from factory_runtime import google_qa_broker_runtime as runtime
from factory_runtime.review_preparation import PACKET, REVIEW, BOOTSTRAP
from factory_state.model import StateError, OWNER_IDENTITY
from factory_state.signers import public_key_der


class BrokerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.WorkflowTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.root=Path(self.f.directory.name)
        for name in (PACKET, REVIEW, BOOTSTRAP):
            path=self.root/name; path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((ROOT/name).read_bytes())
        (self.root/'BUILD.json').write_text(json.dumps({'source_commit':self.f.source}))
        registry={'schema_version':'1.0','enabled':True,'signers':[{
            'identity':OWNER_IDENTITY,'public_key_pem':self.f.keys[OWNER_IDENTITY].decode(),
            'fingerprint':'sha256:'+hashlib.sha256(public_key_der(self.f.keys[OWNER_IDENTITY])).hexdigest(),
            'enrollment_commit':'b'*40,'not_before':int(self.f.now.timestamp()),
            'expires_at':int(self.f.now.timestamp())+3600,'revoked':False}]}
        registry_raw=json.dumps(registry).encode()
        path=self.root/'factory/profiles/scope-signers.json'; path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(registry_raw)
        self.manifest={'activation_id':runtime.ACTIVATION,'pricing':self.f.pricing,
            'signer_registry_sha256':hashlib.sha256(registry_raw).hexdigest(),
            'secret_arn':runtime.SECRET_ARN,'secret_version':runtime.SECRET_VERSION}
        raw=json.dumps(self.manifest).encode(); (self.root/runtime.MANIFEST).write_bytes(raw)
        pin=patch.object(runtime,'ACTIVE_MANIFEST_SHA256',hashlib.sha256(raw).hexdigest())
        pin.start(); self.addCleanup(pin.stop)
        transport=patch.object(runtime,'GoogleQATransport',return_value=self.f.transport)
        transport.start(); self.addCleanup(transport.stop)
        self.clients={'sts':Mock(),'dynamodb':self.f.table,'secretsmanager':Mock()}
        self.clients['sts'].get_caller_identity.return_value={'Account':'666730517561','Arn':runtime.ROLE_PREFIX+'fixture'}
        def secret(**kwargs):
            self.assertEqual(kwargs,{'SecretId':runtime.SECRET_ARN,'VersionId':runtime.SECRET_VERSION,'VersionStage':'AWSCURRENT'})
            return {'ARN':runtime.SECRET_ARN,'VersionId':runtime.SECRET_VERSION,
                    'VersionStages':['AWSCURRENT'],'SecretString':self.f.load()}
        self.clients['secretsmanager'].get_secret_value.side_effect=secret
        self.factory=Mock(return_value=self.clients)
        self.event={'kind':'google_qa_review_once','source_commit':self.f.source,'allowance':self.f.signed()}
    def run_broker(self):
        return runtime.dispatch(self.event,root=self.root,clock=lambda:self.f.now,clients_factory=self.factory)

    def test_pinned_fixture_runs_in_exact_role_and_loads_exact_secret_after_hold(self):
        result=self.run_broker()
        self.assertEqual(result['status'],'GOOGLE_QA_COMPLETE_UNSIGNED')
        self.assertEqual(self.f.events,['reserve','credential','provider','complete'])
        self.clients['secretsmanager'].get_secret_value.assert_called_once()
        self.assertFalse(result['gate_authority'])
    def test_missing_production_pin_even_enabled_never_creates_clients(self):
        with patch.object(runtime,'ACTIVE_MANIFEST_SHA256',None):
            with self.assertRaises(StateError): self.run_broker()
        self.factory.assert_not_called()
    def test_changed_manifest_or_registry_never_creates_clients(self):
        for name in (runtime.MANIFEST,'factory/profiles/scope-signers.json'):
            path=self.root/name; before=path.read_bytes(); path.write_bytes(before+b' ')
            with self.assertRaises(StateError): self.run_broker()
            self.factory.assert_not_called(); path.write_bytes(before)
    def test_wrong_signature_event_or_unqualified_pricing_never_creates_clients(self):
        self.event['allowance']['payload']['approved_cap_micro_usd']=60000
        with self.assertRaises(StateError): self.run_broker()
        self.factory.assert_not_called()
        self.event['allowance']=self.f.signed(); self.event['extra']='attempt override'
        with self.assertRaises(StateError): self.run_broker()
        self.factory.assert_not_called()
        del self.event['extra']; self.manifest['pricing']['combined_output_bound_qualified']=False
        raw=json.dumps(self.manifest).encode(); (self.root/runtime.MANIFEST).write_bytes(raw)
        with patch.object(runtime,'ACTIVE_MANIFEST_SHA256',hashlib.sha256(raw).hexdigest()):
            with self.assertRaises(StateError): self.run_broker()
        self.factory.assert_not_called()
    def test_root_other_role_and_wrong_account_cannot_reserve_or_read_secret(self):
        for caller in ({'Account':'666730517561','Arn':'arn:aws:iam::666730517561:root'},
                       {'Account':'666730517561','Arn':runtime.ROLE_PREFIX+'bad/session'},
                       {'Account':'000000000000','Arn':runtime.ROLE_PREFIX+'fixture'}):
            self.clients['sts'].get_caller_identity.return_value=caller
            with self.assertRaises(StateError): self.run_broker()
            self.assertIsNone(self.f.table.item)
            self.clients['secretsmanager'].get_secret_value.assert_not_called()
    def test_wrong_secret_identity_stops_after_hold_without_provider_call(self):
        self.clients['secretsmanager'].get_secret_value.side_effect=None
        self.clients['secretsmanager'].get_secret_value.return_value={'ARN':'other','SecretString':'PRIVATE'}
        with self.assertRaises(StateError) as caught: self.run_broker()
        self.assertNotIn('PRIVATE',str(caught.exception))
        self.assertEqual(self.f.table.item['reservation_status'],{'S':'HELD'})
        self.f.transport.send_once.assert_not_called()
    def test_pricing_cannot_outlive_owner_enrollment(self):
        self.manifest['pricing']['expires_at']+=1
        raw=json.dumps(self.manifest).encode(); (self.root/runtime.MANIFEST).write_bytes(raw)
        with patch.object(runtime,'ACTIVE_MANIFEST_SHA256',hashlib.sha256(raw).hexdigest()):
            with self.assertRaises(StateError): self.run_broker()
        self.factory.assert_not_called()
    def test_disabled_handler_preserves_existing_boundary_probe(self):
        with patch.dict(os.environ,{'LAMBDA_TASK_ROOT':str(self.root),runtime.FLAG:'false'},clear=True):
            result=runtime.handler({'kind':'google_qa_broker_boundary_probe','source_commit':self.f.source},None)
            self.assertEqual(result['model_calls'],0); self.assertEqual(result['secret_reads'],0)
            with self.assertRaises(StateError): runtime.handler(self.event,None)
        self.factory.assert_not_called()

    def test_free_tier_proposal_signs_and_runs_only_under_fixture_authority(self):
        from prepare_google_qa_free_allowance import proposal
        self.f.free_tier(); self.manifest['pricing']=self.f.pricing
        raw=json.dumps(self.manifest).encode(); (self.root/runtime.MANIFEST).write_bytes(raw)
        with patch.object(runtime,'ACTIVE_MANIFEST_SHA256',hashlib.sha256(raw).hexdigest()):
            self.f.payload=proposal(self.root,source_commit=self.f.source,
                billing=self.f.payload['billing_evidence'],now=self.f.now)
            self.event['allowance']=self.f.signed()
            result=self.run_broker()
            self.assertEqual(result['status'],'GOOGLE_QA_COMPLETE_UNSIGNED')
            self.assertEqual(self.f.table.item['approved_cap_micro_usd'],{'N':'0'})
            self.assertEqual(self.f.transport.send_once.call_count,1)


if __name__=='__main__': unittest.main()
