import base64,copy,json
from datetime import datetime,timezone
from pathlib import Path
import unittest
from unittest.mock import Mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical
from factory_runtime import handoff003_qa_paid_recovery_authorization as a

ROOT=Path(__file__).resolve().parents[1]
class RecoveryAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,10,6,8,tzinfo=timezone.utc) # Old receipts are expired, historical evidence only.
        self.window={'issued_at':int(self.now.timestamp()),'expires_at':int(self.now.timestamp())+300}
        self.bound=a.bindings(ROOT,'a'*40)
        self.q={'kind':'handoff003_qa_paid_recovery002_rate_qualification',**self.bound,**self.window,
            'complete_request_bound_qualified':True,'input_token_bound':32768,'output_token_bound':4096,
            'input_micro_usd_per_million':750000,'output_micro_usd_per_million':3750000,'evidence_digest':'sha256:'+'1'*64}
        self.r={'kind':'handoff003_qa_paid_recovery002_readiness',**self.bound,**self.window,'credential_route_verified':True,
            'paid_tier_verified':True,'google_project_id':'gen-lang-client-0247455615',
            'model_metadata_verified':True,'repository_binding_verified':True,'single_attempt_failure_risk_accepted':True,'evidence_digest':'sha256:'+'2'*64}
        self.args=dict(root=ROOT,source_commit='a'*40,qualification=self.q,readiness=self.r,now=self.now)
        self.payload=a.draft(**self.args,**self.window)
        from factory_runtime.handoff003_protocols import request_bytes
        builder=json.loads((ROOT/'factory/evidence/handoff-003-live/builder-live-result.json').read_bytes())
        self.args['request_bytes']=request_bytes(ROOT,role='qa',builder_response=base64.b64decode(builder['output_base64']),candidate_commit='994719a384b7ac96abeb67e4b2addcab2deb4763')
        self.private=Ed25519PrivateKey.generate()
        self.keys={OWNER_IDENTITY:self.private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)}
    def signed(self,payload=None):
        p=payload or self.payload
        return {'payload':p,'signature':base64.b64encode(self.private.sign(canonical(p))).decode()}
    def test_historical_evidence_never_substitutes_for_fresh_owner_signature(self):
        self.assertEqual(self.payload['qualified_maximum_micro_usd'],39936)
        for envelope in ({'payload':self.payload,'signature':''},json.loads((ROOT/'factory/evidence/handoff-003-live/inspector-live-result.json').read_bytes())):
            with self.assertRaises(StateError):a.verify(envelope,**self.args,trusted_keys=self.keys)
        result=a.verify(self.signed(),**self.args,trusted_keys=self.keys)
        self.assertEqual(result['role'],'qa')
        self.assertFalse(self.payload['prior_hold_release_authorized'])
    def test_even_signed_old_namespace_retry_or_larger_cap_is_rejected(self):
        for field,value in (('attempt_table','tims-factory-handoff-003-attempts'),('retries',1),('approved_cap_micro_usd',300000),('transport_timeout_seconds',600)):
            with self.subTest(field=field):
                p={**self.payload,field:value}
                with self.assertRaises(StateError):a.verify(self.signed(p),**self.args,trusted_keys=self.keys)
    def test_stale_or_excessive_price_stops_before_any_claim(self):
        for q in ({**self.q,'expires_at':int(self.now.timestamp())},{**self.q,'input_micro_usd_per_million':1000000000}):
            with self.assertRaises(StateError):a.verify(self.signed(),**{**self.args,'qualification':q},trusted_keys=self.keys)
        with self.assertRaisesRegex(StateError,'request bytes'):
            a.verify(self.signed(),**{**self.args,'request_bytes':self.args['request_bytes']+b' '},trusted_keys=self.keys)
    def test_permanent_isolated_claim_cannot_be_reused_or_address_original(self):
        args=a.verify(self.signed(),**self.args,trusted_keys=self.keys);db=Mock()
        db.put_item.side_effect=[{},TimeoutError('outcome unknown')]
        store=a.RecoveryAttemptStore(db)
        store.begin(**args)
        with self.assertRaisesRegex(StateError,'uncertain'):store.begin(**args)
        call=db.put_item.call_args.kwargs
        self.assertEqual(call['TableName'],a.TABLE)
        self.assertEqual(call['Item']['PK'],{'S':a.PK})
        self.assertEqual(call['ConditionExpression'],'attribute_not_exists(PK)')
        self.assertEqual(call['Item']['reserved_micro_usd'],{'N':'250000'})
        with self.assertRaises(StateError):a.key('builder')

    def test_unpaid_project_or_prior_recovery_namespace_cannot_authorize(self):
        for field,value in (('paid_tier_verified',False),('google_project_id','different-project')):
            with self.subTest(field=field),self.assertRaises(StateError):
                a.verify(self.signed(),**{**self.args,'readiness':{**self.r,field:value}},trusted_keys=self.keys)
        old={**self.payload,'attempt_table':'tims-factory-handoff-003-qa-recovery-001-attempts'}
        with self.assertRaises(StateError):a.verify(self.signed(old),**self.args,trusted_keys=self.keys)
