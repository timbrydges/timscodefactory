import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from factory_runtime.review_signing import KEYS, ROLES, ReviewAllowanceSigner, ReviewRoleResultSigner
from factory_runtime.cloud_roles import ROLE_IDENTITIES
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.kms_signer import ALGORITHM
from factory_state.model import StateError
from factory_state.signers import public_key_der
from scripts.scope_dispatch_canary import fixture_keys, sign
from test_review_provider_scope import fixture, NOW


class ReviewSigningTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        identities = ('tim_brydges', *(ROLE_IDENTITIES[x] for x in ('builder','inspector','qa')))
        self.keys, self.private = fixture_keys(self.directory.name, identities)
        self.role = 'owner'; self.now = NOW; self.sign_calls = []
        self.public_hook = lambda: None
        self.sign_hook = lambda: None
        self.wrong_session = False; self.corrupt = False

    @property
    def identity(self):
        return 'tim_brydges' if self.role == 'owner' else ROLE_IDENTITIES[self.role]

    def get_caller_identity(self):
        role = 'wrong' if self.wrong_session else ROLES[self.role]
        return {'Account':'666730517561','Arn':'arn:aws:sts::666730517561:assumed-role/'+role+'/fixture'}

    def get_public_key(self, **kw):
        der = public_key_der(self.keys[self.identity]); self.public_hook()
        return {'KeyId':KEYS[self.role],'KeySpec':'ECC_NIST_EDWARDS25519',
                'KeyUsage':'SIGN_VERIFY','SigningAlgorithms':[ALGORITHM],'PublicKey':der}

    def sign(self, **kw):
        self.sign_calls.append(kw)
        signature = sign(json.loads(kw['Message']),self.private[self.identity],self.directory.name)
        self.sign_hook()
        return {'KeyId':KEYS[self.role],'SigningAlgorithm':ALGORITHM,
                'Signature': b'0'*64 if self.corrupt else signature}

    def signer(self, role='owner', enabled=True):
        self.role = role
        context = dict(kms=self,sts=self,key_loader=lambda now:dict(self.keys),
                       clock=lambda:self.now,enabled=enabled)
        scope,price,ready,payload = fixture('builder' if role=='owner' else role)
        if role=='owner':
            return ReviewAllowanceSigner(scope=scope,pricing=price,readiness=ready,**context),payload
        payload = {'kind':'role_result','factory_id':'tims-software-factory','task_id':'bounded-review-003',
            'binding':DynamoDBDispatchStore._binding(scope.request),'dispatch_id':'d'*64,
            'producer_identity':ROLE_IDENTITIES[role],'output_digest':'sha256:'+'e'*64,
            'issued_at':int(NOW.timestamp()),'expires_at':int(NOW.timestamp())+300}
        return ReviewRoleResultSigner(role=role,request=scope.request,dispatch_id='d'*64,**context),payload

    def test_owner_and_three_distinct_result_signatures(self):
        for role in KEYS:
            adapter,payload=self.signer(role)
            if role != 'owner':
                before = len(self.sign_calls)
                self.assertEqual(adapter.preflight(), ROLE_IDENTITIES[role])
                self.assertEqual(len(self.sign_calls), before)
                self.assertFalse(adapter.attempted)
            self.assertEqual(len(adapter.sign(payload,now=NOW)),64)
            self.assertEqual(self.sign_calls[-1]['KeyId'],KEYS[role])
            self.assertEqual(self.sign_calls[-1]['MessageType'],'RAW')
            with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        self.assertEqual(len(self.sign_calls),4)

    def test_disabled_has_no_remote_signature(self):
        adapter,payload=self.signer(enabled=False)
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        self.assertEqual(self.sign_calls,[])

    def test_old_scope_budget_increase_and_wrong_result_bindings_block(self):
        for role,changes in [('owner',{'kind':'handoff004_exact_request_allowance'}),
                ('owner',{'run_reserved_micro_usd':750001}),('qa',{'producer_identity':'tim_brydges'}),
                ('inspector',{'task_id':'authenticated-handoff-004'}),('builder',{'dispatch_id':'f'*64}),
                ('qa',{'binding':'{}'}),('qa',{'output_digest':'bad'}),
                ('qa',{'expires_at':int(NOW.timestamp())+301})]:
            adapter,payload=self.signer(role)
            with self.subTest(role=role,changes=changes),self.assertRaises(StateError):
                adapter.sign({**payload,**changes},now=NOW)
        self.assertEqual(self.sign_calls,[])

    def test_revocation_during_key_read_blocks_signature(self):
        adapter,payload=self.signer('qa')
        self.public_hook=lambda:self.keys.pop(self.identity)
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        self.assertEqual(self.sign_calls,[])
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)

    def test_fresh_clock_expiry_and_wrong_session_block(self):
        adapter,payload=self.signer()
        self.public_hook=lambda:setattr(self,'now',NOW+timedelta(hours=2))
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        self.now=NOW;self.public_hook=lambda:None;self.wrong_session=True
        adapter,payload=self.signer('qa')
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        self.assertEqual(self.sign_calls,[])

    def test_revocation_after_signing_and_corruption_fail_closed(self):
        adapter,payload=self.signer()
        self.sign_hook=lambda:self.keys.pop(self.identity)
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        self.sign_hook=lambda:None;self.corrupt=True
        adapter,payload=self.signer('qa')
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        self.assertEqual(len(self.sign_calls),2)

    def test_shared_identity_key_is_rejected_before_remote_sign(self):
        adapter,payload=self.signer()
        self.keys['qa_engineer_service']=self.keys['tim_brydges']
        with self.assertRaises(StateError): adapter.sign(payload,now=NOW)
        self.assertEqual(self.sign_calls,[])

    def test_concurrent_calls_sign_only_once(self):
        adapter,payload=self.signer('qa')
        def attempt():
            try:
                adapter.sign(payload,now=NOW)
                return 'signed'
            except StateError:
                return 'blocked'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:attempt(),range(2)))
        self.assertCountEqual(results,['signed','blocked'])
        self.assertEqual(len(self.sign_calls),1)
