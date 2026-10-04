import base64
import copy
import json
import unittest
from datetime import datetime,timedelta
from pathlib import Path
from unittest.mock import Mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from factory_runtime import inspector_recovery001_authorization as p
from factory_runtime.inspector_recovery001 import RecoveryAttemptStore
from factory_runtime.pilot002_protocols import request_bytes
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical

ROOT=Path(__file__).resolve().parents[1]


class RecoveryAuthorizationTests(unittest.TestCase):
    def setUp(self):
        # Historical public context plus synthetic local signing key: no live authority.
        plan=json.loads((ROOT/'factory/evidence/pilot-002-inspector-live-review-candidate.json').read_bytes())
        doc=plan['activation'];builder=base64.b64decode(doc['builder_response_base64'])
        self.key=Ed25519PrivateKey.generate()
        keys={OWNER_IDENTITY:self.key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)}
        self.args={'root':ROOT,'request_bytes':request_bytes(ROOT,role='inspector',builder_response=builder,candidate_commit=p.CANDIDATE),
            'source_commit':doc['source_commit'],'pricing':plan['pricing'],'readiness':doc['readiness'],
            'trusted_keys':keys,'now':datetime.fromisoformat(plan['prepared_at']),
            'builder_response':builder,'candidate_commit':p.CANDIDATE}
        self.old=copy.deepcopy(plan['allowance_payload'])
        self.payload={**self.old,'kind':p.KIND,'candidate_commit':p.CANDIDATE,
            'recovery_scope_digest':'sha256:'+p.SCOPE_SHA256,'attempt_table':p.TABLE,'attempt_key':p.PK,
            'capture_failed_review_response':True,'maximum_captured_response_bytes':262144}

    def sign(self,payload=None,key=None):
        payload=self.payload if payload is None else payload
        return {'payload':payload,'signature':base64.b64encode((key or self.key).sign(canonical(payload))).decode()}

    def test_verified_claim_targets_only_recovery_table(self):
        args=p.verify(self.sign(),**self.args)
        db=Mock();RecoveryAttemptStore(db,root=ROOT,enabled=True).begin(**args)
        call=db.put_item.call_args.kwargs
        self.assertEqual(call['TableName'],p.TABLE)
        self.assertEqual(call['Item']['PK'],{'S':p.PK})
        self.assertEqual(call['Item']['approval_digest']['S'],p.digest(canonical(self.payload)))
        self.assertEqual(call['Item']['maximum_cost_micro_usd']['N'],'159744')

    def test_old_pilot_signature_cannot_authorize_recovery(self):
        with self.assertRaisesRegex(StateError,'scope'):p.verify(self.sign(self.old),**self.args)

    def test_signed_scope_expansion_or_wrong_record_fails(self):
        changes=({'maximum_provider_calls':2},{'retries':1},{'gate_authority':True},
            {'capture_failed_review_response':False},{'maximum_captured_response_bytes':262145},
            {'attempt_table':'tims-factory-pilot-002-attempts'},{'attempt_key':'other'},
            {'recovery_scope_digest':'sha256:'+'0'*64},{'candidate_commit':'0'*40},
            {'approved_cap_micro_usd':250001},{'reserved_micro_usd':True},{'role':'qa'},
            {'source_commit':'0'*40},{'extra':'override'})
        for change in changes:
            with self.subTest(change=change),self.assertRaises(StateError):
                p.verify(self.sign({**self.payload,**change}),**self.args)

    def test_tampered_wrong_key_and_missing_owner_signatures_fail(self):
        envelope=self.sign();envelope['payload']=copy.deepcopy(envelope['payload']);envelope['payload']['expires_at']-=1
        for value,keys in ((envelope,self.args['trusted_keys']),
                           (self.sign(key=Ed25519PrivateKey.generate()),self.args['trusted_keys']),
                           (self.sign(),{})):
            with self.assertRaises(StateError):p.verify(value,**{**self.args,'trusted_keys':keys})

    def test_changed_request_candidate_or_builder_context_fails(self):
        for change in ({'request_bytes':self.args['request_bytes']+b' '},
                       {'candidate_commit':'0'*40},{'builder_response':self.args['builder_response']+b' '},
                       {'source_commit':'main'},{'now':self.args['now'].replace(tzinfo=None)}):
            with self.subTest(change=list(change)),self.assertRaises(StateError):
                p.verify(self.sign(),**{**self.args,**change})

    def test_expired_allowance_price_and_readiness_fail_closed(self):
        with self.assertRaises(StateError):p.verify(self.sign(),**{**self.args,'now':self.args['now']+timedelta(hours=2)})
        for field in ('pricing','readiness'):
            stale=copy.deepcopy(self.args[field]);stale['expires_at']=int(self.args['now'].timestamp())
            with self.assertRaises(StateError):p.verify(self.sign(),**{**self.args,field:stale})
        over=copy.deepcopy(self.args['pricing']);over['maximum_cost_micro_usd']=250001
        with self.assertRaises(StateError):p.verify(self.sign(),**{**self.args,'pricing':over})


if __name__=='__main__':unittest.main()
