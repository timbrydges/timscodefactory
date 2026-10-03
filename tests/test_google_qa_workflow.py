import base64
import concurrent.futures
import copy
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from scope_dispatch_canary import fixture_keys, sign
from factory_state.model import StateError, OWNER_IDENTITY
from factory_state.scope import canonical
from factory_runtime.google_qa import ENDPOINT, MODEL, GoogleQATransport, request_body
from factory_runtime.google_qa_authorization import verify, digest
from factory_runtime.google_qa_boundary import ACTIVATION, KEY, TABLE, GoogleQaAttemptStore
from factory_runtime.google_qa_reservation import GoogleQaReservedAttemptStore
from factory_runtime.google_qa_workflow import run_once
from factory_runtime.review_preparation import BINDING, prepare


class Table:
    def __init__(self, events):
        self.events=events; self.lock=threading.Lock(); self.item=None; self.fail=None
    def put_item(self, **kwargs):
        with self.lock:
            self.events.append('reserve')
            assert kwargs['TableName']==TABLE
            assert kwargs['ConditionExpression']=='attribute_not_exists(PK) AND attribute_not_exists(SK)'
            if self.item is not None: raise RuntimeError('duplicate')
            self.item=copy.deepcopy(kwargs['Item'])
            if self.fail=='reservation': raise TimeoutError('PRIVATE')
    def update_item(self, **kwargs):
        self.events.append('complete')
        assert kwargs['TableName']==TABLE and kwargs['Key']==KEY
        assert kwargs['ConditionExpression']=='#s=:started AND request_digest=:digest'
        assert self.item['request_digest']==kwargs['ExpressionAttributeValues'][':digest']
        assert self.item['status']=={'S':'STARTED'}
        if self.fail=='completion': raise TimeoutError('PRIVATE')
        self.item['status']={'S':'COMPLETE'}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,10,3,tzinfo=timezone.utc)
        self.packet=prepare(ROOT,role='qa'); self.source='a'*40
        self.directory=tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.keys,self.private=fixture_keys(self.directory.name,(OWNER_IDENTITY,))
        self.sign_lock=threading.Lock()
        self.pricing={'kind':'google_qa_pricing_envelope','model_id':MODEL,'endpoint':ENDPOINT,
            'currency':'USD','maximum_input_tokens':32768,'maximum_output_tokens_including_thinking':4096,
            'combined_output_bound_qualified':True,'input_micro_usd_per_million_tokens':750000,
            'output_micro_usd_per_million_tokens':3750000,'evidence_digest':'sha256:'+'c'*64,
            'issued_at':int(self.now.timestamp()),'expires_at':int(self.now.timestamp())+3600}
        self.payload={'kind':'google_qa_allowance','owner_identity':OWNER_IDENTITY,'activation_id':ACTIVATION,
            'source_commit':self.source,'model_id':MODEL,'endpoint':ENDPOINT,
            **{k:self.packet[k] for k in ('candidate_commit','contract_digest','packet_digest')},
            'request_digest':'sha256:'+hashlib.sha256(request_body(self.packet,root=ROOT)).hexdigest(),
            'pricing_digest':digest(self.pricing),'reserved_micro_usd':39936,'approved_cap_micro_usd':50000,
            'maximum_provider_calls':1,'retries':0,'task_state_writes':0,'gate_authority':False,
            'production_release_authorized':False,'issued_at':int(self.now.timestamp()),
            'expires_at':int(self.now.timestamp())+1800}
        self.events=[]; self.table=Table(self.events)
        self.store=GoogleQaReservedAttemptStore(TABLE,self.table)
        self.loader=Mock(side_effect=self.load)
        self.transport=Mock(); self.transport.send_once.side_effect=self.send
        assessment={**{k:self.packet[k] for k in BINDING},'verdict':'ACCEPTED','rationale':'Fixture only','findings':[]}
        self.raw=canonical({'modelVersion':MODEL,'candidates':[{'finishReason':'STOP',
            'content':{'role':'model','parts':[{'text':json.dumps(assessment)}]}}],
            'usageMetadata':{'promptTokenCount':2931,'candidatesTokenCount':100,'totalTokenCount':3031}})
    def signed(self):
        with self.sign_lock:
            signature=sign(self.payload,self.private[OWNER_IDENTITY],self.directory.name)
        return {'payload':copy.deepcopy(self.payload),'signature':base64.b64encode(signature).decode()}
    def load(self):
        self.events.append('credential'); return 'fixture-only-not-a-real-key'
    def send(self,*args,**kwargs):
        self.events.append('provider')
        self.assertEqual(kwargs['expected_request_digest'],self.payload['request_digest'])
        return self.raw
    def run_workflow(self,**overrides):
        args=dict(root=ROOT,source_commit=self.source,pricing=self.pricing,trusted_keys=self.keys,
            store=self.store,load_key=self.loader,transport=self.transport,clock=lambda:self.now)
        args.update(overrides)
        return run_once(self.signed(),**args)
    def verify(self,envelope=None):
        return verify(self.signed() if envelope is None else envelope,packet=self.packet,root=ROOT,
            source_commit=self.source,pricing=self.pricing,trusted_keys=self.keys,now=self.now)

    def free_tier(self):
        self.pricing.update(kind='google_qa_free_tier_policy',combined_output_bound_qualified=False,
            billing_mode='UNLINKED_FREE_TIER',google_project='gen-lang-client-0247455615',
            input_micro_usd_per_million_tokens=0,output_micro_usd_per_million_tokens=0)
        self.payload.update(pricing_digest=digest(self.pricing),reserved_micro_usd=0,approved_cap_micro_usd=0,
            expires_at=int(self.now.timestamp())+300,billing_evidence={
                'google_project':'gen-lang-client-0247455615','billing_account_linked':False,
                'observed_at':int(self.now.timestamp()),'evidence_digest':'sha256:'+'e'*64})

    def test_free_tier_zero_dollar_claim_is_bound_and_reconcilable(self):
        from factory_runtime.google_qa_reconcile import inspect_item
        self.free_tier(); self.run_workflow()
        self.assertEqual(self.table.item['reserved_micro_usd'],{'N':'0'})
        self.assertEqual(self.table.item['billing_mode'],{'S':'UNLINKED_FREE_TIER'})
        # Mock ledger omits the response; inspect its still-valid STARTED form.
        item={**self.table.item,'status':{'S':'STARTED'}}
        result=inspect_item(item,root=ROOT,source_commit=self.source,observed_at=self.now+timedelta(hours=1))
        self.assertEqual(result['billing_mode'],'UNLINKED_FREE_TIER')
        self.assertFalse(result['retry_authorized'])
        with self.assertRaises(StateError): self.run_workflow()
        self.assertEqual(self.transport.send_once.call_count,1)

    def test_free_tier_linked_stale_future_wrong_project_and_nonzero_cap_rejected(self):
        self.free_tier(); original=copy.deepcopy(self.payload)
        for field,value in [('billing_account_linked',True),('observed_at',int(self.now.timestamp())-301),
                            ('observed_at',int(self.now.timestamp())+1),('google_project','other'),('evidence_digest','bad')]:
            self.payload=copy.deepcopy(original); self.payload['billing_evidence'][field]=value
            with self.subTest(field=field),self.assertRaises(StateError): self.run_workflow()
            self.assertEqual(self.events,[])
        self.payload=copy.deepcopy(original); self.payload['approved_cap_micro_usd']=1
        with self.assertRaises(StateError): self.run_workflow()
        self.assertEqual(self.events,[])

    def test_free_tier_cannot_disguise_paid_prices_or_unbound_zero_reservations(self):
        self.free_tier(); self.pricing['output_micro_usd_per_million_tokens']=1
        self.payload['pricing_digest']=digest(self.pricing)
        with self.assertRaises(StateError): self.run_workflow()
        self.assertEqual(self.events,[])
        self.free_tier(); args=self.verify()
        for field in ('billing_evidence_digest','billing_verified_at'):
            bad={**args}; del bad[field]
            with self.assertRaises(StateError): self.store.begin(**bad)
        self.assertIsNone(self.table.item)

    def test_signed_workflow_orders_effects_and_retains_hold(self):
        result=self.run_workflow()
        self.assertEqual(self.events,['reserve','credential','provider','complete'])
        self.assertEqual(result['status'],'GOOGLE_QA_COMPLETE_UNSIGNED')
        self.assertFalse(result['gate_authority'])
        self.assertEqual(self.table.item['reserved_micro_usd'],{'N':'39936'})
        self.assertEqual(self.table.item['reservation_status'],{'S':'HELD'})
        self.assertEqual(self.table.item['status'],{'S':'COMPLETE'})
        self.loader.assert_called_once()

    def test_workflow_result_flows_into_independent_qa_bundle_without_a_second_call(self):
        from factory_runtime.qa_execution import execute
        from factory_runtime.qa_evidence import combine
        result=self.run_workflow()
        bundle=combine(execute(ROOT),self.packet,root=ROOT,google_record=canonical(result['response']))
        self.assertEqual(bundle['review_status'],'READY_FOR_INDEPENDENT_PUBLICATION_REVIEW')
        self.assertFalse(bundle['gate_authority'])
        self.assertEqual(self.transport.send_once.call_count,1)
    def test_tampered_or_wrong_key_signature_never_reaches_reservation(self):
        envelope=self.signed(); envelope['payload']['approved_cap_micro_usd']=60000
        with self.assertRaises(StateError): self.verify(envelope)
        other,_=fixture_keys(self.directory.name,('other-owner',))
        self.keys={OWNER_IDENTITY:other['other-owner']}
        with self.assertRaises(StateError): self.run_workflow()
        self.assertEqual(self.events,[])
    def test_even_signed_wrong_scope_or_expired_allowance_is_rejected(self):
        original=copy.deepcopy(self.payload)
        for field,value in [('activation_id','other'),('source_commit','b'*40),('retries',1),
            ('maximum_provider_calls',True),('approved_cap_micro_usd',39935),('approved_cap_micro_usd',1000001),
            ('reserved_micro_usd',39935),('request_digest','sha256:'+'d'*64),('gate_authority',True),
            ('expires_at',int(self.now.timestamp())),('issued_at',int(self.now.timestamp())+1)]:
            self.payload={**original,field:value}
            with self.subTest(field=field),self.assertRaises(StateError): self.run_workflow()
            self.assertEqual(self.events,[])
    def test_unqualified_pricing_and_rounding(self):
        self.pricing['combined_output_bound_qualified']=False
        self.payload['pricing_digest']=digest(self.pricing)
        with self.assertRaises(StateError): self.run_workflow()
        self.assertEqual(self.events,[])
        self.pricing['combined_output_bound_qualified']=True
        self.pricing['input_micro_usd_per_million_tokens']=750001
        self.payload['pricing_digest']=digest(self.pricing)
        self.payload['reserved_micro_usd']=39937
        self.assertEqual(self.verify()['reserved_micro_usd'],39937)
    def test_every_uncertain_stage_stops_without_retry_or_release(self):
        for stage in ('reservation','credential','provider','response','completion'):
            self.setUp(); self.table.fail=stage
            if stage=='credential': self.loader.side_effect=TimeoutError('PRIVATE')
            elif stage=='provider': self.transport.send_once.side_effect=TimeoutError('PRIVATE')
            elif stage=='response': self.raw=b'invalid response'
            with self.subTest(stage=stage),self.assertRaises(StateError) as caught: self.run_workflow()
            self.assertNotIn('PRIVATE',str(caught.exception))
            self.assertEqual(self.table.item['reservation_status'],{'S':'HELD'})
            self.assertLessEqual(self.loader.call_count,1); self.assertLessEqual(self.transport.send_once.call_count,1)
            if stage=='reservation': self.loader.assert_not_called()
            # A fresh workflow object or a later clock never permits a replay.
            with self.assertRaises(StateError): self.run_workflow()
            self.assertLessEqual(self.transport.send_once.call_count,1)
    def test_expiry_during_credential_read_prevents_send_but_keeps_hold(self):
        times=iter([self.now,self.now+timedelta(hours=1)])
        with self.assertRaises(StateError): self.run_workflow(clock=lambda:next(times))
        self.assertEqual(self.events,['reserve','credential'])
        self.transport.send_once.assert_not_called()
        self.assertEqual(self.table.item['reservation_status'],{'S':'HELD'})
    def test_concurrent_workflows_send_only_once(self):
        def attempt(_):
            try: self.run_workflow(); return True
            except StateError: return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(attempt,range(12))),1)
        self.assertEqual(self.loader.call_count,1); self.assertEqual(self.transport.send_once.call_count,1)
    def test_legacy_store_and_changed_transport_bytes_are_rejected(self):
        with self.assertRaises(StateError): self.run_workflow(store=GoogleQaAttemptStore(TABLE,Mock()))
        opener=Mock(); transport=GoogleQATransport(opener=opener)
        with self.assertRaises(StateError):
            transport.send_once(self.packet,root=ROOT,api_key='fixture-key-value',expected_request_digest='sha256:'+'0'*64)
        opener.open.assert_not_called()


if __name__=='__main__': unittest.main()
