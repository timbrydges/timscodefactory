import base64
import copy
import hashlib
import unittest
from datetime import datetime,timedelta,timezone
from unittest.mock import Mock,patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import test_pilot002_protocols as protocols
import test_pilot002_transport as transports
from factory_runtime import pilot002_adapter as p
from factory_runtime.pilot002_attempts import Pilot002AttemptStore
from factory_runtime.pilot002_packets import digest
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.fixtures=protocols.ProtocolTests();self.fixtures.setUp()
        self.now=datetime(2026,10,3,19,tzinfo=timezone.utc);self.clock=Mock(return_value=self.now)
        self.private=Ed25519PrivateKey.generate()
        self.keys={OWNER_IDENTITY:self.private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)}

    def setup_role(self,role='builder',enabled=True):
        context={'root':protocols.ROOT,**self.fixtures.context(role),'source_commit':'c'*40}
        packet=p._packet(protocols.ROOT,role,context.get('builder_response'),context.get('candidate_commit'))
        raw=p.request_bytes(protocols.ROOT,**self.fixtures.context(role))
        bindings={k:packet[k] for k in ('role','model_id','task_id','contract_digest','packet_digest')}
        bindings.update(source_commit='c'*40,request_digest='sha256:'+hashlib.sha256(raw).hexdigest())
        epoch=int(self.now.timestamp())
        q={'kind':'pilot002_provider_rate_qualification',**bindings,'currency':'USD',
            'complete_request_bound_qualified':True,'combined_output_bound_qualified':True,
            'standard_text_only_no_cache_rates':True,'input_token_bound':32768,'output_token_bound':4096,
            'input_micro_usd_per_million':1000000,'output_micro_usd_per_million':2000000,
            'issued_at':epoch,'expires_at':epoch+3600,'evidence_digest':'sha256:'+'a'*64}
        adapter=p.Pilot002Adapter(**context,qualification=q,clock=self.clock,enabled=enabled)
        ready={'kind':'pilot002_provider_readiness',**bindings,'credential_route_verified':True,
            'model_access_verified':True,'repository_binding_verified':True,
            'issued_at':epoch,'expires_at':epoch+900,'evidence_digest':'sha256:'+'b'*64}
        payload={'kind':'pilot002_exact_request_allowance','owner_identity':OWNER_IDENTITY,**bindings,
            'pricing_digest':digest(adapter.pricing),'readiness_digest':digest(ready),
            'reserved_micro_usd':250000,'approved_cap_micro_usd':250000,'maximum_provider_calls':1,
            'retries':0,'task_state_writes':0,'gate_authority':False,'production_release_authorized':False,
            'issued_at':epoch,'expires_at':epoch+600}
        envelope={'payload':payload,'signature':base64.b64encode(self.private.sign(canonical(payload))).decode()}
        self.events=[];self.rows={};db=Mock()
        def claim(**args):
            self.events.append('claim');key=args['Item']['PK']['S']
            if key in self.rows:raise RuntimeError('already used')
            self.rows[key]=args['Item']
        db.put_item.side_effect=claim;db.update_item.side_effect=lambda **kw:self.events.append('complete')
        credential=transports.AWS if role=='inspector' else transports.KEY
        load=Mock(side_effect=lambda:(self.events.append('credential') or credential))
        args={**context,'qualification':q,'readiness':ready,'trusted_keys':self.keys,
            'store':Pilot002AttemptStore(db),'load_credential':load,'clock':self.clock,'enabled':True}
        return adapter,packet,raw,q,envelope,args,db

    def test_full_composition_three_roles_claim_before_send(self):
        for role in ('builder','inspector','qa'):
            _,_,_,_,envelope,args,db=self.setup_role(role)
            connection=transports.Connection(transports.Response(canonical(self.fixtures.response(role))))
            original=connection.request
            def send(*a,**kw):self.events.append('send');return original(*a,**kw)
            connection.request=send
            with self.subTest(role=role),patch.object(transports.p.http.client,'HTTPSConnection',return_value=connection):
                result=p.run_bound_once(envelope,**args)
                self.assertEqual(self.events,['claim','credential','send','complete'])
                self.assertEqual(result['actual_micro_usd'],160)
                self.assertFalse(result['gate_authority']);self.assertEqual(result['reservation_status'],'HELD')
                self.assertEqual(next(iter(self.rows.values()))['reserved_micro_usd'],{'N':'250000'})
                with self.assertRaisesRegex(StateError,'reservation'):p.run_bound_once(envelope,**args)
                self.assertEqual(len(connection.calls),1)

    def test_changed_rate_invalidates_signature_even_if_rounded_maximum_equal(self):
        _,_,_,_,envelope,args,db=self.setup_role()
        args['qualification']['input_micro_usd_per_million']-=1
        with patch.object(transports.p.http.client,'HTTPSConnection') as connect:
            with self.assertRaisesRegex(StateError,'authorization'):p.run_bound_once(envelope,**args)
            db.put_item.assert_not_called();args['load_credential'].assert_not_called();connect.assert_not_called()

    def test_disabled_wrapper_has_no_dependency_calls(self):
        with self.assertRaisesRegex(StateError,'disabled'):
            p.run_bound_once(None,root=None,role=None,source_commit=None,qualification=None,readiness=None,
                trusted_keys=None,store=None,load_credential=None,clock=None)

    def test_unobserved_or_substituted_response_rejected(self):
        adapter,packet,raw,_,_,args,_=self.setup_role()
        response=canonical(self.fixtures.response('builder'))
        with self.assertRaisesRegex(StateError,'not returned'):adapter.parse_response(response,packet)
        with patch.object(transports.p.http.client,'HTTPSConnection',return_value=transports.Connection(transports.Response(response))):
            adapter.send_once(request_bytes=raw,credential=transports.KEY,expected_request_digest=p._hash(raw))
        self.assertEqual(adapter.parse_response(response,packet)['actual_micro_usd'],160)
        with self.assertRaisesRegex(StateError,'not returned'):adapter.parse_response(response+b' ',packet)

    def test_quote_snapshot_and_returned_pricing_are_isolated(self):
        adapter,packet,_,q,_,_,_=self.setup_role()
        before=adapter.pricing;q['input_micro_usd_per_million']=0
        exposed=adapter.pricing;exposed['maximum_cost_micro_usd']=0
        self.assertEqual(adapter.pricing,before)
        altered=copy.deepcopy(packet);altered['instructions']='replace rules'
        with self.assertRaisesRegex(StateError,'packet differs'):adapter.build_request(altered)

    def test_unqualified_changed_zero_and_over_cap_rates_rejected(self):
        _,_,_,q,_,args,_=self.setup_role()
        context={k:args[k] for k in ('root','role','source_commit')}
        for changes in ({'combined_output_bound_qualified':False},{'input_token_bound':True},
                        {'output_token_bound':4095},{'model_id':'different'},
                        {'input_micro_usd_per_million':1.1},{'input_micro_usd_per_million':-1},
                        {'input_micro_usd_per_million':1000000000},
                        {'input_micro_usd_per_million':0,'output_micro_usd_per_million':0},
                        {'expires_at':q['issued_at']},{'evidence_digest':'unverified'}):
            with self.subTest(changes=changes),self.assertRaises(StateError):
                p.Pilot002Adapter(**context,qualification={**q,**changes},clock=self.clock)

    def test_rounding_is_conservative_at_micro_usd_precision(self):
        self.assertEqual(p._cost(1,1,{'input_micro_usd_per_million':1,'output_micro_usd_per_million':1}),1)
        self.assertEqual(p._cost(100,30,{'input_micro_usd_per_million':1000000,'output_micro_usd_per_million':2000000}),160)

    def test_expired_quote_stops_before_send_and_does_not_reopen_latch(self):
        adapter,_,raw,_,_,_,_=self.setup_role()
        self.clock.return_value=self.now+timedelta(hours=2)
        with patch.object(transports.p.http.client,'HTTPSConnection') as connect:
            with self.assertRaisesRegex(StateError,'expired'):
                adapter.send_once(request_bytes=raw,credential=transports.KEY,expected_request_digest=p._hash(raw))
            self.clock.return_value=self.now
            with self.assertRaisesRegex(StateError,'already attempted'):
                adapter.send_once(request_bytes=raw,credential=transports.KEY,expected_request_digest=p._hash(raw))
            connect.assert_not_called()

    def test_transport_failure_retains_permanent_claim(self):
        _,_,_,_,envelope,args,db=self.setup_role()
        connection=transports.Connection(error=TimeoutError('private'))
        with patch.object(transports.p.http.client,'HTTPSConnection',return_value=connection):
            with self.assertRaisesRegex(StateError,'provider'):p.run_bound_once(envelope,**args)
            with self.assertRaisesRegex(StateError,'reservation'):p.run_bound_once(envelope,**args)
        self.assertEqual(len(connection.calls),1);db.update_item.assert_not_called()
        self.assertEqual(len(self.rows),1)

    def test_observed_usage_over_qualified_input_bound_rejected(self):
        _,packet,raw,q,_,args,_=self.setup_role();q['input_token_bound']=99
        adapter=p.Pilot002Adapter(root=args['root'],role='builder',source_commit=args['source_commit'],
            qualification=q,clock=self.clock,enabled=True)
        response=canonical(self.fixtures.response('builder'))
        with patch.object(transports.p.http.client,'HTTPSConnection',return_value=transports.Connection(transports.Response(response))):
            adapter.send_once(request_bytes=raw,credential=transports.KEY,expected_request_digest=p._hash(raw))
        with self.assertRaisesRegex(StateError,'input exceeds'):adapter.parse_response(response,packet)

    def test_completion_can_record_cost_after_timely_response(self):
        adapter,packet,raw,_,_,_,_=self.setup_role()
        response=canonical(self.fixtures.response('builder'))
        with patch.object(transports.p.http.client,'HTTPSConnection',return_value=transports.Connection(transports.Response(response))):
            adapter.send_once(request_bytes=raw,credential=transports.KEY,expected_request_digest=p._hash(raw))
        self.clock.return_value=self.now+timedelta(hours=2)
        self.assertEqual(adapter.parse_response(response,packet)['actual_micro_usd'],160)


if __name__=='__main__':unittest.main()
