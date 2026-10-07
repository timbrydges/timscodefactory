import base64
import copy
from dataclasses import replace
from datetime import timedelta
import tempfile
import unittest
from factory_state.dispatch import DispatchRequest
from factory_state.model import StateError
from factory_state.scope import canonical
from factory_runtime.worker import digest
from factory_runtime.review_provider_scope import ProviderScope, verify
from scripts.scope_dispatch_canary import fixture_keys, sign
from test_autonomous_scheduler import NOW


def fixture(role='builder'):
    request=DispatchRequest('lease-'+role,'bounded-review-004','bounded-review', 'a'*40,
                            digest(b'contract'),digest(b'input-'+role.encode()))
    scope=ProviderScope(role,request,'b'*40,digest(b'candidate'),digest(b'tests'),b'exact request '+role.encode())
    times={'issued_at':int(NOW.timestamp())-1,'expires_at':int(NOW.timestamp())+600}
    pricing={'kind':'bounded_review004_rate_qualification',**scope.bindings(),'currency':'USD',
        'complete_request_bound_qualified':True,'standard_text_only_no_cache_rates':True,
        'input_token_bound':32768,'output_token_bound':4096,'input_micro_usd_per_million':{'builder':4000000,'inspector':3000000,'qa':750000}[role],
        'output_micro_usd_per_million':{'builder':20000000,'inspector':15000000,'qa':3750000}[role],'evidence_digest':digest(b'fixture quote'),**times}
    readiness={'kind':'bounded_review004_provider_readiness',**scope.bindings(),
        'credential_route_verified':True,'model_metadata_verified':True,'repository_binding_verified':True,
        'single_attempt_failure_risk_accepted':True,'evidence_digest':digest(b'fixture readiness'),**times}
    payload={'kind':'bounded_review004_provider_allowance','owner_identity':'tim_brydges',**scope.bindings(),
        'pricing_digest':digest(canonical(pricing)),'readiness_digest':digest(canonical(readiness)),
        'reserved_micro_usd':{'builder':250000,'inspector':175000,'qa':75000}[role],'run_reserved_micro_usd':500000,'aggregate_ceiling_micro_usd':3250000,
        'maximum_provider_calls':1,'retries':0,'production_release_authorized':False,**times}
    return scope,pricing,readiness,payload


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.keys,self.private=fixture_keys(self.directory.name)

    def verify(self,scope,pricing,readiness,payload,*,signer='tim_brydges',keys=None,now=NOW):
        envelope={'payload':payload,'signature_base64':base64.b64encode(
            sign(payload,self.private[signer],self.directory.name)).decode()}
        return verify(envelope,scope=scope,pricing=pricing,readiness=readiness,now=now,
                      trusted_keys=self.keys if keys is None else keys)

    def test_three_distinct_fixed_provider_routes_and_exact_signed_scope(self):
        providers=set()
        for role in ('builder','inspector','qa'):
            data=fixture(role);grant=self.verify(*data);providers.add(data[0].bindings()['provider'])
            self.assertEqual(grant.role,role);self.assertEqual(grant.maximum_cost_micro_usd,{'builder':212992,'inspector':159744,'qa':39936}[role])
        self.assertEqual(providers,{'openai','bedrock','google'})

    def test_role_reservations_cannot_be_swapped_or_enlarged(self):
        for role,cap in {'builder':250000,'inspector':175000,'qa':75000}.items():
            scope,price,ready,payload=fixture(role)
            for changed in ({'reserved_micro_usd':cap+1},{'run_reserved_micro_usd':750000},
                            {'aggregate_ceiling_micro_usd':3500000}):
                with self.subTest(role=role,changed=changed),self.assertRaises(StateError):
                    self.verify(scope,price,ready,{**payload,**changed})
            price['output_micro_usd_per_million']=1000000000
            with self.assertRaises(StateError):self.verify(scope,price,ready,payload)

    def test_wrong_signer_revocation_and_expiry_block(self):
        data=fixture()
        with self.assertRaises(StateError):self.verify(*data,signer='independent_inspector_service')
        with self.assertRaises(StateError):self.verify(*data,keys={})
        with self.assertRaises(StateError):self.verify(*data,now=NOW+timedelta(minutes=11))

    def test_old_kinds_budget_increase_and_boolean_numbers_block(self):
        for changes in ({'kind':'handoff004_exact_request_allowance'}, {'task_id':'authenticated-handoff-004'},
                {'reserved_micro_usd':250001},{'run_reserved_micro_usd':750001},
                {'aggregate_ceiling_micro_usd':3250001},{'maximum_provider_calls':True},
                {'kind':'bounded_review001_provider_allowance'},{'task_id':'bounded-review-001'},
                {'kind':'bounded_review002_provider_allowance'},{'task_id':'bounded-review-002'},
                {'kind':'bounded_review003_provider_allowance'},{'task_id':'bounded-review-003'},
                {'aggregate_ceiling_micro_usd':3000000},
                {'aggregate_ceiling_micro_usd':2750000},
                {'retries':1},{'production_release_authorized':True}):
            scope,price,ready,payload=fixture()
            with self.subTest(changes=changes),self.assertRaises(StateError):
                self.verify(scope,price,ready,{**payload,**changes})

    def test_request_candidate_proof_and_dispatch_cannot_be_substituted(self):
        scope,price,ready,payload=fixture()
        for changed in (replace(scope,request_bytes=b'changed'),replace(scope,candidate_commit='c'*40),
                replace(scope,test_evidence_digest=digest(b'changed')),
                replace(scope,request=replace(scope.request,lease_id='another-lease'))):
            with self.assertRaises(StateError):self.verify(changed,price,ready,payload)

    def test_unqualified_or_over_cap_rates_and_readiness_block_even_when_signed(self):
        for field,changes in (('price',{'input_micro_usd_per_million':1000000000}),
                ('price',{'input_token_bound':True}),('price',{'complete_request_bound_qualified':False}),
                ('ready',{'credential_route_verified':False}),('ready',{'provider':'other'})):
            scope,price,ready,payload=copy.deepcopy(fixture())
            (price if field=='price' else ready).update(changes)
            payload.update(pricing_digest=digest(canonical(price)),readiness_digest=digest(canonical(ready)))
            with self.assertRaises(StateError):self.verify(scope,price,ready,payload)
