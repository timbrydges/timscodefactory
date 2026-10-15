"""Synthetic offline fixtures only: no signatures, network, candidate execution or authority."""
import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from factory_state.model import StateError, TaskState
from factory_state.scope import canonical
from factory_runtime.worker import digest
from factory_runtime.remediation_material import RemediationMaterial, contract
from factory_runtime.remediation_profile import (TASK, CANDIDATE, CANDIDATE_DIGEST,
    BASELINE, PROVIDER_HOLDS, claim_key, EXISTING_HOLDS, NEW_AWS_HOLD, AGGREGATE_CEILING)
from factory_runtime.remediation_deployment import RemediationSecurityMaterial, disabled_backend
from factory_runtime.remediation_intake import prepare_intake
from factory_runtime import remediation_lambda
from factory_runtime.review_provider_scope import validate_unsigned as review_unsigned
from factory_runtime.security_provider_scope import validate_unsigned as security_unsigned
from factory_runtime.review_provider_claims import ReviewProviderClaims
from factory_runtime.security_provider_claims import SecurityProviderClaims

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 15, 20, tzinfo=timezone.utc)
SOURCE = 'a'*40


def material_bytes():
    files = json.loads((ROOT/BASELINE).read_bytes())['files']
    proof = {'source_commit':SOURCE, 'candidate_commit':CANDIDATE, 'observed_at':NOW.isoformat(),
        'runtime':'python3.12-linux', 'python_version':'3.12.12', 'exit_code':0,
        'credentials_in_environment':False, 'stdout':'', 'stderr':'Ran 21 tests in 0.01s\n\nOK\n',
        'files':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in files.items()}}
    raw = canonical(proof)
    imported = {'task_id':TASK, 'status':'AUTHENTICATED_MAIN_TEST_PROOF',
        'repository':'timbrydges/timscodefactory', 'source_commit':SOURCE,
        'workflow':'.github/workflows/runtime-canary.yml', 'candidate_commit':CANDIDATE,
        'candidate_digest':CANDIDATE_DIGEST, 'run_id':123, 'artifact_id':456,
        'archive_digest':digest(b'synthetic archive'), 'proof_digest':digest(raw),
        'proof_base64':base64.b64encode(raw).decode(), 'model_calls':0, 'state_writes':0, 'gate_authority':False}
    return canonical({'kind':'remediation005_deployment_material', 'task_id':TASK,
        'candidate_files':files, 'test_proof':imported})


def load(raw=None, now=NOW):
    raw = material_bytes() if raw is None else raw
    return RemediationMaterial.load(raw, expected_digest=digest(raw), deployed_commit=SOURCE, clock=lambda:now)


def allowance(scope, role):
    prefix = 'bounded_security005' if role == 'security' else 'bounded_review005'
    binding = scope.bindings()
    times = {'issued_at':int(NOW.timestamp()), 'expires_at':int(NOW.timestamp())+600}
    price = {'kind':prefix+'_rate_qualification', **binding, 'currency':'USD',
        'complete_request_bound_qualified':True, 'standard_text_only_no_cache_rates':True,
        'input_token_bound':32768, 'output_token_bound':4096, 'input_micro_usd_per_million':750000,
        'output_micro_usd_per_million':3750000, 'evidence_digest':digest(b'fixture rates'), **times}
    ready = {'kind':prefix+'_provider_readiness', **binding, 'credential_route_verified':True,
        'model_metadata_verified':True, 'repository_binding_verified':True,
        'single_attempt_failure_risk_accepted':True, 'evidence_digest':digest(b'fixture readiness'), **times}
    payload = {'kind':prefix+'_provider_allowance', 'owner_identity':'tim_brydges', **binding,
        'pricing_digest':digest(canonical(price)), 'readiness_digest':digest(canonical(ready)),
        'reserved_micro_usd':PROVIDER_HOLDS[role], 'aggregate_ceiling_micro_usd':AGGREGATE_CEILING,
        'maximum_provider_calls':1, 'retries':0, 'production_release_authorized':False, **times}
    if role != 'security': payload['run_reserved_micro_usd'] = 500000
    return payload, price, ready


class RemediationTests(unittest.TestCase):
    def test_four_distinct_requests_and_budget_accounting(self):
        m=load(); requests=[m.prepared(r) for r in ('builder','inspector','qa')]
        requests.append(m.security(qa_binding=m.binding('qa'),qa_result_digest=digest(b'new QA receipt')))
        for r in requests:r.validate()
        self.assertEqual(len({r.scope.request.lease_id for r in requests}),4)
        self.assertEqual(len({r.scope.request.input_digest for r in requests}),4)
        self.assertEqual({r.scope.request.objective_id for r in requests},{TASK})
        self.assertEqual(EXISTING_HOLDS+sum(PROVIDER_HOLDS.values())+NEW_AWS_HOLD,4450000)
        self.assertFalse(json.loads(m.contract_bytes)['production_release_authorized'])

    def test_exact_candidate_and_task_reject_even_rehashed(self):
        for field,value in [('task_id','bounded-review-004'),('kind','bounded_review004_deployment_material')]:
            doc=json.loads(material_bytes());doc[field]=value
            with self.subTest(field=field),self.assertRaises(StateError):load(canonical(doc))
        doc=json.loads(material_bytes());doc['candidate_files']['fingerprint.py']='changed'
        with self.assertRaises(StateError):load(canonical(doc))

    def test_material_pin_and_noncanonical_input_rejected(self):
        raw=material_bytes()
        with self.assertRaises(StateError):load(raw+b'\n')
        with self.assertRaises(StateError):
            RemediationMaterial.load(raw,expected_digest=digest(b'other'),deployed_commit=SOURCE,clock=lambda:NOW)

    def test_expired_or_seventeen_test_proof_rejected(self):
        with self.assertRaises(StateError):load(now=NOW+timedelta(hours=2))
        doc=json.loads(material_bytes());p=doc['test_proof'];raw=base64.b64decode(p['proof_base64'])
        raw=raw.replace(b'Ran 21 tests',b'Ran 17 tests');p['proof_base64']=base64.b64encode(raw).decode();p['proof_digest']=digest(raw)
        with self.assertRaises(StateError):load(canonical(doc))

    def test_metadata_cannot_invent_authority_or_change_source(self):
        for change in ({'gate_authority':True},{'model_calls':False},{'run_id':True},
                {'source_commit':'b'*40},{'task_id':'bounded-review-004'}):
            doc=json.loads(material_bytes());doc['test_proof'].update(change)
            with self.subTest(change=change),self.assertRaises(StateError):load(canonical(doc))

    def test_old_qa_and_changed_qa_proof_rejected(self):
        m=load()
        for q in (replace(m.binding('qa'),task_id='bounded-review-004'),
                replace(m.binding('qa'),test_evidence_digest=digest(b'old proof'))):
            with self.assertRaises(StateError):m.security(qa_binding=q,qa_result_digest=digest(b'receipt'))

    def test_unknown_task_or_candidate_scope_rejected(self):
        s=load().prepared('builder').scope
        for changed in (replace(s,task_id='bounded-review-006'),replace(s,candidate_commit='b'*40),
                replace(s,request=replace(s.request,objective_id='bounded-review-004'))):
            with self.assertRaises(StateError):changed.bindings()

    def test_new_ceiling_and_claims_for_all_roles(self):
        m=load()
        for role in PROVIDER_HOLDS:
            prepared=m.security(qa_binding=m.binding('qa'),qa_result_digest=digest(b'receipt')) if role=='security' else m.prepared(role)
            payload,price,ready=allowance(prepared.scope,role)
            validate=security_unsigned if role=='security' else review_unsigned
            grant=validate(payload,scope=prepared.scope,pricing=price,readiness=ready,now=NOW)
            cls=SecurityProviderClaims if role=='security' else ReviewProviderClaims
            store=object.__new__(cls)
            row=store._item(grant,'a'*64,NOW)
            self.assertEqual(row['PK']['S'],claim_key(TASK,role));self.assertEqual(row['reservation_status']['S'],'HELD')
            for change in ({'aggregate_ceiling_micro_usd':3600000},{'aggregate_ceiling_micro_usd':4450001},
                    {'retries':1},{'maximum_provider_calls':True},{'task_id':'bounded-review-004'},
                    {'production_release_authorized':True}):
                with self.subTest(role=role,change=change),self.assertRaises(StateError):
                    validate({**payload,**change},scope=prepared.scope,pricing=price,readiness=ready,now=NOW)

    def test_legacy_unsigned_scopes_still_validate(self):
        from test_review_provider_scope import fixture
        from test_security_provider_scope import fixture as security_fixture
        from test_autonomous_scheduler import NOW as old_now
        for role in ('builder','inspector','qa'):
            s,p,r,a=fixture(role)
            self.assertEqual(review_unsigned(a,scope=s,pricing=p,readiness=r,now=old_now).task_id,'bounded-review-004')
        s,p,r,a=security_fixture()
        self.assertEqual(security_unsigned(a,scope=s,pricing=p,readiness=r,now=old_now).task_id,'bounded-review-004')

    def test_all_entrypoints_disabled_before_io_and_old_switches_insufficient(self):
        for stage in ('review_role','review_controller','security_role','security_controller'):
            with patch('factory_runtime.pilot002_entrypoint._aws_session') as session:
                with self.assertRaisesRegex(StateError,'disabled'):
                    remediation_lambda.dispatch(stage,{},None,root=None,env={
                        'FACTORY_SECURITY_ENABLED':'true','FACTORY_BOUNDED_REVIEW_ENABLED':'true'},clock=lambda:NOW)
                session.assert_not_called()

    def test_new_switch_does_not_bypass_existing_disabled_gates(self):
        for stage in ('review_role','review_controller','security_role','security_controller'):
            with self.assertRaisesRegex(StateError,'disabled'):
                remediation_lambda.dispatch(stage,{},None,root=None,
                    env={'FACTORY_REMEDIATION005_ENABLED':'true'},clock=lambda:NOW)

    def test_read_only_intake_four_stages_and_lease_identity(self):
        m=load()
        for role,stage in [('builder','IMPLEMENTATION'),('inspector','INSPECTION'),('qa','QA'),('security','SECURITY_REVIEW')]:
            material=RemediationSecurityMaterial(m,digest(b'receipt')) if role=='security' else m
            state=TaskState('tims-software-factory',TASK,stage,0,NOW,'tim_brydges')
            states=Mock(load_state=Mock(return_value=state))
            plan=prepare_intake(material=material,role=role,states=states,clock=lambda:NOW)
            self.assertEqual(plan.task_id,TASK);self.assertEqual(plan.lease.lease_id,plan.request.lease_id)
            self.assertTrue(all(c[0]=='load_state' for c in states.mock_calls))
            states.load_state.return_value=replace(state,task_id='bounded-review-004')
            with self.assertRaises(StateError):prepare_intake(material=material,role=role,states=states,clock=lambda:NOW)

    def test_disabled_security_composition_preserves_concrete_qa_verifier(self):
        m=load(); sm=RemediationSecurityMaterial(m,digest(b'receipt'))
        states,ledger=Mock(),Mock()
        claims=object.__new__(SecurityProviderClaims);claims.client=Mock()
        backend=disabled_backend(material=sm,qa_binding=m.binding('qa'),qa_request=m.prepared('qa').scope.request,
            envelope={},pricing={},readiness={},states=states,ledger=ledger,claims=claims,
            key_loader=lambda now:{},historical_key_loader=lambda now:{},clock=lambda:NOW)
        self.assertFalse(backend.enabled)
        self.assertEqual(backend.verify_prerequisites.request,m.prepared('qa').scope.request)
        states.assert_not_called();self.assertFalse(states.mock_calls);self.assertFalse(claims.client.mock_calls)

    def test_paused_bootstrap_default_is_zero_io(self):
        from factory_runtime.review_bootstrap import run
        db,sts=Mock(),Mock()
        with self.assertRaisesRegex(StateError,'disabled'):
            run({},approved_digest=digest(b'none'),material=load(),db=db,sts=sts,clock=lambda:NOW)
        self.assertFalse(db.mock_calls);self.assertFalse(sts.mock_calls)

    def test_scope_preparation_uses_new_policy_without_signing(self):
        from factory_runtime.review_scope_policy import FixedScopeReview
        from factory_runtime.review_scope_signing import check_plan as check_review_plan
        from factory_runtime.security_capability_signing import check_plan
        m=load()
        for role,stage in [('builder','IMPLEMENTATION'),('inspector','INSPECTION'),('qa','QA'),('security','SECURITY_REVIEW')]:
            state=TaskState('tims-software-factory',TASK,stage,0,NOW,'tim_brydges')
            states=Mock(load_state=Mock(return_value=state))
            material=RemediationSecurityMaterial(m,digest(b'receipt')) if role=='security' else m
            plan=prepare_intake(material=material,role=role,states=states,clock=lambda:NOW)
            if role=='security':
                self.assertEqual(check_plan(material,plan,NOW),material.prepared())
            else:
                self.assertEqual(check_review_plan(m,role,plan,NOW),m.prepared(role))
                policy=FixedScopeReview(plan=plan,prepared=m.prepared(role),contract_bytes=m.contract_bytes,
                    owner_signature=b'unsigned fixture',test_evidence=m.evidence('qa' if role=='qa' else 'inspector',clock=lambda:NOW),
                    states=states,key_loader=lambda now:{},clock=lambda:NOW)
                # Check composition only. This mock supplies no cryptographic evidence.
                with patch('factory_runtime.review_scope_policy.SignedScopeStore._capability_item') as verify:
                    self.assertEqual(policy.review(now=NOW),plan.review_payload);verify.assert_called_once()
                with self.assertRaises(StateError):policy.review(now=NOW)

    def test_authenticated_import_route_selects_new_artifact_and_candidate(self):
        from scripts.prepare_remediation_material import prepare
        from scripts.prepare_review_test_proof import COMMAND
        from factory_runtime.docker_sandbox import DockerSandboxPolicy
        from factory_runtime.sandbox import SandboxRequest
        from test_review_test_proof_import import archive_bytes, REPOSITORY, WORKFLOW
        doc=json.loads(material_bytes());files=doc['candidate_files']
        proof=json.loads(base64.b64decode(doc['test_proof']['proof_base64']))
        workspace=digest(b''.join(('F\0'+p+'\0'+'0\0'+hashlib.sha256(v.encode()).hexdigest()+'\n').encode()
            for p,v in sorted(files.items())))
        policy=DockerSandboxPolicy('python@sha256:'+'a'*64)
        request=SandboxRequest('candidate-test-proof-v1','candidate-test-proof-canary','fixture-qa',
            'qa_engineer',SOURCE,workspace,COMMAND,policy.environment_digest,180,policy.runner_identity)
        metadata=json.dumps({'python_version':proof['python_version']})+'\n'
        proof['sandbox']={'image_ref':policy.image_ref,'request_digest':request.request_digest,
            'environment_digest':policy.environment_digest,'workspace_digest':workspace,
            'runner_metadata_stdout':metadata,'stdout_digest':digest(metadata.encode()),
            'stderr_digest':digest(proof['stderr'].encode()),'network':'none','user':policy.user}
        archive=archive_bytes({'candidate-test-proof.json':canonical(proof)})
        run={'id':123,'event':'workflow_dispatch','head_branch':'main','head_sha':SOURCE,'path':WORKFLOW,
            'status':'completed','conclusion':'success','repository':{'full_name':REPOSITORY},'head_repository':{'full_name':REPOSITORY}}
        artifact={'id':456,'name':'isolated-remediation005-test-proof','expired':False,'size_in_bytes':len(archive),
            'digest':digest(archive),'workflow_run':{'id':123,'head_sha':SOURCE,'head_branch':'main'}}
        prefix='repos/'+REPOSITORY
        responses={prefix+'/git/ref/heads/main':canonical({'object':{'sha':SOURCE}}),
            prefix+'/actions/runs/123':canonical(run),prefix+'/actions/runs/123/artifacts?per_page=100':
            canonical({'total_count':1,'artifacts':[artifact]}),prefix+'/actions/artifacts/456/zip':archive}
        api=Mock(side_effect=lambda path:responses[path])
        result=prepare(SOURCE,123,api=api,clock=lambda:NOW)
        self.assertEqual(load(result).binding('qa').task_id,TASK);self.assertEqual(api.call_count,4)
        artifact['name']='isolated-candidate-test-proof'
        responses[prefix+'/actions/runs/123/artifacts?per_page=100']=canonical({'total_count':1,'artifacts':[artifact]})
        with self.assertRaises(StateError):prepare(SOURCE,123,api=api,clock=lambda:NOW)

    def test_bootstrap_targets_only_new_task_and_checks_all_four_claims(self):
        from factory_runtime.review_bootstrap import run
        m=load();config={'kind':'bounded_review005_paused_bootstrap','factory_id':'tims-software-factory',
            'task_id':TASK,'source_commit':SOURCE,'contract_digest':digest(m.contract_bytes),'owner_identity':'tim_brydges',
            'initial_state':'PAUSED','provider_calls':0,'not_before':int(NOW.timestamp()),
            'expires_at':int(NOW.timestamp())+600,'nonce':'a'*32}
        db=Mock();db.meta.endpoint_url='https://dynamodb.ca-central-1.amazonaws.com';db.meta.config.retries={'total_max_attempts':1}
        rows={}
        key=lambda item:(item['PK']['S'],item['SK']['S'])
        db.get_item.side_effect=lambda **kw:{'Item':rows[key(kw['Key'])]} if key(kw['Key']) in rows else {}
        def transaction(**kw):
            checks=[x['ConditionCheck'] for x in kw['TransactItems'] if 'ConditionCheck' in x]
            self.assertEqual({x['Key']['PK']['S'] for x in checks},{claim_key(TASK,r) for r in PROVIDER_HOLDS})
            for x in kw['TransactItems']:
                if 'Put' in x:
                    item=x['Put']['Item'];self.assertIn('#TASK#'+TASK,item['PK']['S']);rows[key(item)]=item
        db.transact_write_items.side_effect=transaction
        sts=Mock(get_caller_identity=Mock(return_value={'Account':'666730517561','Arn':'fixture-only'}))
        result=run(config,approved_digest=digest(canonical(config)),material=m,db=db,sts=sts,clock=lambda:NOW,enabled=True)
        self.assertEqual(result['state'],'PAUSED');self.assertEqual(result['claim_writes'],0)

    def test_package_metadata_selects_explicit_new_handler_and_all_disabled_flags(self):
        import scripts.build_bounded_review_package as builder
        from test_bounded_review_package import BoundedPackageTests
        from factory_runtime.remediation_profile import DISABLED_ENV, HANDLERS
        f=BoundedPackageTests();f.setUp();self.addCleanup(f.doCleanups)
        # Fixture repository and dependency bytes only; no dependency download.
        with patch.object(builder,'ROOT',f.root),patch.object(builder,'_dependencies',return_value={}):
            result=builder.build(f.root.parent/'remediation005-package.zip',task=TASK)
        self.assertEqual(result['handler'],HANDLERS['controller'])
        self.assertEqual(result['environment'],DISABLED_ENV)
        self.assertFalse(result['execution_enabled'])

    def test_security_scope_never_accepts_unconsumed_new_qa(self):
        from factory_runtime.security_scope_policy import SecurityScopeReview
        m=load();sm=RemediationSecurityMaterial(m,digest(b'receipt'))
        state=TaskState('tims-software-factory',TASK,'SECURITY_REVIEW',0,NOW,'tim_brydges')
        states=Mock(load_state=Mock(return_value=state));ledger=Mock()
        plan=prepare_intake(material=sm,role='security',states=states,clock=lambda:NOW)
        claims=object.__new__(SecurityProviderClaims);claims.client=Mock()
        backend=disabled_backend(material=sm,qa_binding=m.binding('qa'),qa_request=m.prepared('qa').scope.request,
            envelope={},pricing={},readiness={},states=states,ledger=ledger,claims=claims,
            key_loader=lambda now:{},historical_key_loader=lambda now:{},clock=lambda:NOW)
        policy=SecurityScopeReview(material=sm,plan=plan,owner_signature=b'unsigned fixture',
            prerequisites=backend.verify_prerequisites,key_loader=lambda now:{},clock=lambda:NOW)
        with patch('factory_runtime.security_scope_policy.SignedScopeStore._capability_item'):
            with self.assertRaisesRegex(StateError,'Consumed QA'):policy.review(now=NOW)
        self.assertFalse(ledger.mock_calls)


if __name__=='__main__':unittest.main()
