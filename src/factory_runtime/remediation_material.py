"""Task005 material and pure preparation, with no signers, clients or activation.

The privileged importer must authenticate expected_digest against reviewed CI.
A caller-supplied hash alone is never proof provenance or execution authority.
"""
import base64
import json
from dataclasses import dataclass, replace

from factory_state.dispatch import DispatchRequest
from factory_state.model import COMMIT_SHA, SHA256_DIGEST, StateError
from factory_state.scope import canonical
from .remediation_profile import (TASK, CANDIDATE, CANDIDATE_DIGEST, PATHS,
    TEST_COUNT, AGGREGATE_CEILING, PROVIDER_HOLDS, EXISTING_HOLDS, NEW_AWS_HOLD, EVIDENCE, STOP)
from .review_provider_protocol import job_input, prepare
from .review_provider_scope import FACTORY, PROVIDERS
from .review_verdict import ReviewBinding, PinnedPythonTestEvidence
from .security_policy import policy_digest
from .security_verdict import SecurityReviewBinding
from .worker import digest


def contract(source_commit, proof_digest):
    if (type(source_commit) is not str or not COMMIT_SHA.fullmatch(source_commit) or
            type(proof_digest) is not str or not SHA256_DIGEST.fullmatch(proof_digest)):
        raise StateError('Exact task005 source and proof required')
    return canonical({'kind':'remediation005_contract','factory_id':FACTORY,'task_id':TASK,
        'source_commit':source_commit,'candidate_commit':CANDIDATE,'candidate_digest':CANDIDATE_DIGEST,
        'test_evidence_digest':proof_digest,'allowed_paths':list(PATHS),'test_count':TEST_COUNT,
        'role_holds_micro_usd':dict(PROVIDER_HOLDS),'new_aws_hold_micro_usd':NEW_AWS_HOLD,
        'preserved_holds_micro_usd':EXISTING_HOLDS,'aggregate_ceiling_micro_usd':AGGREGATE_CEILING,
        'maximum_attempts_per_role':1,'retries':0,'candidate_changes_allowed':False,
        'production_release_authorized':False,'historical_authority_reusable':False,
        'security_policy_digest':policy_digest(),
        'required_evidence':EVIDENCE,
        'stop_condition':STOP})


@dataclass(frozen=True)
class RemediationMaterial:
    source_commit: str
    candidate_bytes: bytes
    proof_bytes: bytes
    contract_bytes: bytes

    @classmethod
    def load(cls, raw, *, expected_digest, deployed_commit, clock):
        if type(raw) is not bytes or not 0 < len(raw) <= 196608 or digest(raw) != expected_digest:
            raise StateError('Task005 material differs from authenticated deployment pin')
        try:
            value=json.loads(raw)
            if canonical(value)!=raw or set(value)!={'kind','task_id','candidate_files','test_proof'}:
                raise ValueError('shape')
            if value['kind']!='remediation005_deployment_material' or value['task_id']!=TASK:
                raise ValueError('task')
            files=value['candidate_files']; proof=value['test_proof']
            expected={'status':'AUTHENTICATED_MAIN_TEST_PROOF','repository':'timbrydges/timscodefactory',
                'source_commit':deployed_commit,'workflow':'.github/workflows/runtime-canary.yml',
                'candidate_commit':CANDIDATE,'candidate_digest':CANDIDATE_DIGEST,
                'task_id':TASK,'model_calls':0,'state_writes':0,'gate_authority':False}
            if (type(files) is not dict or set(files)!=set(PATHS) or
                    any(type(v) is not str for v in files.values()) or digest(canonical(files))!=CANDIDATE_DIGEST or
                    type(proof) is not dict or set(proof)!=set(expected)|
                    {'run_id','artifact_id','archive_digest','proof_digest','proof_base64'} or
                    any(type(proof[k]) is not type(v) or proof[k]!=v for k,v in expected.items()) or
                    any(type(proof[k]) is not int or proof[k]<=0 for k in ('run_id','artifact_id')) or
                    any(type(proof[k]) is not str or not SHA256_DIGEST.fullmatch(proof[k])
                        for k in ('archive_digest','proof_digest'))):
                raise ValueError('binding')
            proof_bytes=base64.b64decode(proof['proof_base64'],validate=True)
            if digest(proof_bytes)!=proof['proof_digest']:raise ValueError('proof')
            result=cls(deployed_commit,canonical(files),proof_bytes,contract(deployed_commit,proof['proof_digest']))
            result.evidence('qa',clock=clock)
            return result
        except (ValueError,TypeError,KeyError,AttributeError,RecursionError):
            raise StateError('Invalid authenticated task005 material') from None

    def files(self):
        return json.loads(self.candidate_bytes)

    def prepared(self, role):
        if role not in PROVIDERS:raise StateError('Task005 review role required')
        raw=job_input(role=role,source_commit=self.source_commit,contract_digest=digest(self.contract_bytes),
            candidate_commit=CANDIDATE,files=self.files(),test_evidence_digest=digest(self.proof_bytes),task_id=TASK)
        request=DispatchRequest('bounded-review-005-'+role,TASK,'bounded-review-005-'+role,
            self.source_commit,digest(self.contract_bytes),digest(raw))
        return prepare(role=role,request=request,candidate_commit=CANDIDATE,files=self.files(),
            test_evidence_digest=digest(self.proof_bytes),input_bytes=raw,task_id=TASK)

    def binding(self, role):
        if role not in ('inspector','qa'):raise StateError('Inspector or QA binding required')
        return ReviewBinding(FACTORY,TASK,'qa_engineer' if role=='qa' else 'independent_inspector',
            self.source_commit,digest(self.contract_bytes),self.prepared(role).scope.request.input_digest,
            CANDIDATE,CANDIDATE_DIGEST,digest(self.proof_bytes),PATHS)

    def evidence(self, role, *, clock):
        evidence=PinnedPythonTestEvidence(self.binding(role),self.proof_bytes,self.files(),test_count=TEST_COUNT,clock=clock)
        if evidence(CANDIDATE,CANDIDATE_DIGEST,digest(self.proof_bytes)) is not True:
            raise StateError('Task005 proof invalid or expired')
        return evidence

    def security(self, *, qa_binding, qa_result_digest):
        # This checks linkage only. ConsumedQAProvenance must independently verify
        # the retained signed receipt and normal QA transition at execution time.
        if qa_binding!=self.binding('qa') or type(qa_result_digest) is not str or not SHA256_DIGEST.fullmatch(qa_result_digest):
            raise StateError('New task005 requires its own exact QA binding and receipt')
        from .security_provider_protocol import job_input as security_input, prepare as security_prepare
        binding=SecurityReviewBinding(qa_binding,digest(b'task005-unbound'),qa_result_digest,policy_digest())
        raw=security_input(binding,self.files());binding=replace(binding,input_digest=digest(raw))
        request=DispatchRequest('bounded-security-005',TASK,'bounded-security-005',self.source_commit,
            digest(self.contract_bytes),digest(raw))
        return security_prepare(binding=binding,request=request,files=self.files(),input_bytes=raw)
