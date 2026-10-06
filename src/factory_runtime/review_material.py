"""Pinned deployment material, never an event-supplied approval or test attestation.

The trusted deployment process obtains expected_digest from the authenticated
GitHub importer. A matching hash alone does not authenticate an arbitrary file.
"""
import base64
import json
from dataclasses import dataclass

from factory_state.dispatch import DispatchRequest
from factory_state.model import SHA256_DIGEST, StateError
from factory_state.scope import canonical
from .review_provider_protocol import job_input, prepare
from .review_provider_scope import FACTORY, TASK, PROVIDERS
from .review_scope_policy import contract
from .review_verdict import ReviewBinding, PinnedPythonTestEvidence
from .worker import digest

CANDIDATE = '994719a384b7ac96abeb67e4b2addcab2deb4763'
CANDIDATE_DIGEST = 'sha256:741d2ccc568ea8ea1410ebd3b3a3a22fbda5552f43d04cc885654bb48de38d7f'
PATHS = ('fingerprint.py', 'tests/test_fingerprint.py')


@dataclass(frozen=True)
class PinnedReviewMaterial:
    source_commit: str
    candidate_bytes: bytes
    proof_bytes: bytes
    contract_bytes: bytes

    @classmethod
    def load(cls, raw, *, expected_digest, deployed_commit, clock):
        if type(raw) is not bytes or not 0 < len(raw) <= 196608 or digest(raw) != expected_digest:
            raise StateError('review material differs from privileged deployment pin')
        try:
            value = json.loads(raw)
            if (canonical(value) != raw or set(value) != {'kind','test_proof','candidate_files'} or
                    value['kind'] != 'bounded_review003_deployment_material'):
                raise ValueError('material shape')
            proof = value['test_proof']; files = value['candidate_files']
            expected = {'status':'AUTHENTICATED_MAIN_TEST_PROOF',
                'repository':'timbrydges/timscodefactory','source_commit':deployed_commit,
                'workflow':'.github/workflows/runtime-canary.yml','candidate_commit':CANDIDATE,
                'candidate_digest':CANDIDATE_DIGEST,'model_calls':0,'state_writes':0,'gate_authority':False}
            if (type(proof) is not dict or set(proof) != set(expected) |
                    {'run_id','artifact_id','archive_digest','proof_digest','proof_base64'} or
                    any(type(proof[k]) is not type(v) or proof[k] != v for k,v in expected.items()) or
                    any(type(proof[k]) is not int or proof[k] <= 0 for k in ('run_id','artifact_id')) or
                    any(type(proof[k]) is not str or not SHA256_DIGEST.fullmatch(proof[k])
                        for k in ('archive_digest','proof_digest')) or
                    type(files) is not dict or set(files) != set(PATHS) or
                    digest(canonical(files)) != CANDIDATE_DIGEST):
                raise ValueError('material binding')
            proof_bytes = base64.b64decode(proof['proof_base64'], validate=True)
            if digest(proof_bytes) != proof['proof_digest']:
                raise ValueError('proof digest')
            contract_bytes = contract(source_commit=deployed_commit,candidate_commit=CANDIDATE,
                candidate_digest=CANDIDATE_DIGEST,test_evidence_digest=proof['proof_digest'])
            result = cls(deployed_commit,canonical(files),proof_bytes,contract_bytes)
            result.evidence('inspector', clock=clock)
            return result
        except (ValueError,TypeError,KeyError,AttributeError,RecursionError):
            raise StateError('invalid pinned review deployment material') from None

    def files(self):
        return json.loads(self.candidate_bytes)

    def prepared(self, role):
        if role not in PROVIDERS:
            raise StateError('bounded provider role required')
        raw = job_input(role=role,source_commit=self.source_commit,
            contract_digest=digest(self.contract_bytes),candidate_commit=CANDIDATE,
            files=self.files(),test_evidence_digest=digest(self.proof_bytes))
        request = DispatchRequest('bounded-review-003-'+role,TASK,'bounded-review-'+role,
            self.source_commit,digest(self.contract_bytes),digest(raw))
        return prepare(role=role,request=request,candidate_commit=CANDIDATE,files=self.files(),
            test_evidence_digest=digest(self.proof_bytes),input_bytes=raw)

    def binding(self, role):
        if role not in ('inspector','qa'):
            raise StateError('review binding requires Inspector or QA')
        prepared = self.prepared(role)
        return ReviewBinding(FACTORY,TASK,'independent_inspector' if role=='inspector' else 'qa_engineer',
            self.source_commit,digest(self.contract_bytes),prepared.scope.request.input_digest,
            CANDIDATE,CANDIDATE_DIGEST,digest(self.proof_bytes),PATHS)

    def evidence(self, role, *, clock):
        binding = self.binding(role)
        evidence = PinnedPythonTestEvidence(binding,self.proof_bytes,self.files(),test_count=17,clock=clock)
        if evidence(CANDIDATE,CANDIDATE_DIGEST,digest(self.proof_bytes)) is not True:
            raise StateError('deployment test proof is invalid or expired')
        return evidence
