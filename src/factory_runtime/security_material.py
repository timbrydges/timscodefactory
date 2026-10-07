"""Security deployment material; hashes never substitute for authenticated import.

The privileged deployer supplies the authenticated Docker importer pin and exact
historical QA binding/result pin. Runtime must still authenticate the consumed
QA receipt, current signatures and custody before any provider send.
"""
import json
from dataclasses import dataclass, replace

from factory_state.dispatch import DispatchRequest
from .review_material import PinnedReviewMaterial
from .review_verdict import PinnedPythonTestEvidence
from .security_contract import contract, validate_link
from .security_policy import policy_digest
from .security_provider_protocol import job_input, prepare
from .security_verdict import SecurityReviewBinding
from .worker import digest


@dataclass(frozen=True)
class PinnedSecurityMaterial:
    candidate_bytes: bytes
    proof_bytes: bytes
    contract_bytes: bytes
    binding: SecurityReviewBinding

    @classmethod
    def load(cls, raw, *, expected_digest, deployed_commit, qa_binding, qa_result_digest, clock):
        # Reuse authenticated import format and candidate/proof validation only.
        # The old three-provider contract is deliberately discarded.
        material = PinnedReviewMaterial.load(raw, expected_digest=expected_digest,
            deployed_commit=deployed_commit, clock=clock)
        contract_bytes = contract(source_commit=deployed_commit,
            test_evidence_digest=digest(material.proof_bytes),
            qa_binding=qa_binding, qa_result_digest=qa_result_digest)
        q = replace(material.binding('qa'), contract_digest=digest(contract_bytes))
        binding = SecurityReviewBinding(q, digest(b'security-material-unbound'),
            qa_result_digest, policy_digest())
        validate_link(binding, qa_binding, contract_bytes)
        raw_input = job_input(binding, material.files())
        binding = replace(binding, input_digest=digest(raw_input))
        result = cls(material.candidate_bytes, material.proof_bytes, contract_bytes, binding)
        result.prepared().validate()
        result.evidence(clock=clock)
        return result

    def prepared(self):
        q = self.binding.qa
        files = json.loads(self.candidate_bytes)
        raw = job_input(self.binding, files)
        request = DispatchRequest('bounded-security-004', q.task_id, 'bounded-security-004',
            q.source_commit, q.contract_digest, digest(raw))
        return prepare(binding=self.binding, request=request, files=files, input_bytes=raw)

    def evidence(self, *, clock):
        from factory_state.model import StateError
        q = self.binding.qa
        evidence = PinnedPythonTestEvidence(q, self.proof_bytes, json.loads(self.candidate_bytes),
            test_count=17, clock=clock)
        if evidence(q.candidate_commit, q.candidate_digest, q.test_evidence_digest) is not True:
            raise StateError('Security deployment test proof is invalid or expired')
        return evidence
