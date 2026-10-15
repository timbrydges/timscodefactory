"""Explicit task005 deployment composition; never selected by event content."""
from dataclasses import dataclass
from factory_state.model import StateError
from .remediation_material import RemediationMaterial
from .security_provider_backend import SecurityProviderBackend
from .security_qa_provenance import ConsumedQAProvenance


@dataclass(frozen=True)
class RemediationSecurityMaterial:
    review: RemediationMaterial
    qa_result_digest: str

    @classmethod
    def load(cls, raw, *, expected_digest, deployed_commit, qa_binding, qa_result_digest, clock):
        review = RemediationMaterial.load(raw, expected_digest=expected_digest,
            deployed_commit=deployed_commit, clock=clock)
        review.security(qa_binding=qa_binding, qa_result_digest=qa_result_digest).validate()
        return cls(review, qa_result_digest)

    @property
    def binding(self):
        return self.prepared().scope.binding

    def prepared(self):
        return self.review.security(qa_binding=self.review.binding('qa'),
            qa_result_digest=self.qa_result_digest)

    def evidence(self, *, clock):
        return self.review.evidence('qa', clock=clock)


def disabled_backend(*, material, qa_binding, qa_request, envelope, pricing, readiness,
                     states, ledger, claims, key_loader, historical_key_loader, clock):
    if (type(material) is not RemediationSecurityMaterial or
            qa_binding != material.review.binding('qa') or
            qa_request != material.review.prepared('qa').scope.request):
        raise StateError('Exact new-task QA deployment and request required')
    # All four stages bind the same task005 contract. The concrete provenance
    # verifier still authenticates the consumed QA transition and signed receipt.
    provenance = ConsumedQAProvenance(binding=material.binding, qa_binding=qa_binding,
        qa_request=qa_request, states=states, ledger=ledger,
        historical_key_loader=historical_key_loader, clock=clock)
    return SecurityProviderBackend(prepared=material.prepared(), envelope=envelope,
        pricing=pricing, readiness=readiness, states=states, ledger=ledger, claims=claims,
        key_loader=key_loader, test_evidence=material.evidence(clock=clock),
        verify_prerequisites=provenance, clock=clock, enabled=False)


def load_review_role(root, env, *, clock):
    from .review_role_lambda import load_deployment
    return load_deployment(root, env, clock=clock, material_type=RemediationMaterial)


def load_review_controller(root, env, *, clock):
    from .review_controller_lambda import load_deployment
    from .remediation_profile import TASK
    return load_deployment(root, env, clock=clock, material_type=RemediationMaterial, task_id=TASK)


def load_security(root, env, *, clock):
    from .security_deployment import load_deployment
    result = load_deployment(root, env, clock=clock, material_type=RemediationSecurityMaterial,
        provenance_kind='bounded_security005_qa_provenance')
    if result.qa_request != result.material.review.prepared('qa').scope.request:
        raise StateError('Task005 QA request differs from deployment')
    return result


def load_security_controller(root, env, **kwargs):
    from .security_controller_config import load_controller_config
    return load_controller_config(root, env, activation_id='bounded-security-005', **kwargs)
