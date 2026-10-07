"""Fresh security contract; historical QA is provenance, never a renewed grant."""
from dataclasses import asdict

from factory_state.model import COMMIT_SHA, SHA256_DIGEST, StateError
from factory_state.scope import canonical
from .review_verdict import ReviewBinding
from .security_policy import policy_digest
from .security_provider_scope import RESERVATION, AGGREGATE_CEILING, CLAIM_KEY, MODEL
from .worker import digest


def contract(*, source_commit, test_evidence_digest, qa_binding, qa_result_digest):
    if type(qa_binding) is not ReviewBinding:
        raise StateError('Exact historical QA binding required')
    qa_binding.validate()
    if ((qa_binding.factory_id, qa_binding.task_id, qa_binding.role_id) !=
            ('tims-software-factory', 'bounded-review-004', 'qa_engineer') or
            qa_binding.allowed_paths != ('fingerprint.py', 'tests/test_fingerprint.py') or
            type(source_commit) is not str or not COMMIT_SHA.fullmatch(source_commit) or
            any(type(v) is not str or not SHA256_DIGEST.fullmatch(v)
                for v in (test_evidence_digest, qa_result_digest))):
        raise StateError('Fixed security task and immutable provenance pins required')
    return canonical({'kind': 'bounded_security004_contract',
        'factory_id': qa_binding.factory_id, 'task_id': qa_binding.task_id,
        'source_commit': source_commit, 'test_evidence_digest': test_evidence_digest,
        'candidate_commit': qa_binding.candidate_commit,
        'candidate_digest': qa_binding.candidate_digest,
        'allowed_paths': list(qa_binding.allowed_paths),
        'prior_qa_binding': asdict(qa_binding), 'prior_qa_result_digest': qa_result_digest,
        'security_policy_digest': policy_digest(), 'provider': 'bedrock', 'model_id': MODEL,
        'claim_key': CLAIM_KEY, 'maximum_provider_calls': 1, 'retries': 0,
        'reserved_micro_usd': RESERVATION, 'aggregate_ceiling_micro_usd': AGGREGATE_CEILING,
        'candidate_changes_allowed': False, 'production_release_authorized': False,
        'historical_authority_renewed': False,
        'stop_condition': 'Stop on uncertainty, rejection or stale evidence; stop before release.'})


def validate_link(binding, qa_binding, contract_bytes):
    """Check deterministic linkage only; signatures and fresh proof stay external."""
    from .security_verdict import SecurityReviewBinding
    if type(binding) is not SecurityReviewBinding or type(contract_bytes) is not bytes:
        raise StateError('Deployment-owned security contract required')
    binding.validate()
    expected = contract(source_commit=binding.qa.source_commit,
        test_evidence_digest=binding.qa.test_evidence_digest,
        qa_binding=qa_binding, qa_result_digest=binding.qa_result_digest)
    shared = ('factory_id', 'task_id', 'candidate_commit', 'candidate_digest', 'allowed_paths')
    if (contract_bytes != expected or digest(expected) != binding.qa.contract_digest or
            binding.qa.contract_digest == qa_binding.contract_digest or
            binding.security_scope_digest != policy_digest() or
            any(getattr(binding.qa, k) != getattr(qa_binding, k) for k in shared)):
        raise StateError('Security contract or historical QA linkage differs')
