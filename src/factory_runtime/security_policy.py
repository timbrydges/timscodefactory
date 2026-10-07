"""Fixed deployment-owned review policy, independent of dispatch receipt bytes."""
from factory_state.scope import canonical
from .worker import digest


def policy_bytes():
    return canonical({'kind':'bounded_security004_policy',
        'role_id':'deep_security_reviewer', 'stage':'SECURITY_REVIEW',
        'method':'static adversarial review of exact supplied source',
        'required_surfaces':['filesystem paths and symlinks', 'blocking and resource exhaustion',
            'input and output disclosure', 'code and command injection', 'dependency and credential access'],
        'historical_mitigations_assumed':False, 'sandbox_protection_assumed':False,
        'candidate_execution_allowed':False, 'tools_allowed':False,
        'risk_waivers_allowed':False, 'unresolved_risk_verdict':'REJECTED',
        'production_release_authorized':False})


def policy_digest():
    return digest(policy_bytes())
