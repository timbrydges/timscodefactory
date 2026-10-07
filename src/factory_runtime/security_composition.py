"""Offline deployment composition. No credential loader or activation switch."""
from factory_state.model import StateError
from .security_contract import validate_link
from .security_material import PinnedSecurityMaterial
from .security_provider_backend import SecurityProviderBackend
from .security_qa_provenance import ConsumedQAProvenance


def disabled_backend(*, material, qa_binding, qa_request, envelope, pricing, readiness,
                     states, ledger, claims, key_loader, historical_key_loader, clock):
    """Compose exact material and consumed provenance without reading or writing AWS.

    Material and both key loaders are privileged deployment inputs. Constructing
    this object does not authenticate a QA receipt or grant execution authority;
    the concrete verifier rechecks retained evidence when the runtime uses it.
    """
    if type(material) is not PinnedSecurityMaterial:
        raise StateError('Pinned security deployment material required')
    validate_link(material.binding, qa_binding, material.contract_bytes)
    prepared = material.prepared()
    provenance = ConsumedQAProvenance(binding=material.binding, qa_binding=qa_binding,
        qa_request=qa_request, states=states, ledger=ledger,
        historical_key_loader=historical_key_loader, clock=clock,
        contract_bytes=material.contract_bytes)
    # Cross-contract configuration must always include the separate contract.
    return SecurityProviderBackend(prepared=prepared, envelope=envelope, pricing=pricing,
        readiness=readiness, states=states, ledger=ledger, claims=claims,
        key_loader=key_loader, test_evidence=material.evidence(clock=clock),
        verify_prerequisites=provenance, clock=clock, enabled=False)
