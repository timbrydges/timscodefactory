"""Read-only current-stage task005 preparation; no lease or receipt writes."""
from dataclasses import replace
from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import StateError
from .intake import AuthenticatedIntakeService
from .remediation_material import RemediationMaterial
from .remediation_deployment import RemediationSecurityMaterial
from .remediation_profile import TASK, EVIDENCE, STOP
from .review_provider_scope import FACTORY
from .review_scope_policy import STAGES, ROLE_IDS, IDENTITY, RATIONALE


def prepare_intake(*, material, role, states, clock):
    if role == 'security' and type(material) is RemediationSecurityMaterial:
        from .security_scope_policy import RATIONALE as rationale
        prepared = material.prepared()
        material.evidence(clock=clock)
        stage, role_id = 'SECURITY_REVIEW', 'deep_security_reviewer'
    elif type(role) is str and role in STAGES and type(material) is RemediationMaterial:
        prepared = material.prepared(role)
        material.evidence('qa' if role == 'qa' else 'inspector', clock=clock)
        stage, role_id, rationale = STAGES[role], ROLE_IDS[role], RATIONALE
    else:
        raise StateError('Exact task005 stage and material required')
    request = prepared.scope.request
    service = AuthenticatedIntakeService(states, DynamoDBDispatchStore('unused', None),
        key_loader=lambda now: {}, clock=clock)
    plan = service.prepare(FACTORY, TASK, role_id=role_id, source_commit=request.source_commit,
        objective_id=TASK, capability_id=request.capability_id,
        contract_bytes=material.review.contract_bytes if role == 'security' else material.contract_bytes,
        input_bytes=prepared.input_bytes, reviewer_identity=IDENTITY, required_evidence=EVIDENCE,
        stop_condition=STOP, rationale=rationale, lease_seconds=900, receipt_seconds=600)
    state = states.load_state(FACTORY, TASK)
    if (state is None or (state.factory_id, state.task_id, state.state, state.version) !=
            (FACTORY, TASK, stage, plan.state_version) or
            any(x.active_at(clock()) or x.lease_id == request.lease_id for x in state.leases)):
        raise StateError('Current task005 stage changed or lease consumed')
    return replace(plan, lease=replace(plan.lease, lease_id=request.lease_id), request=request,
        review_payload={**plan.review_payload, 'binding': DynamoDBDispatchStore._binding(request)})
