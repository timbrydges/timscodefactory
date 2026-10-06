"""Prepare one current-stage scope plan; never create state or approval receipts."""
from dataclasses import replace

from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import StateError
from .intake import AuthenticatedIntakeService
from .review_material import PinnedReviewMaterial
from .review_scope_policy import FACTORY, TASK, STAGES, ROLE_IDS, IDENTITY, EVIDENCE, STOP, RATIONALE


def prepare_intake(*, material, role, states, clock):
    if type(material)is not PinnedReviewMaterial or type(role)is not str or role not in STAGES or not callable(clock):
        raise StateError('authenticated material and current bounded role required')
    prepared=material.prepared(role)
    material.evidence('qa' if role=='qa' else 'inspector',clock=clock)
    service=AuthenticatedIntakeService(states,DynamoDBDispatchStore('unused',None),
        key_loader=lambda now:{},clock=clock)
    plan=service.prepare(FACTORY,TASK,role_id=ROLE_IDS[role],source_commit=material.source_commit,
        objective_id=TASK,capability_id='bounded-review-'+role,contract_bytes=material.contract_bytes,
        input_bytes=prepared.input_bytes,reviewer_identity=IDENTITY,required_evidence=EVIDENCE,
        stop_condition=STOP,rationale=RATIONALE,lease_seconds=900,receipt_seconds=600)
    # The bounded deployment fixes one permanent request per role. Keep that
    # request's lease identity instead of generic intake's state-derived name.
    state=states.load_state(FACTORY,TASK)
    if (state is None or (state.factory_id,state.task_id,state.state,state.version)!=
            (FACTORY,TASK,STAGES[role],plan.state_version) or
            any(x.active_at(clock()) or x.lease_id==prepared.scope.request.lease_id for x in state.leases)):
        raise StateError('current stage changed or bounded lease already consumed')
    material.evidence('qa' if role=='qa' else 'inspector',clock=clock)
    request=prepared.scope.request
    review={**plan.review_payload,'binding':DynamoDBDispatchStore._binding(request)}
    return replace(plan,lease=replace(plan.lease,lease_id=request.lease_id),request=request,review_payload=review)
