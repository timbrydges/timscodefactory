"""Isolated capability and independent scope signers for one bounded stage."""
import copy
from datetime import datetime, timedelta

from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import StateError
from factory_state.scope import canonical
from .intake import IntakePlan
from .review_material import PinnedReviewMaterial
from .review_scope_policy import (FixedScopeReview, ReviewScopeSigner, STAGES, ROLE_IDS,
    ROLE_IDENTITIES, FACTORY, TASK, IDENTITY, EVIDENCE, STOP, RATIONALE)
from .review_signing import _EnrolledSigner


def check_plan(material, role, plan, now):
    if (type(material)is not PinnedReviewMaterial or type(role)is not str or role not in STAGES or
            type(plan)is not IntakePlan or type(now)is not datetime or now.tzinfo is None):
        raise StateError('exact bounded scope signing context required')
    prepared=material.prepared(role)
    material.evidence('qa' if role=='qa' else 'inspector',clock=lambda:now)
    if ((plan.factory_id,plan.task_id,plan.state)!=(FACTORY,TASK,STAGES[role]) or
            type(plan.state_version)is not int or plan.state_version<0 or plan.request!=prepared.scope.request or
            (plan.lease.lease_id,plan.lease.role_id,plan.lease.authoritative_identity)!=
            (plan.request.lease_id,ROLE_IDS[role],ROLE_IDENTITIES[role]) or
            not now<plan.lease.expires_at<=now+timedelta(minutes=15)):
        raise StateError('scope plan differs from bounded deployment')
    cap=plan.capability_payload
    expected={'kind':'capability','factory_id':FACTORY,'objective_id':TASK,'capability_id':'bounded-review-'+role,
        'contract_digest':plan.request.contract_digest,'owner_identity':'tim_brydges',
        'required_evidence':EVIDENCE,'stop_condition':STOP}
    if (type(cap)is not dict or set(cap)!=set(expected)|{'issued_at','expires_at'} or
            any(type(cap[k])is not type(v) or cap[k]!=v for k,v in expected.items()) or
            any(type(cap[k])is not int for k in ('issued_at','expires_at')) or
            not cap['issued_at']<=now.timestamp()<cap['expires_at']<=cap['issued_at']+600 or
            cap['expires_at']>plan.lease.expires_at.timestamp()):
        raise StateError('owner capability exceeds fixed contract or lifetime')
    review={'kind':'scope_review','factory_id':FACTORY,'task_id':TASK,
        'binding':DynamoDBDispatchStore._binding(plan.request),'verdict':'ACCEPTED',
        'reviewer_identity':IDENTITY,'rationale':RATIONALE,
        'issued_at':cap['issued_at'],'expires_at':cap['expires_at']}
    if canonical(plan.review_payload)!=canonical(review):
        raise StateError('independent review binding differs')
    return prepared


class ReviewCapabilitySigner(_EnrolledSigner):
    def __init__(self, *, material, role, plan, **kwargs):
        self.material,self.provider_role,self.plan=copy.deepcopy((material,role,plan))
        super().__init__(role='owner',**kwargs)

    def _check(self,payload,now):
        check_plan(self.material,self.provider_role,self.plan,now)
        if canonical(payload)!=canonical(self.plan.capability_payload):
            raise StateError('only exact owner capability may be signed')


def independent_signer(*, material, role, plan, owner_signature, states, key_loader, clock, kms, sts, enabled=False):
    prepared=check_plan(material,role,plan,clock())
    policy=FixedScopeReview(plan=plan,prepared=prepared,contract_bytes=material.contract_bytes,
        owner_signature=owner_signature,states=states,key_loader=key_loader,clock=clock,
        test_evidence=material.evidence('qa' if role=='qa' else 'inspector',clock=clock))
    return ReviewScopeSigner(policy=policy,kms=kms,sts=sts,enabled=enabled)
