"""Independent fresh security scope review; no grants or provider execution."""
import copy
from datetime import datetime, timedelta

from factory_state.dispatch import DynamoDBDispatchStore
from factory_state.model import CONTROLLER_IDENTITY, FactoryStateMachine, StateError
from factory_state.scope import SignedScopeStore, canonical
from .intake import IntakePlan
from .security_material import PinnedSecurityMaterial
from .security_contract import validate_link
from .security_qa_provenance import ConsumedQAProvenance

IDENTITY = 'product_spec_reviewer_service'
EVIDENCE = 'Fresh authenticated 17-test Docker proof and exact consumed signed QA result.'
STOP = 'Stop on uncertainty, rejection or stale evidence; stop before release.'
RATIONALE = 'Exact security contract, QA provenance, fresh tests, owner scope and bounded lease verified.'


class SecurityScopeReview:
    def __init__(self, *, material, plan, owner_signature, prerequisites, key_loader, clock):
        if (type(material) is not PinnedSecurityMaterial or type(plan) is not IntakePlan or
                type(owner_signature) is not bytes or type(prerequisites) is not ConsumedQAProvenance or
                not callable(key_loader) or not callable(clock)):
            raise StateError('Deployment-owned security scope review required')
        self.material, self.plan = material, copy.deepcopy(plan)
        self.owner_signature, self.prerequisites = owner_signature, prerequisites
        self.key_loader, self.clock = key_loader, clock

    def review(self, *, now):
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise StateError('Aware security scope review time required')
        m, p, prerequisite = self.material, self.plan, self.prerequisites
        b = m.binding; q = b.qa
        validate_link(b, prerequisite.qa_binding, m.contract_bytes)
        prepared = m.prepared(); prepared.validate()
        state = prerequisite.states.load_state(q.factory_id, q.task_id)
        if (prerequisite.binding != b or state is None or
                (state.factory_id,state.task_id,state.state,state.version) !=
                (q.factory_id,q.task_id,'SECURITY_REVIEW',p.state_version) or
                (p.factory_id,p.task_id,p.state) != (q.factory_id,q.task_id,'SECURITY_REVIEW') or
                p.request != prepared.scope.request or p.lease.lease_id != p.request.lease_id or
                (p.lease.role_id,p.lease.authoritative_identity) !=
                ('deep_security_reviewer','deep_security_reviewer_service') or
                any(lease.active_at(now) for lease in state.leases) or
                not now < p.lease.expires_at <= now+timedelta(minutes=15)):
            raise StateError('Security scope state, dispatch or lease differs')
        FactoryStateMachine(state).issue_lease(CONTROLLER_IDENTITY,p.lease,
            expected_version=state.version,now=now)
        cap = p.capability_payload
        if cap.get('required_evidence') != EVIDENCE or cap.get('stop_condition') != STOP:
            raise StateError('Security evidence and stop conditions differ')
        for receipt in (cap,p.review_payload):
            if (type(receipt.get('issued_at')) is not int or type(receipt.get('expires_at')) is not int or
                    not receipt['issued_at'] <= now.timestamp() < receipt['expires_at'] <= receipt['issued_at']+600 or
                    receipt['expires_at'] > p.lease.expires_at.timestamp()):
                raise StateError('Security scope receipt lifetime exceeds bound')
        SignedScopeStore('unused',None,self.key_loader(now))._capability_item(
            state,p.request,cap,self.owner_signature,now=now)
        m.evidence(clock=self.clock)
        if prerequisite(b) is not True:
            raise StateError('Consumed QA prerequisite authentication failed')
        expected = {'kind':'scope_review','factory_id':q.factory_id,'task_id':q.task_id,
            'binding':DynamoDBDispatchStore._binding(p.request),'verdict':'ACCEPTED',
            'reviewer_identity':IDENTITY,'rationale':RATIONALE,
            'issued_at':cap['issued_at'],'expires_at':cap['expires_at']}
        if canonical(p.review_payload) != canonical(expected):
            raise StateError('Security independent scope receipt differs')
        return expected
