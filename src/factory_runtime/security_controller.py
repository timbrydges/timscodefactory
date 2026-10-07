"""Disabled single-stage security composition. Never dispatches release work."""
from factory_state.model import StateError
from .acceptance_jobs import VersionedS3AcceptanceJobSource
from .autonomy import AutonomyActivation, AutonomousCycle, AutonomousScheduler
from .cloud_roles import LambdaRoleExecutor
from .intake import AuthenticatedIntakeService
from .progression import SignedResultProgressor
from .receipt_transport import VersionedS3ReceiptTransport
from .review_controller import _PinnedInputs, _ProofGuard
from .security_provider_backend import SecurityProviderBackend
from .security_qa_provenance import ConsumedQAProvenance
from .security_verdict import BoundSecurityValidator
from .worker import DispatchWorker


class BoundedSecurityController:
    def __init__(self, *, activation, deployed_commit, guard, prerequisites,
                 lambda_api, s3, function_arn, job_versions, enabled=False):
        if (type(enabled) is not bool or type(activation) is not AutonomyActivation or
                type(guard) is not SecurityProviderBackend or
                type(prerequisites) is not ConsumedQAProvenance):
            raise StateError('Deployment-owned security controller configuration required')
        activation.validate(guard.clock())
        b = guard.prepared.scope.binding; q = b.qa
        if (activation.source_commit != deployed_commit or
                any(getattr(activation,k) != getattr(q,k)
                    for k in ('factory_id','task_id','source_commit','contract_digest')) or
                guard.load_credential is not None or (enabled and not guard.enabled) or
                guard.verify_prerequisites is not prerequisites or prerequisites.binding != b or
                prerequisites.states is not guard.states or prerequisites.ledger is not guard.ledger or
                type(job_versions) is not dict or set(job_versions) != {'SECURITY_REVIEW'}):
            raise StateError('Exact credential-free security guard, provenance and job required')
        self.guard, self.binding, self.prerequisites = guard, b, prerequisites
        self.verify_tests()
        worker_id = 'bounded-security-controller'
        executor = LambdaRoleExecutor(lambda_api, function_arn=function_arn,
            worker_id=worker_id, guard=_ProofGuard(guard,self.verify_tests))
        if executor.role != 'security':
            raise StateError('Security controller requires exact security function')
        intake = AuthenticatedIntakeService(guard.states,guard.ledger,
            key_loader=guard.key_loader,clock=guard.clock)
        worker = DispatchWorker(guard.states,guard.ledger,deployed_commit=deployed_commit,
            worker_id=worker_id,key_loader=guard.key_loader,
            executors={'deep_security_reviewer':executor},clock=guard.clock)
        validator = BoundSecurityValidator(b,guard.evidence,prerequisites)
        progressor = SignedResultProgressor(guard.states,guard.ledger,key_loader=guard.key_loader,
            clock=guard.clock,review_validator=validator)
        jobs = _PinnedInputs(VersionedS3AcceptanceJobSource(s3,activation,job_versions),
                             {'SECURITY_REVIEW':b.input_digest})
        cycle = AutonomousCycle(intake,worker,progressor,VersionedS3ReceiptTransport(s3),enabled=enabled)
        self.scheduler = AutonomousScheduler(cycle,guard.states,jobs,activation,clock=guard.clock,enabled=enabled)
        self.activation, self.enabled = activation, enabled

    def verify_tests(self):
        q = self.binding.qa
        if self.guard.evidence(q.candidate_commit,q.candidate_digest,q.test_evidence_digest) is not True:
            raise StateError('Security test evidence absent, invalid or expired')

    def tick(self, factory_id, task_id):
        if not self.enabled:
            raise StateError('Security controller disabled')
        self.activation.validate(self.guard.clock())
        if (factory_id,task_id) != (self.activation.factory_id,self.activation.task_id):
            raise StateError('Security activation target differs')
        state = self.guard.states.load_state(factory_id,task_id)
        if state is None:
            raise StateError('Security task missing')
        if state.state != 'SECURITY_REVIEW':
            return {'status':'STOPPED','state':state.state,'worker_invocations':0,
                    'release_dispatched':False,'activation_id':self.activation.activation_id}
        self.verify_tests()
        if self.prerequisites(self.binding) is not True:
            raise StateError('Consumed QA prerequisite not authenticated')
        return self.scheduler.tick(factory_id,task_id)
