"""Deployment-owned three-role composition; no entrypoint or spending grant.

Proof bytes and their digest must come from an authenticated main artifact import.
Guards remain privileged provider-specific scope/pricing/budget implementations;
role labels do not establish provider independence. No historical scope is reused.
"""
from factory_state.model import SHA256_DIGEST, StateError
from .acceptance_jobs import VersionedS3AcceptanceJobSource
from .autonomy import AutonomyActivation, AutonomousCycle, AutonomousScheduler
from .cloud_roles import LambdaRoleExecutor
from .intake import AuthenticatedIntakeService
from .progression import SignedResultProgressor
from .receipt_transport import VersionedS3ReceiptTransport
from .review_verdict import BoundReviewValidator, PinnedPythonTestEvidence, ReviewBinding
from .worker import DispatchWorker

ROLES = {'IMPLEMENTATION': ('builder', 'engineering_agent'),
         'INSPECTION': ('inspector', 'independent_inspector'),
         'QA': ('qa', 'qa_engineer')}


class _ProofGuard:
    def __init__(self, guard, verify):
        self.guard, self.verify = guard, verify

    def check_activation(self, *args, **kwargs):
        self.verify()
        return self.guard.check_activation(*args, **kwargs)

    def reserve(self, *args, **kwargs):
        self.verify()
        return self.guard.reserve(*args, **kwargs)


class _PinnedInputs:
    def __init__(self, jobs, digests):
        self.jobs, self.digests = jobs, dict(digests)

    def load(self, factory_id, task_id, state):
        if state.state not in self.digests:
            raise StateError('bounded controller cannot dispatch this stage')
        job = self.jobs.load(factory_id, task_id, state)
        if job.plan.request.input_digest != self.digests[state.state]:
            raise StateError('job input differs from deployment-owned review composition')
        return job


class BoundedReviewController:
    """One authenticated Builder/Inspector/QA cycle per tick; stop before security.

    All constructor arguments are deployment-owned, never event/model fields.
    Constructing this service performs no IO and defaults to disabled. Its guards
    must independently enforce fresh signed provider scope and at-most-once budget
    claims at the remote side as well as the controller side.
    """
    def __init__(self, *, activation, deployed_commit, states, ledger, key_loader,
                 lambda_api, s3, function_arns, guards, job_versions,
                 inspector_binding, qa_binding, builder_input_digest,
                 proof_bytes, candidate_files, test_count, clock, enabled=False):
        if type(enabled) is not bool or type(activation) is not AutonomyActivation:
            raise StateError('explicit bounded controller configuration required')
        activation.validate(clock())
        if activation.source_commit != deployed_commit:
            raise StateError('controller source differs from activation')
        if (type(inspector_binding) is not ReviewBinding or type(qa_binding) is not ReviewBinding or
                inspector_binding.role_id != 'independent_inspector' or qa_binding.role_id != 'qa_engineer'):
            raise StateError('both deployment-owned review bindings required')
        inspector_binding.validate(); qa_binding.validate()
        shared = ('factory_id', 'task_id', 'source_commit', 'contract_digest',
                  'candidate_commit', 'candidate_digest', 'test_evidence_digest', 'allowed_paths')
        if (any(getattr(inspector_binding, key) != getattr(qa_binding, key) for key in shared) or
                any(getattr(inspector_binding, key) != getattr(activation, key)
                    for key in shared[:4])):
            raise StateError('review bindings must share the exact activation, candidate and proof')
        names = {name for name, _ in ROLES.values()}
        if (type(function_arns) is not dict or set(function_arns) != names or
                type(guards) is not dict or set(guards) != names or
                len({id(guard) for guard in guards.values()}) != 3 or
                any(not callable(getattr(guard, method, None)) for guard in guards.values()
                    for method in ('check_activation', 'reserve')) or
                type(job_versions) is not dict or set(job_versions) != set(ROLES) or
                type(builder_input_digest) is not str or not SHA256_DIGEST.fullmatch(builder_input_digest)):
            raise StateError('exact three-role routes, guards and job pins required')
        self.evidence = PinnedPythonTestEvidence(inspector_binding, proof_bytes, candidate_files,
                                                test_count=test_count, clock=clock)
        self.binding = inspector_binding
        self.verify_tests()
        self.validators = {
            'INSPECTION': BoundReviewValidator(inspector_binding, self.evidence),
            'QA': BoundReviewValidator(qa_binding, self.evidence)}
        worker_id = 'bounded-review-controller'
        executors = {}
        for name, role_id in ROLES.values():
            executor = LambdaRoleExecutor(lambda_api, function_arn=function_arns[name],
                worker_id=worker_id, guard=_ProofGuard(guards[name], self.verify_tests))
            if executor.role != name:
                raise StateError('function route differs from configured role')
            executors[role_id] = executor
        intake = AuthenticatedIntakeService(states, ledger, key_loader=key_loader, clock=clock)
        worker = DispatchWorker(states, ledger, deployed_commit=deployed_commit,
            worker_id=worker_id, key_loader=key_loader, executors=executors, clock=clock)
        progressor = SignedResultProgressor(states, ledger, key_loader=key_loader,
            clock=clock, review_validator=self.validate_review)
        jobs = _PinnedInputs(VersionedS3AcceptanceJobSource(s3, activation, job_versions),
            {'IMPLEMENTATION': builder_input_digest, 'INSPECTION': inspector_binding.input_digest,
             'QA': qa_binding.input_digest})
        cycle = AutonomousCycle(intake, worker, progressor, VersionedS3ReceiptTransport(s3), enabled=enabled)
        self.scheduler = AutonomousScheduler(cycle, states, jobs, activation, clock=clock, enabled=enabled)
        self.activation, self.clock, self.enabled, self.states = activation, clock, enabled, states

    def verify_tests(self):
        b = self.binding
        if self.evidence(b.candidate_commit, b.candidate_digest, b.test_evidence_digest) is not True:
            raise StateError('authenticated pinned tests are absent, invalid or expired')

    def validate_review(self, state, request, output):
        validator = self.validators.get(state.state)
        return validator is not None and validator(state, request, output) is True

    def tick(self, factory_id, task_id):
        if not self.enabled:
            raise StateError('bounded review controller is disabled')
        self.activation.validate(self.clock())
        if (factory_id, task_id) != (self.activation.factory_id, self.activation.task_id):
            raise StateError('bounded controller target differs from activation')
        state = self.states.load_state(factory_id, task_id)
        if state is None:
            raise StateError('bounded controller task missing')
        if state.state not in ROLES:
            return {'status': 'STOPPED', 'state': state.state, 'worker_invocations': 0,
                    'release_dispatched': False, 'activation_id': self.activation.activation_id}
        self.verify_tests()
        return self.scheduler.tick(factory_id, task_id)
