"""Composition checks; synthetic evidence is confined to these test fixtures."""
from dataclasses import replace
from datetime import timedelta
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from factory_runtime.acceptance_jobs import PinnedJobVersion
from factory_runtime.autonomy import AutonomyActivation, ScheduledAutonomyJob
from factory_runtime.intake import IntakePlan
from factory_runtime.receipt_transport import ReceiptVersions
from factory_runtime.review_controller import BoundedReviewController
from factory_runtime.review_verdict import ReviewBinding
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical
from test_autonomous_scheduler import NOW, States, task_state, job
import test_cloud_roles as roles


class NoIO:
    def __init__(self, service):
        self.meta = SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts': 1}),
            endpoint_url=f'https://{service}.ca-central-1.amazonaws.com')

    def __getattr__(self, name):
        raise AssertionError('unexpected construction IO: ' + name)


def configuration(*, now=NOW, factory='factory', task='task-1', contract=None, input_digest=None):
    files = {'fingerprint.py': 'print("fixture")\n'}
    proof = canonical({'source_commit': 'a'*40, 'candidate_commit': 'd'*40,
        'observed_at': now.isoformat(), 'runtime': 'python3.12-linux', 'python_version': '3.12.15',
        'files': {p: hashlib.sha256(v.encode()).hexdigest() for p,v in files.items()},
        'exit_code': 0, 'credentials_in_environment': False, 'stdout': '',
        'stderr': 'test_fixture ... ok\n\nRan 1 tests in 0.001s\n\nOK\n'})
    binding = ReviewBinding(factory, task, 'independent_inspector', 'a'*40,
        contract or digest(b'approved contract'), input_digest or digest(b'approved input'),
        'd'*40, digest(canonical(files)), digest(proof), tuple(files))
    return dict(activation=AutonomyActivation('fresh-review', factory, task, 'a'*40,
        binding.contract_digest, now-timedelta(minutes=1), now+timedelta(hours=2)),
        deployed_commit='a'*40, states=States(), ledger=NoIO('dynamodb'), key_loader=lambda _: {},
        lambda_api=NoIO('lambda'), s3=NoIO('s3'),
        function_arns={role: f'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-{role}:1'
                       for role in ('builder', 'inspector', 'qa')},
        guards={role: Mock() for role in ('builder', 'inspector', 'qa')},
        job_versions={stage: PinnedJobVersion('version-1', 'sha256:'+'f'*64)
                      for stage in ('IMPLEMENTATION', 'INSPECTION', 'QA')},
        inspector_binding=binding, qa_binding=replace(binding, role_id='qa_engineer'),
        builder_input_digest=binding.input_digest, proof_bytes=proof, candidate_files=files,
        test_count=1, clock=lambda: now)


class CompositionTests(unittest.TestCase):
    def test_disabled_and_constructed_without_io(self):
        service = BoundedReviewController(**configuration())
        with self.assertRaisesRegex(StateError, 'disabled'): service.tick('factory', 'task-1')
        worker = service.scheduler.cycle.worker
        self.assertEqual(set(worker.executors), {'engineering_agent', 'independent_inspector', 'qa_engineer'})
        self.assertIs(service.scheduler.cycle.progressor.review_validator.__self__, service)

    def test_mismatched_candidate_source_contract_and_missing_roles_reject(self):
        for change in ('candidate_commit', 'candidate_digest', 'test_evidence_digest', 'contract_digest',
                       'source_commit', 'task_id', 'allowed_paths'):
            config = configuration(); binding = config['qa_binding']
            value = {'candidate_commit':'e'*40, 'source_commit':'b'*40, 'task_id':'other',
                     'allowed_paths':('other.py',)}.get(change, 'sha256:'+'0'*64)
            config['qa_binding'] = replace(binding, **{change:value})
            with self.subTest(change=change), self.assertRaises(StateError):
                BoundedReviewController(**config)
        for field in ('guards', 'function_arns'):
            config = configuration(); config[field].pop(next(iter(config[field])))
            with self.assertRaises(StateError): BoundedReviewController(**config)
        config = configuration(); config['function_arns']['qa'] = config['function_arns']['inspector']
        with self.assertRaises(StateError): BoundedReviewController(**config)
        config = configuration(); config['guards']['qa'] = config['guards']['inspector']
        with self.assertRaises(StateError): BoundedReviewController(**config)

    def test_unpinned_stage_waits_without_jobs_claims_or_invocation(self):
        config=configuration(); config['job_versions']={'IMPLEMENTATION':config['job_versions']['IMPLEMENTATION']}
        config['states']=States(task_state('INSPECTION'))
        service=BoundedReviewController(**config,enabled=True)
        service.scheduler=Mock()
        result=service.tick('factory','task-1')
        self.assertEqual(result['status'],'AWAITING_SIGNED_STAGE')
        self.assertEqual(result['worker_invocations'],0)
        self.assertEqual(service.scheduler.mock_calls,[])
        self.assertTrue(all(not g.mock_calls for g in config['guards'].values()))
        for pins in ({},{'SECURITY_REVIEW':config['job_versions']['IMPLEMENTATION']}):
            with self.assertRaises(StateError):BoundedReviewController(**{**config,'job_versions':pins})

    def test_stops_before_security_or_release_without_loading_jobs(self):
        for stage in ('SECURITY_REVIEW', 'RELEASE_READY', 'PAUSED'):
            config=configuration(); config['states']=States(task_state(stage))
            service=BoundedReviewController(**config, enabled=True)
            result=service.tick('factory','task-1')
            self.assertEqual(result['status'],'STOPPED')
            self.assertEqual(result['worker_invocations'],0)
            self.assertFalse(result['release_dispatched'])

    def test_expired_proof_blocks_tick_and_guard_before_any_io(self):
        config=configuration(); observed=[NOW]; config['clock']=lambda:observed[0]
        service=BoundedReviewController(**config,enabled=True)
        observed[0]+=timedelta(hours=1,seconds=1)
        with self.assertRaisesRegex(StateError,'expired'):service.tick('factory','task-1')
        for executor in service.scheduler.cycle.worker.executors.values():
            with self.assertRaises(StateError):executor.guard.check_activation(None,None,now=observed[0])
            with self.assertRaises(StateError):executor.guard.reserve(None,None,dispatch_id='x',now=observed[0])
        self.assertTrue(all(not guard.mock_calls for guard in config['guards'].values()))

    def test_job_input_mismatch_blocks_before_cycle_or_guard(self):
        service=BoundedReviewController(**configuration(),enabled=True)
        supplied=job(); supplied=replace(supplied,plan=replace(supplied.plan,
            request=replace(supplied.plan.request,input_digest=digest(b'other'))))
        service.scheduler.jobs.jobs=Mock(load=Mock(return_value=supplied))
        service.scheduler.cycle=Mock()
        with self.assertRaisesRegex(StateError,'job input differs'):service.tick('factory','task-1')
        self.assertEqual(service.scheduler.cycle.mock_calls,[])


@unittest.skipIf(roles.mock_aws is None,'Requires moto[dynamodb]')
class SignedCompositionTests(unittest.TestCase):
    def test_both_review_roles_advance_from_real_signatures_and_persist_once(self):
        # Reuse the no-provider role fixture: real Ed25519 and Moto transactions.
        fixture=roles.CloudRoleTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        for role,stage,next_stage in (('inspector','INSPECTION','QA'),('qa','QA','SECURITY_REVIEW')):
            fixture.setup_role(role)
            fixture.db.put_item(TableName='role-state', Item=fixture.states._serialize_lease(
                fixture.state,fixture.state.leases[0]))
            from test_cloud_roles import NOW as ROLE_NOW
            config=configuration(now=ROLE_NOW,factory=fixture.state.factory_id,task=fixture.state.task_id,
                contract=fixture.request.contract_digest,input_digest=fixture.request.input_digest)
            config.update(states=fixture.states,ledger=fixture.ledger,key_loader=lambda _:fixture.keys,
                          lambda_api=fixture.client)
            service=BoundedReviewController(**config,enabled=True)
            # The remote fixture requires the exact claimed worker identity.
            service.scheduler.cycle.worker.worker_id='worker-1'
            for executor in service.scheduler.cycle.worker.executors.values():executor.worker_id='worker-1'
            binding=config['inspector_binding' if role=='inspector' else 'qa_binding']
            verdict={k:getattr(binding,k) for k in binding.__dataclass_fields__ if k!='allowed_paths'}
            verdict.update(kind='factory_review_v1',verdict='ACCEPTED',rationale='Synthetic fixture.',findings=[])
            calls=[]
            def execute(*args,**kwargs):calls.append(1);return canonical(verdict)
            fixture.service.backend.execute=execute
            plan=IntakePlan(fixture.state.factory_id,fixture.state.task_id,stage,fixture.state.version,
                fixture.state.leases[0],fixture.request,{}, {})
            scheduled=ScheduledAutonomyJob(plan,ReceiptVersions('owner-v1','review-v1'),fixture.input,fixture.contract)
            service.scheduler.jobs.jobs=Mock(load=Mock(return_value=scheduled))
            result=service.tick(fixture.state.factory_id,fixture.state.task_id)
            self.assertEqual(result['status'],'ADVANCED')
            state=fixture.states.load_state(fixture.state.factory_id,fixture.state.task_id)
            self.assertEqual(state.state,next_stage)
            self.assertEqual(service.scheduler.cycle.progressor.advance(
                state.factory_id,state.task_id,fixture.request)['status'],'ALREADY_ADVANCED')
            self.assertEqual(len(calls),1)
