import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from factory_runtime import inspection_completion as completion
from factory_runtime.autonomy_controller_lambda import handler
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import StateError
from test_progression import MemoryStates

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 2, 20, tzinfo=timezone.utc)


class CheckedStates(MemoryStates):
    def persist_transition(self, before, after, **kwargs):
        DynamoDBStateStore._validate_audit_event(before, after,
            kwargs['caller_identity'], kwargs['audit_event'])
        DynamoDBStateStore._validate_state_delta(before, after,
            kwargs['caller_identity'], kwargs['audit_event'])
        super().persist_transition(before, after, **kwargs)


class InspectionCompletionTests(unittest.TestCase):
    def setUp(self):
        self.baseline, self.payload = completion.validate_bundle(ROOT, NOW)
        self.states = CheckedStates(self.baseline)
        self.service = completion.InspectionCompletion(ROOT, self.states, clock=lambda: NOW)

    def test_verified_review_advances_once_with_complete_history_and_normal_audits(self):
        result = self.service.complete()
        self.assertEqual((result['state'], result['version'], result['model_calls']), ('QA', 12, 0))
        self.assertFalse(result['release_dispatched'])
        self.assertFalse(result['schedule_enabled'])
        self.assertEqual(self.states.state.leases[:6], self.baseline.leases)
        self.assertEqual(len(self.states.state.leases), 7)
        self.assertTrue(all(x.revoked for x in self.states.state.leases))
        self.assertEqual(self.states.state.consumed_evidence_ids - self.baseline.consumed_evidence_ids,
                         {result['evidence_id']})
        self.assertEqual([x[2]['audit_event']['event_type'] for x in self.states.writes],
                         ['LEASE_ISSUED', 'STATE_TRANSITION'])
        self.assertEqual(self.service.complete()['status'], 'ALREADY_ADVANCED')
        self.assertEqual(len(self.states.writes), 2)

    def test_unknown_commit_outcomes_reconcile_without_duplicate_writes(self):
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                states = CheckedStates(self.baseline)
                persist = states.persist_transition
                def unknown(*args, **kwargs):
                    persist(*args, **kwargs)
                    if len(states.writes) == fail_at:
                        raise TimeoutError('commit outcome unknown')
                states.persist_transition = unknown
                service = completion.InspectionCompletion(ROOT, states, clock=lambda: NOW)
                with self.assertRaises(TimeoutError):
                    service.complete()
                states.persist_transition = persist
                service.clock = lambda: NOW + timedelta(seconds=1)
                service.complete()
                self.assertEqual(states.state.state, 'QA')
                self.assertEqual(len(states.writes), 2)

    def test_failed_write_before_commit_can_reconcile(self):
        with patch.object(self.states, 'persist_transition', side_effect=TimeoutError):
            with self.assertRaises(TimeoutError): self.service.complete()
        self.assertEqual(self.states.state, self.baseline)
        self.assertEqual(self.service.complete()['status'], 'ADVANCED')

    def test_drift_never_resets_state_or_removes_history(self):
        for state in (replace(self.baseline, version=11),
                      replace(self.baseline, state='QA'),
                      replace(self.baseline, leases=self.baseline.leases[:-1])):
            with self.subTest(state=state.state, version=state.version):
                self.states.state = state
                with self.assertRaises(StateError): self.service.complete()
                self.assertEqual(self.states.writes, [])

    def test_expiry_and_missing_signer_prevent_writes(self):
        self.service.clock = lambda: datetime.fromisoformat(completion.EXPIRY)
        with self.assertRaises(StateError): self.service.complete()
        self.service.clock = lambda: NOW
        with patch.object(completion, 'load_trusted_signers', return_value={}):
            with self.assertRaises(StateError): self.service.complete()
        self.assertEqual(self.states.writes, [])

    def test_modified_signed_result_baseline_or_approval_fails_closed(self):
        for relative in (completion.REVIEW, completion.BASELINE,
                         'factory/evidence/' + completion.AUTHORIZATION + '.json'):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for path in (completion.REVIEW, completion.BASELINE,
                             'factory/evidence/' + completion.AUTHORIZATION + '.json',
                             'factory/profiles/scope-signers.json'):
                    target = root / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / path, target)
                target = root / relative
                data = json.loads(target.read_bytes())
                if relative == completion.REVIEW: data['payload']['verdict'] = 'REJECTED'
                elif relative == completion.BASELINE: data['version'] = 9
                else: data['maximum_model_calls'] = 1
                target.write_text(json.dumps(data))
                with self.assertRaises(StateError):
                    completion.InspectionCompletion(root, self.states, clock=lambda: NOW).complete()
        self.assertEqual(self.states.writes, [])

    def test_handler_requires_explicit_completion_flag_and_exact_event(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'BUILD.json').write_text(json.dumps({'source_commit': 'a'*40}))
            event = {'kind': 'complete_implementation_inspection', 'source_commit': 'a'*40,
                     'authorization_id': completion.AUTHORIZATION, 'candidate_commit': completion.CANDIDATE}
            with patch.dict(os.environ, {'LAMBDA_TASK_ROOT': directory,
                    'FACTORY_AUTONOMY_CONTROLLER_ENABLED': 'false'}, clear=True):
                with self.assertRaises(StateError): handler(event, None)
                os.environ[completion.ENABLED] = 'true'
                with self.assertRaises(StateError): handler({**event, 'extra': True}, None)


if __name__ == '__main__': unittest.main()
