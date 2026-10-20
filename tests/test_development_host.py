"""Host wiring with fake provider transport and sandbox; no credentials/network."""
import asyncio
from dataclasses import replace
from decimal import Decimal
import json
import unittest

import test_development_provider as fixtures
import test_openai_provider as provider
from factory_runtime.development_host import DevelopmentHost
from factory_runtime.provider_credentials import EnvironmentProviderCredentialLeaseSource
from factory_state.model import StateError


class DevelopmentHostTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.DevelopmentProviderTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        runner = self.f.f.runner
        self.path = self.f.f.root / 'fresh-attempt'
        self.options = dict(task=self.f.f.task,
            contract_bytes=runner.contract_bytes, snapshot=runner.snapshot,
            builder=self.f.builder, reviewer=self.f.reviewer, target=provider.TARGET,
            builder_cap=Decimal('0.25'), reviewer_cap=Decimal('0.25'),
            total_cap=Decimal('0.50'), request_for=runner.request_for,
            sandbox_for=runner.sandbox_for, clock=runner.clock)

    def test_default_disabled_does_not_dispatch_or_claim(self):
        host = DevelopmentHost(self.path, **self.options)
        self.assertEqual(asyncio.run(host.tick()), {'status': 'DISABLED'})
        self.assertEqual(self.f.requests, [])
        self.assertIsNone(host.queue.claim())
        self.assertFalse((self.path / 'builder.started.json').exists())

    def test_fake_end_to_end_retains_artifact_and_never_repeats(self):
        host = DevelopmentHost(self.path, enabled=True, **self.options)
        self.assertEqual(asyncio.run(host.tick())['status'], 'TICK_COMPLETED')
        self.assertEqual(len(self.f.requests), 2)
        artifact = json.loads((self.path / 'attempt.json').read_text())
        self.assertFalse(artifact['release_authorized'])
        self.assertTrue((self.path / 'reviewer.completed.json').exists())
        self.assertEqual(asyncio.run(host.tick())['status'], 'IDLE_OR_PAUSED')
        with self.assertRaises(FileExistsError):
            DevelopmentHost(self.path, enabled=True, **self.options)
        self.assertEqual(len(self.f.requests), 2)

    def test_mismatched_contract_rejected_before_directory_creation(self):
        self.options['task'] = replace(self.options['task'], contract_digest='sha256:'+'0'*64)
        with self.assertRaises(StateError):
            DevelopmentHost(self.path, **self.options)
        self.assertFalse(self.path.exists())

    def test_uncertain_call_consumed_and_review_not_called(self):
        self.f.fail_transport = True
        host = DevelopmentHost(self.path, enabled=True, **self.options)
        self.assertEqual(asyncio.run(host.tick())['status'], 'NEEDS_RECONCILIATION')
        self.assertEqual(asyncio.run(host.tick())['status'], 'IDLE_OR_PAUSED')
        self.assertEqual(len(self.f.requests), 1)
        self.assertTrue((self.path / 'builder.started.json').exists())
        self.assertFalse((self.path / 'reviewer.started.json').exists())

    def test_missing_injected_credential_stops_before_transport(self):
        self.f.builder.credential_source = EnvironmentProviderCredentialLeaseSource(environment={})
        host = DevelopmentHost(self.path, enabled=True, **self.options)
        self.assertEqual(asyncio.run(host.tick())['status'], 'NEEDS_RECONCILIATION')
        self.assertEqual(self.f.requests, [])
        self.assertEqual(asyncio.run(host.tick())['status'], 'IDLE_OR_PAUSED')

    def test_injected_fake_secret_never_enters_artifacts(self):
        secret = 'offline-fake-key-not-a-real-credential'
        source = EnvironmentProviderCredentialLeaseSource(
            environment={'FACTORY_OPENAI_API_KEY': secret})
        self.f.builder.credential_source = self.f.reviewer.credential_source = source
        host = DevelopmentHost(self.path, enabled=True, **self.options)
        self.assertEqual(asyncio.run(host.tick())['status'], 'TICK_COMPLETED')
        for path in self.path.iterdir():
            self.assertNotIn(secret.encode(), path.read_bytes())
        self.assertNotIn(secret, json.dumps(self.f.requests))

    def test_delivery_survives_host_and_serialization_without_mutable_authority(self):
        delivery = {'mode': 'complete_task_single_proposal',
            'required_changed_paths': [self.f.f.f.path], 'test_command': ['node', '--test']}
        host = DevelopmentHost(self.path, enabled=True, delivery=delivery, **self.options)
        delivery['test_command'].append('untrusted-change')
        self.assertEqual(asyncio.run(host.tick())['status'], 'TICK_COMPLETED')
        wire = self.f.requests[0]
        turn = json.loads(wire['input'])
        self.assertEqual(turn['delivery']['test_command'], ['node', '--test'])
        self.assertIn('exactly one builder', wire['instructions'])
        self.assertIn('complete implementation and regression tests', wire['instructions'])
        self.assertEqual(len(self.f.requests), 2)
        self.assertEqual(asyncio.run(host.tick())['status'], 'IDLE_OR_PAUSED')

    def test_invalid_delivery_never_reaches_provider(self):
        delivery = {'mode': 'complete_task_single_proposal',
            'required_changed_paths': ['.env'], 'test_command': ['node', '--test']}
        host = DevelopmentHost(self.path, enabled=True, delivery=delivery, **self.options)
        self.assertEqual(asyncio.run(host.tick())['result']['phase'], 'BINDING')
        self.assertEqual(self.f.requests, [])
        self.assertEqual(asyncio.run(host.tick())['status'], 'IDLE_OR_PAUSED')

    def test_test_receipt_is_durable_before_review_failure(self):
        host = DevelopmentHost(self.path, enabled=True, **self.options)
        async def fail_review(turn):
            evidence = json.loads((self.path / 'tests.json').read_text())
            self.assertEqual(evidence['test_receipt']['exit_code'], 0)
            self.assertEqual(evidence['test_observation']['status'], 'TESTS_PASSED_REVIEW_REQUIRED')
            self.assertFalse(evidence['release_authorized'])
            raise RuntimeError('private failure after durable tests')
        host.runner.reviewer = fail_review
        result = asyncio.run(host.tick())
        self.assertEqual(result['result']['phase'], 'REVIEW')
        self.assertTrue((self.path / 'tests.json').exists())
        self.assertFalse((self.path / 'attempt.json').exists())
        self.assertNotIn('private failure', json.dumps(result))
        self.assertEqual(asyncio.run(host.tick())['status'], 'IDLE_OR_PAUSED')

    def test_test_evidence_collision_preserves_prior_bytes_and_blocks_review(self):
        host = DevelopmentHost(self.path, enabled=True, **self.options)
        (self.path / 'tests.json').write_bytes(b'prior-evidence')
        result = asyncio.run(host.tick())
        self.assertEqual(result['result']['phase'], 'TEST_EVIDENCE')
        self.assertEqual((self.path / 'tests.json').read_bytes(), b'prior-evidence')
        self.assertEqual(len(self.f.requests), 1)
        self.assertFalse((self.path / 'reviewer.started.json').exists())
        self.assertEqual(asyncio.run(host.tick())['status'], 'IDLE_OR_PAUSED')

    def test_failed_test_receipt_is_retained_without_review(self):
        self.f.f.exit_code = 1
        host = DevelopmentHost(self.path, enabled=True, **self.options)
        self.assertEqual(asyncio.run(host.tick())['status'], 'REJECTED')
        evidence = json.loads((self.path / 'tests.json').read_text())
        self.assertEqual(evidence['test_receipt']['exit_code'], 1)
        self.assertEqual(evidence['test_observation']['status'], 'TESTS_FAILED')
        self.assertEqual(len(self.f.requests), 1)
