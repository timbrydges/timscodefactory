from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import patch
import test_development_host as fixtures
from factory_runtime.development_approval import compose_approved_host
from factory_state.model import StateError


class ApprovalTests(TestCase):
    def setUp(self):
        self.f = fixtures.DevelopmentHostTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        o = self.f.options
        self.now = datetime.now(timezone.utc)
        self.pins = dict(source_commit=o['task'].source_commit, contract_digest=o['task'].contract_digest,
            repository=o['snapshot'].repository, target_commit=o['snapshot'].commit,
            image_ref='sha256:'+'a'*64, model_id=o['target'].model_id, attempt_id=o['task'].entry_id,
            credential_source='injected-test-source', builder_cap='0.25', reviewer_cap='0.25',
            total_cap='0.50', max_request_bytes=42020, max_output_tokens=4096)
        self.approval = {'pins': dict(self.pins), 'expires_at': (self.now+timedelta(hours=1)).isoformat()}
        self.receipt = self.f.path.parent/'approval-consumed.json'

    def compose(self, authorized=True):
        return compose_approved_host(self.f.path, approval=self.approval, expected_pins=self.pins,
            receipt_path=self.receipt, now=self.now, owner_authorized=authorized, **self.f.options)

    def test_no_owner_approval_or_changed_pin_never_constructs(self):
        with patch('factory_runtime.development_approval.DevelopmentHost') as host:
            with self.assertRaises(StateError): self.compose(False)
            self.approval['pins']['total_cap'] = '50'
            with self.assertRaises(StateError): self.compose()
            host.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_expired_approval_never_consumes_or_constructs(self):
        self.approval['expires_at'] = self.now.isoformat()
        with self.assertRaises(StateError): self.compose()
        self.assertFalse(self.receipt.exists())

    def test_once_only_even_when_host_construction_fails(self):
        with patch('factory_runtime.development_approval.DevelopmentHost', side_effect=RuntimeError()) as host:
            with self.assertRaises(RuntimeError): self.compose()
            with self.assertRaises(FileExistsError): self.compose()
            host.assert_called_once()

    def test_runtime_bounds_checked_before_consumption(self):
        self.pins['max_output_tokens'] = 64
        self.approval['pins'] = dict(self.pins)
        with self.assertRaises(StateError): self.compose()
        self.assertFalse(self.receipt.exists())

    def test_profile_digest_without_trusted_profile_is_rejected(self):
        self.pins['execution_profile_digest'] = 'sha256:'+'a'*64
        self.approval['pins'] = dict(self.pins)
        with self.assertRaises(StateError): self.compose()
        self.assertFalse(self.receipt.exists())

    def test_generic_profile_checks_delivery_before_consuming(self):
        import json
        from factory_runtime.development_profile import TaskExecutionProfile
        spec = json.loads(self.f.options['contract_bytes'])
        profile = TaskExecutionProfile(spec['repository'], spec['task_id'],
            tuple(spec['allowed_paths']), ('python', '-m', 'unittest'))
        self.pins['execution_profile_digest'] = profile.digest
        self.approval['pins'] = dict(self.pins)
        with self.assertRaises(StateError):
            compose_approved_host(self.f.path, approval=self.approval,
                expected_pins=self.pins, receipt_path=self.receipt, now=self.now,
                owner_authorized=True, execution_profile=profile, **self.f.options)
        self.assertFalse(self.receipt.exists())
        self.f.options['delivery'] = profile.delivery
        with patch('factory_runtime.development_approval.DevelopmentHost') as host:
            compose_approved_host(self.f.path, approval=self.approval,
                expected_pins=self.pins, receipt_path=self.receipt, now=self.now,
                owner_authorized=True, execution_profile=profile, **self.f.options)
            host.assert_called_once()
        self.assertTrue(self.receipt.exists())


class PrivateSourceApprovalTests(ApprovalTests):
    def setUp(self):
        super().setUp()
        from factory_runtime.private_source import snapshot_manifest_digest
        self.pins.update(source_config_digest='sha256:'+'c'*64,
                         source_manifest_digest=snapshot_manifest_digest(self.f.options['snapshot']))
        self.approval['pins'] = dict(self.pins)

    def test_source_pins_are_accepted_as_pair_and_content_checked(self):
        with patch('factory_runtime.development_approval.DevelopmentHost') as host:
            self.compose()
            host.assert_called_once()

    def test_single_source_pin_rejected(self):
        for key in ('source_config_digest', 'source_manifest_digest'):
            with self.subTest(key=key):
                pins = dict(self.pins); del pins[key]
                self.pins, saved = pins, self.pins
                self.approval['pins'] = dict(pins)
                with self.assertRaises(StateError): self.compose()
                self.pins = saved; self.approval['pins'] = dict(saved)
        self.assertFalse(self.receipt.exists())

    def test_snapshot_differing_from_manifest_pin_never_consumes(self):
        self.pins['source_manifest_digest'] = 'sha256:'+'0'*64
        self.approval['pins'] = dict(self.pins)
        with patch('factory_runtime.development_approval.DevelopmentHost') as host:
            with self.assertRaises(StateError): self.compose()
            host.assert_not_called()
        self.assertFalse(self.receipt.exists())
