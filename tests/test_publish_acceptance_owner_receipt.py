import json
import sys
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src'), str(ROOT / 'tests')]

import yaml
from factory_runtime.receipt_transport import receipt_plan_digest
from factory_state.model import StateError
from prepare_acceptance_job import PLAN_FIELDS
from publish_acceptance_owner_receipt import publish, validate_plan
import test_prepare_acceptance_activation_bundle as bundle_fixtures
from test_receipt_publication import FakeS3, Signer


class OwnerReceiptTests(unittest.TestCase):
    def material(self):
        binding, raw, now = bundle_fixtures.ActivationBundleTests().material()
        job = json.loads(raw)
        return {key: job[key] for key in PLAN_FIELDS}, binding['source_commit'], now

    def test_publishes_only_owner_receipt_without_activating_or_claiming_review(self):
        document, commit, now = self.material()
        writer, signer = FakeS3(), Signer('tim_brydges')
        sts = Mock()
        sts.get_caller_identity.return_value = {'Account': '666730517561',
            'Arn': 'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-owner/test'}
        result = publish(document, document['plan_digest'], commit, now=now,
                         signer=signer, writer=writer, sts=sts)
        self.assertEqual(result['status'], 'OWNER_RECEIPT_PUBLISHED')
        self.assertFalse(result['activation_authorized'])
        self.assertEqual(result['reviewer_receipts_published'], 0)
        self.assertEqual(len(signer.calls), 1)
        self.assertEqual(len(writer.calls), 1)
        self.assertTrue(writer.calls[0]['Key'].endswith('/owner.json'))
        self.assertEqual(writer.calls[0]['IfNoneMatch'], '*')

    def test_wrong_digest_source_expiry_and_identity_fail_before_signing(self):
        document, commit, now = self.material()
        for digest, source, at in (
            ('sha256:' + '0' * 64, commit, now),
            (document['plan_digest'], 'b' * 40, now),
            (document['plan_digest'], commit, now + timedelta(hours=1))):
            signer, writer, sts = Signer('tim_brydges'), FakeS3(), Mock()
            with self.subTest(source=source, at=at), self.assertRaises(StateError):
                publish(document, digest, source, now=at, signer=signer, writer=writer, sts=sts)
            self.assertEqual(signer.calls, [])
            self.assertEqual(writer.calls, [])
            sts.get_caller_identity.assert_not_called()
        sts.get_caller_identity.return_value = {'Account': '666730517561',
            'Arn': 'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-inspector/test'}
        with self.assertRaisesRegex(StateError, 'isolated role'):
            publish(document, document['plan_digest'], commit, now=now,
                    signer=signer, writer=writer, sts=sts)
        self.assertEqual(signer.calls, [])

    def test_recomputed_digest_cannot_authorize_expanded_payload_or_wrong_factory(self):
        document, commit, now = self.material()
        plan = validate_plan(document, document['plan_digest'], commit, now=now)
        for changes in ({'extra': 'permission'}, {'factory_id': 'other-factory'}):
            cap = {**plan.capability_payload, **changes}
            changed = replace(plan, capability_payload=cap)
            proposed = {**document, 'capability_payload': cap, 'plan_digest': receipt_plan_digest(changed)}
            with self.subTest(changes=changes), self.assertRaises(StateError):
                validate_plan(proposed, proposed['plan_digest'], commit, now=now)

    def test_workflow_is_owner_only_main_only_off_by_default_and_cannot_rerun(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/factory-owner-signing.yml').read_text())
        job = workflow['jobs']['publish_owner_receipt']
        for condition in ("github.ref == 'refs/heads/main'", "github.actor_id == '214414801'",
                          'github.run_attempt == 1', "vars.FACTORY_OWNER_RECEIPT_PUBLICATION_ENABLED == 'true'"):
            self.assertIn(condition, job['if'])
        self.assertEqual(job['environment'], 'production')
        self.assertEqual(job['env']['AWS_MAX_ATTEMPTS'], '1')
        commands = '\n'.join(step.get('run', '') for step in job['steps'])
        self.assertNotIn('${{ inputs.', commands)
        self.assertIn('publish_acceptance_owner_receipt.py', commands)


if __name__ == '__main__':
    unittest.main()
