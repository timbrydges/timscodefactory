import base64
import copy
import hashlib
import sys
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
import prepare_pilot002_qa_live as p
import test_pilot002_reviewer_signing as signing_fixture


class QaPreviewTests(unittest.TestCase):
    def setUp(self):
        fixture = signing_fixture.ReviewerSigningTests()
        fixture.setUp()
        self.now = fixture.now
        self.plan = fixture.plan('qa')
        self.digest = p.signing.digest(self.plan)
        sha = hashlib.sha256(b'offline-fixture').digest()
        self.package = {'sha256': sha.hex(), 'code_sha256': base64.b64encode(sha).decode(),
            'source_commit': p.signing.QA_SOURCE, 'activation_sha256': self.plan['activation_sha256'],
            'request_digest': p.signing.REQUESTS['qa'], 'role': 'qa', 'execution_enabled': False,
            'activation_authorized': False, 'signed_allowance_included': False, 'model_calls': 0, 'zip_bytes': 15}
        self.code = {'S3Bucket': p.BUCKET, 'S3Key': 'pilot-002/runtime/' + p.signing.QA_SOURCE + '/' + sha.hex() + '.zip',
            'S3ObjectVersion': 'immutable-fixture'}
        self.changes = {'Status': 'CREATE_COMPLETE', 'ExecutionStatus': 'AVAILABLE', 'StackId': p.STACK,
            'Changes': [{'Type': 'Resource', 'ResourceChange': {'LogicalResourceId': 'QaFunction',
                'ResourceType': 'AWS::Lambda::Function', 'Action': 'Modify', 'Replacement': 'False'}}]}

    def render(self, **kwargs):
        args = {'approved_digest': self.digest, 'now': self.now}
        args.update(kwargs)
        return p.render(p.baseline(), self.plan, self.package, self.code, **args)

    def test_only_qa_changes_without_iam_or_other_workers(self):
        before = p.baseline()
        after = self.render()
        self.assertEqual([name for name in before['Resources'] if before['Resources'][name] != after['Resources'][name]], ['QaFunction'])
        result = p.validate(after, self.changes, self.plan, self.package, self.code,
            approved_digest=self.digest, now=self.now)
        self.assertFalse(result['execution_authorized'])
        self.assertEqual(result['maximum_cost_micro_usd'], 0)

    def test_expired_or_changed_plan_and_mutable_package_rejected(self):
        with self.assertRaises(p.StateError):
            self.render(now=self.now + timedelta(seconds=300))
        with self.assertRaises(p.StateError):
            self.render(approved_digest='sha256:' + '0' * 64)
        for field, value in (('source_commit', p.signing.SOURCE), ('role', 'inspector'),
                             ('signed_allowance_included', True), ('model_calls', False),
                             ('activation_sha256', '0' * 64), ('request_digest', 'sha256:' + '0' * 64)):
            with self.subTest(field=field):
                original = self.package[field]
                self.package[field] = value
                with self.assertRaises(p.StateError): self.render()
                self.package[field] = original
        self.code['S3ObjectVersion'] = 'null'
        with self.assertRaises(p.StateError): self.render()

    def test_expanded_changes_replacement_and_target_substitution_rejected(self):
        after = self.render()
        for mutate in (lambda c: c.update(NextToken='more'),
                       lambda c: c['Changes'].append(copy.deepcopy(c['Changes'][0])),
                       lambda c: c['Changes'][0]['ResourceChange'].update(Replacement='True'),
                       lambda c: c['Changes'][0]['ResourceChange'].update(LogicalResourceId='InspectorFunction')):
            changes = copy.deepcopy(self.changes)
            mutate(changes)
            with self.assertRaises(p.StateError):
                p.validate(after, changes, self.plan, self.package, self.code, approved_digest=self.digest, now=self.now)


if __name__ == '__main__':
    unittest.main()
