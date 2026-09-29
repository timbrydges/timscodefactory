import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import prepare_receipt_writer_iam as gate


class ReceiptWriterAttachmentTests(unittest.TestCase):
    def test_template_changes_only_exact_two_role_attachments(self):
        gate.validate_template()
        template = json.loads(gate.TEMPLATE.read_text())
        self.assertEqual(set(template['Resources']['OwnerRole']['Properties']['ManagedPolicyArns']),
            {'arn:aws:iam::666730517561:policy/tims-software-factory-owner-receipt-writer'})

    def test_change_set_rejects_broader_role_edit(self):
        changes = [{'ResourceChange': {'LogicalResourceId': name,
            'ResourceType': 'AWS::IAM::Role', 'Action': 'Modify',
            'Replacement': 'False', 'Scope': ['Properties'],
            'Details': [{'Target': {'Name': 'ManagedPolicyArns'}}]}}
            for name in ('OwnerRole', 'InspectorRole')]
        gate.validate_changes(changes)
        changes[1]['ResourceChange']['Details'].append({'Target': {'Name': 'AssumeRolePolicyDocument'}})
        with self.assertRaisesRegex(RuntimeError, 'more than managed policies'):
            gate.validate_changes(changes)

    def test_simulation_rejects_incomplete_response(self):
        with patch.object(gate, 'aws', return_value={'EvaluationResults': []}):
            with self.assertRaisesRegex(RuntimeError, 'incomplete evidence'):
                gate._decision('role', 's3:PutObject', 'resource', encrypted=True)


if __name__ == '__main__':
    unittest.main()
