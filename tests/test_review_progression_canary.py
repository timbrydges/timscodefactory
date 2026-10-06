import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock
from scripts.review_progression_canary import run,TABLE
from factory_state.model import StateError
try:
    import boto3
    from moto import mock_aws
except ImportError:
    mock_aws=None


class CanaryBoundaryTests(unittest.TestCase):
    def test_invalid_source_cannot_access_database(self):
        db=Mock()
        with self.assertRaises(StateError):run(db,'main',Path('unused'))
        db.get_item.assert_not_called();db.put_item.assert_not_called()
    def test_existing_journal_prevents_mutations(self):
        db=Mock();db.get_item.return_value={}
        with tempfile.TemporaryDirectory() as directory:
            journal=Path(directory)/'journal';journal.write_text('previous attempt')
            with self.assertRaises(FileExistsError):run(db,'a'*40,journal)
        db.put_item.assert_not_called();db.transact_write_items.assert_not_called()


@unittest.skipIf(mock_aws is None,'Optional moto DynamoDB integration')
class CanaryIntegrationTests(unittest.TestCase):
    def test_both_review_gates_persist_and_repeated_canary_is_refused(self):
        with mock_aws(),tempfile.TemporaryDirectory() as directory:
            db=boto3.client('dynamodb',region_name='ca-central-1')
            db.create_table(TableName=TABLE,KeySchema=[{'AttributeName':'PK','KeyType':'HASH'},
                {'AttributeName':'SK','KeyType':'RANGE'}],AttributeDefinitions=[
                {'AttributeName':'PK','AttributeType':'S'},{'AttributeName':'SK','AttributeType':'S'}],
                BillingMode='PAY_PER_REQUEST')
            result=run(db,'a'*40,Path(directory)/'first')
            self.assertEqual([r['state'] for r in result['results']],['QA','SECURITY_REVIEW'])
            self.assertEqual(result['model_calls'],0)
            self.assertFalse(result['independent_review_proven'])
            with self.assertRaises(StateError):run(db,'a'*40,Path(directory)/'second')
            self.assertFalse((Path(directory)/'second').exists())
