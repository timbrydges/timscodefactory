import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from factory_runtime.acceptance_claim import DynamoDBAcceptanceClaimStore
from factory_state.model import StateError

DIGEST = 'sha256:' + 'a' * 64


class Table:
    def __init__(self):
        self.rows = {}

    def put_item(self, *, TableName, Item, ConditionExpression):
        key = (Item['PK']['S'], Item['SK']['S'])
        if key in self.rows:
            raise RuntimeError('conditional write failed')
        self.rows[key] = Item

    def get_item(self, *, TableName, Key, ConsistentRead):
        return {'Item': self.rows.get((Key['PK']['S'], Key['SK']['S']))}

    def update_item(self, *, TableName, Key, UpdateExpression,
                    ConditionExpression, ExpressionAttributeNames,
                    ExpressionAttributeValues):
        key = (Key['PK']['S'], Key['SK']['S'])
        item = self.rows[key]
        if item['status'] != {'S': 'STARTED'} or item['event_digest'] != ExpressionAttributeValues[':digest']:
            raise RuntimeError('conditional update failed')
        item['status'] = {'S': 'COMPLETE'}
        item['response'] = ExpressionAttributeValues[':response']


class ClaimTests(unittest.TestCase):
    def test_started_is_unknown_and_completed_is_replayed_without_reinvocation(self):
        store = DynamoDBAcceptanceClaimStore('tims-factory-acceptance-broker-claims', Table())
        binding = dict(activation_id='acceptance-1', dispatch_id='dispatch-1', event_digest=DIGEST)
        self.assertIsNone(store.begin(**binding))
        with self.assertRaisesRegex(StateError, 'reconciliation'):
            store.begin(**binding)
        store.complete(**binding, response={'result': 'bounded'})
        self.assertEqual(store.begin(**binding), {'result': 'bounded'})
        with self.assertRaisesRegex(StateError, 'conflicted'):
            store.begin(**{**binding, 'event_digest': 'sha256:' + 'b' * 64})


if __name__ == '__main__':
    unittest.main()
