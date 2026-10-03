import concurrent.futures
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from factory_runtime.google_qa_boundary import GoogleQaAttemptStore, KEY, TABLE
from factory_runtime.google_qa_reservation import GoogleQaReservedAttemptStore
from factory_state.model import StateError


class AtomicTable:
    def __init__(self):
        self.lock = threading.Lock()
        self.item = None

    def put_item(self, **kwargs):
        assert kwargs['TableName'] == TABLE
        assert kwargs['ConditionExpression'] == 'attribute_not_exists(PK) AND attribute_not_exists(SK)'
        with self.lock:
            if self.item is not None:
                raise RuntimeError('conditional failure')
            self.item = kwargs['Item']


class ReservationTests(unittest.TestCase):
    def args(self):
        now = datetime(2026, 10, 3, tzinfo=timezone.utc)
        return dict(request_bytes=b'exact candidate request', approval_digest='sha256:'+'a'*64,
            source_commit='b'*40, reserved_micro_usd=40000, approved_cap_micro_usd=50000,
            pricing_digest='sha256:'+'c'*64, now=now,
            approval_expires_at=now+timedelta(hours=1), pricing_expires_at=now+timedelta(hours=2))

    def test_concurrent_process_equivalents_can_hold_only_once(self):
        table = AtomicTable()
        def attempt(_):
            try:
                GoogleQaReservedAttemptStore(TABLE, table).begin(**self.args())
                return True
            except StateError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(32))), 1)
        self.assertEqual(table.item['reserved_micro_usd'], {'N': '40000'})
        self.assertEqual(table.item['reservation_status'], {'S': 'HELD'})
        self.assertEqual(table.item['PK'], KEY['PK'])

    def test_legacy_claim_blocks_reserved_claim_and_reverse(self):
        for legacy_first in (True, False):
            table = AtomicTable()
            reserved = GoogleQaReservedAttemptStore(TABLE, table)
            old = GoogleQaAttemptStore(TABLE, table)
            args = {k:v for k,v in self.args().items() if k in ('request_bytes','approval_digest','source_commit')}
            if legacy_first:
                old.begin(**args)
                with self.assertRaises(StateError): reserved.begin(**self.args())
            else:
                reserved.begin(**self.args())
                with self.assertRaises(StateError): old.begin(**args)

    def test_expiry_money_types_and_over_cap_fail_before_write(self):
        args = self.args()
        for change in ({'reserved_micro_usd': True}, {'reserved_micro_usd': 50001},
                       {'reserved_micro_usd': 0}, {'approved_cap_micro_usd': 1.1},
                       {'approved_cap_micro_usd': 1000001}, {'pricing_digest': 'bad'},
                       {'approval_expires_at': args['now']}, {'pricing_expires_at': args['now']},
                       {'now': datetime(2026,10,3)}):
            client = Mock()
            with self.assertRaises(StateError):
                GoogleQaReservedAttemptStore(TABLE, client).begin(**{**args, **change})
            client.put_item.assert_not_called()

    def test_timeout_after_write_leaves_hold_and_never_retries(self):
        table = AtomicTable()
        def uncertain(**kwargs):
            table.put_item(**kwargs)
            raise TimeoutError('PRIVATE diagnostic')
        client = Mock(); client.put_item.side_effect = uncertain
        with self.assertRaises(StateError) as error:
            GoogleQaReservedAttemptStore(TABLE, client).begin(**self.args())
        self.assertNotIn('PRIVATE', str(error.exception))
        self.assertEqual(client.put_item.call_count, 1)
        client.get_item.assert_not_called()
        self.assertEqual(table.item['reservation_status'], {'S': 'HELD'})
        with self.assertRaises(StateError):
            GoogleQaReservedAttemptStore(TABLE, table).begin(**self.args())

    def test_completion_does_not_release_hold(self):
        client = Mock(); store = GoogleQaReservedAttemptStore(TABLE, client)
        digest = store.begin(**self.args())
        store.complete(request_digest=digest,
            response={'status':'UNAUTHENTICATED_PROVIDER_RESPONSE','gate_authority':False})
        update = client.update_item.call_args.kwargs
        self.assertEqual(update['UpdateExpression'], 'SET #s=:done, #r=:response')
        self.assertNotIn('reservation_status', str(update))
        client.delete_item.assert_not_called()


if __name__ == '__main__': unittest.main()
