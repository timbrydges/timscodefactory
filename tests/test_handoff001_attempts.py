import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from factory_runtime.handoff001_attempts import Handoff001AttemptStore, TABLE, ROLES, key
from factory_runtime.handoff001_packets import TASK
from factory_runtime.pilot002_attempts import Pilot002AttemptStore, TABLE as OLD_TABLE, key as old_key
from factory_state.model import StateError


class HandoffAttemptTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.args = dict(role='builder', request_bytes=b'complete request', source_commit='a'*40,
            approval_digest='sha256:'+'b'*64, pricing_digest='sha256:'+'c'*64,
            now=now, approval_expires_at=now+timedelta(minutes=30),
            pricing_expires_at=now+timedelta(minutes=30))
        self.db = Mock()
        self.rows = {(OLD_TABLE, old_key(role)['PK']['S']): {'status': {'S': 'COMPLETE'}} for role in ROLES}
        def put(**kw):
            self.assertEqual(kw['ConditionExpression'], 'attribute_not_exists(PK)')
            identity = (kw['TableName'], kw['Item']['PK']['S'])
            if identity in self.rows: raise RuntimeError('conditional failure')
            self.rows[identity] = kw['Item']
        self.db.put_item.side_effect = put
        self.store = Handoff001AttemptStore(self.db)

    def test_new_holds_do_not_recycle_consumed_pilot(self):
        for role in ROLES:
            digest = self.store.begin(**{**self.args, 'role': role})
            self.store.complete(role=role, request_digest=digest, output_bytes=b'signed result', actual_micro_usd=100)
            self.assertEqual(self.db.update_item.call_args.kwargs['TableName'], TABLE)
            self.assertEqual(self.db.update_item.call_args.kwargs['Key'], key(role))
            with self.assertRaises(StateError): self.store.begin(**{**self.args, 'role': role})
            with self.assertRaises(StateError): Pilot002AttemptStore(self.db).begin(**{**self.args, 'role': role})
            self.assertEqual(self.rows[(OLD_TABLE, old_key(role)['PK']['S'])], {'status': {'S': 'COMPLETE'}})
        new = [value for (table, _), value in self.rows.items() if table == TABLE]
        self.assertEqual(len(new), 3)
        self.assertTrue(all(row['task_id']['S'] == TASK for row in new))
        self.assertEqual(sum(int(row['reserved_micro_usd']['N']) for row in new), 750000)
        self.db.delete_item.assert_not_called()

    def test_uncertain_claim_never_retries_or_reads_back(self):
        self.db.put_item.side_effect = TimeoutError('unknown outcome')
        with self.assertRaises(StateError): self.store.begin(**self.args)
        self.db.put_item.assert_called_once()
        self.db.get_item.assert_not_called()
        self.db.update_item.assert_not_called()

    def test_expired_approval_and_unknown_role_do_not_write(self):
        for patch in ({'approval_expires_at': self.args['now']}, {'role': 'security'}, {'role': []}):
            with self.assertRaises(StateError): self.store.begin(**{**self.args, **patch})
        self.db.put_item.assert_not_called()

    def test_legacy_workflow_cannot_consume_fresh_rows(self):
        from factory_runtime.pilot002_workflow import run_once
        adapter, credential = Mock(), Mock()
        with self.assertRaisesRegex(StateError, 'fixed-role attempt store'):
            run_once({}, root=None, role='builder', source_commit='a'*40,
                pricing={}, readiness={}, trusted_keys={}, store=self.store,
                load_credential=credential, adapter=adapter, clock=Mock(), enabled=True)
        self.db.put_item.assert_not_called()
        adapter.build_request.assert_not_called()
        credential.assert_not_called()
