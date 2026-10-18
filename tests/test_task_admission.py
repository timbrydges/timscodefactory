import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from factory_runtime.task_admission import AuthenticatedTaskAdmission, OwnerAdmissionVerifier, plan_binding
from factory_runtime.task_queue import GenericTaskRunner, LocalTaskQueue, QueuedTask
from factory_runtime.worker import digest
from factory_state.model import OWNER_IDENTITY, StateError
from factory_state.scope import canonical


class FixtureVerifier:
    """Authentication boundary double, not a valid owner signature or signer."""
    def __init__(self, payload):
        self.expected = canonical(payload)
        self.revoked = False

    def verify(self, payload, signature, now):
        if self.revoked or canonical(payload) != self.expected or signature != b'x' * 64:
            raise StateError('fixture authentication rejected')


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.queue = LocalTaskQueue(Path(self.tmp.name) / 'queue.db')
        self.now = datetime(2026, 10, 18, 20, tzinfo=timezone.utc)
        self.raw = (Path(__file__).resolve().parents[1] /
                    'factory/projects/bonus-library-pagination/task.json').read_bytes()
        self.spec = json.loads(self.raw)
        self.tasks = [QueuedTask('entry-' + str(i), 'factory', self.spec['task_id'], 'activation',
            'a' * 40, digest(self.raw), state) for i, state in enumerate(['IMPLEMENTATION','INSPECTION','QA'])]
        self.args = dict(plan_id='plan-one', repository=self.spec['repository'],
            target_commit=self.spec['target_commit'], contract_bytes=self.raw, tasks=self.tasks)
        self.payload = {'kind': 'factory_queue_admission_v1', 'owner': OWNER_IDENTITY,
            'receipt_id': 'receipt-one', 'issued_at': int(self.now.timestamp()),
            'expires_at': int(self.now.timestamp()) + 3600, 'plan': plan_binding(**self.args),
            'execution_authorized': False, 'spending_authorized': False,
            'signing_authorized': False, 'release_authorized': False}
        self.verifier = FixtureVerifier(self.payload)
        self.admission = AuthenticatedTaskAdmission(self.queue, verifier=self.verifier, clock=lambda: self.now)

    def admit(self, **changes):
        self.admission.admit(self.payload, b'x' * 64, **{**self.args, **changes})

    def test_valid_fixture_admission_is_atomic_and_replay_does_not_reset(self):
        self.admit(); self.queue.pause(False)
        self.queue.claim(); self.admit()
        self.assertEqual(self.queue.inspect('entry-0')['status'], 'STARTED')
        self.assertIsNone(self.queue.claim())

    def test_changed_source_target_contract_and_task_are_rejected(self):
        for change in [dict(target_commit='b' * 40), dict(repository='other/repo'),
                       dict(contract_bytes=self.raw+b' '), dict(tasks=[replace(t,source_commit='b'*40) for t in self.tasks])]:
            with self.subTest(change=change), self.assertRaises(StateError): self.admit(**change)
        self.assertIsNone(self.queue.inspect('entry-0'))

    def test_forged_receipt_rejected_before_queue_write(self):
        with self.assertRaises(StateError):
            self.admission.admit(self.payload,b'y'*64,**self.args)
        self.assertIsNone(self.queue.inspect('entry-0'))

    def test_expiry_revocation_and_authority_flags_fail_closed(self):
        for field,value in [('expires_at',int(self.now.timestamp())),('owner','other'),
                            ('spending_authorized',True),('execution_authorized',True),
                            ('issued_at',True)]:
            payload={**self.payload,field:value}
            with self.subTest(field=field), self.assertRaises(StateError):
                self.admission.admit(payload,b'x'*64,**self.args)
        self.verifier.revoked=True
        with self.assertRaises(StateError): self.admit()

    def test_reused_receipt_id_for_different_plan_rolls_back(self):
        self.admit()
        args={**self.args,'plan_id':'plan-two','tasks':[replace(t,entry_id=t.entry_id+'-two') for t in self.tasks]}
        payload={**self.payload,'plan':plan_binding(**args)}
        self.verifier.expected=canonical(payload)
        with self.assertRaises(sqlite3.IntegrityError):
            self.admission.admit(payload,b'x'*64,**args)
        self.assertIsNone(self.queue.inspect('entry-0-two'))

    def test_unsigned_local_plan_cannot_use_authenticated_resolver(self):
        self.queue.enqueue_plan(**self.args); self.queue.pause(False)
        calls=[]
        resolver=self.admission.scheduler_resolver(lambda t:calls.append(t))
        self.assertEqual(GenericTaskRunner(self.queue,resolver,enabled=True).tick()['status'],'NEEDS_RECONCILIATION')
        self.assertEqual(calls,[])

    def test_admission_rechecked_at_dispatch_after_expiry_or_revocation(self):
        self.admit(); self.queue.pause(False)
        calls=[]
        resolver=self.admission.scheduler_resolver(lambda t:calls.append(t))
        self.now+=timedelta(hours=1)
        self.assertEqual(GenericTaskRunner(self.queue,resolver,enabled=True).tick()['status'],'NEEDS_RECONCILIATION')
        self.assertEqual(calls,[])

    def test_revocation_after_admission_blocks_resolver(self):
        self.admit(); self.queue.pause(False); self.verifier.revoked=True
        calls=[]
        resolver=self.admission.scheduler_resolver(lambda t:calls.append(t))
        self.assertEqual(GenericTaskRunner(self.queue,resolver,enabled=True).tick()['status'],'NEEDS_RECONCILIATION')
        self.assertEqual(calls,[])

    def test_key_loader_requires_owner_and_real_verifier_rejects_invalid_signature(self):
        # Published RFC8032 public key; no private key or signing occurs.
        der=bytes.fromhex('302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        pem=b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(der)+b'\n-----END PUBLIC KEY-----\n'
        for keys in [{},{OWNER_IDENTITY:pem}]:
            with self.assertRaises(StateError):
                OwnerAdmissionVerifier(lambda now:keys).verify(self.payload,b'x'*64,self.now)


if __name__=='__main__': unittest.main()
