import copy
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from factory_runtime.google_qa import MODEL, request_body
from factory_runtime.google_qa_boundary import KEY, TABLE
from factory_runtime.google_qa_reservation import GoogleQaReservedAttemptStore
from factory_runtime.google_qa_reconcile import inspect_item, observe
from factory_runtime.review_preparation import BINDING, parse_assessment, prepare
from factory_state.model import StateError
from factory_state.scope import canonical


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 3, tzinfo=timezone.utc)
        self.source = 'a'*40
        self.packet = prepare(ROOT, role='qa')
        client = Mock()
        GoogleQaReservedAttemptStore(TABLE, client).begin(
            request_bytes=request_body(self.packet, root=ROOT), approval_digest='sha256:'+'b'*64,
            source_commit=self.source, reserved_micro_usd=40000, approved_cap_micro_usd=50000,
            pricing_digest='sha256:'+'c'*64, approval_expires_at=self.now+timedelta(hours=1),
            pricing_expires_at=self.now+timedelta(hours=2), now=self.now)
        self.item = client.put_item.call_args.kwargs['Item']

    def inspect(self, item, **kwargs):
        return inspect_item(item, root=ROOT, source_commit=self.source,
                            observed_at=kwargs.get('observed_at', self.now))

    def completed(self):
        assessment = parse_assessment(canonical({**{k:self.packet[k] for k in BINDING},
            'verdict':'ACCEPTED','rationale':'Source review','findings':[]}), self.packet, root=ROOT)
        value = {'assessment':assessment,'provider_family':'google','model_id':MODEL,
            'input_tokens':2931,'output_tokens_including_thinking':100,
            'status':'UNAUTHENTICATED_PROVIDER_RESPONSE','gate_authority':False}
        item = copy.deepcopy(self.item)
        item.update(status={'S':'COMPLETE'}, response={'S':canonical(value).decode()})
        return item

    def test_absence_is_snapshot_and_never_permission_to_generate(self):
        client = Mock(); client.get_item.return_value = {}
        result = observe(client, root=ROOT, source_commit=self.source, observed_at=self.now)
        self.assertEqual(result['status'], 'ABSENT_AT_OBSERVATION_NOT_AUTHORIZED')
        self.assertFalse(result['retry_authorized']); self.assertFalse(result['generation_authorized'])
        client.get_item.assert_called_once_with(TableName=TABLE, Key=KEY, ConsistentRead=True)
        self.assertEqual([call[0] for call in client.mock_calls], ['get_item'])

    def test_started_and_expired_holds_never_release_or_retry(self):
        for now in (self.now, self.now+timedelta(days=2)):
            result = self.inspect(self.item, observed_at=now)
            self.assertEqual(result['status'], 'STARTED_HELD_OUTCOME_UNKNOWN')
            self.assertFalse(result['reservation_released']); self.assertFalse(result['retry_authorized'])
            self.assertEqual(result['approval_or_pricing_expired'], now != self.now)

    def test_completed_retains_hold_and_has_no_gate_authority(self):
        result = self.inspect(self.completed())
        self.assertEqual(result['status'], 'COMPLETE_UNSIGNED_HOLD_RETAINED')
        self.assertEqual(result['assessment_verdict'], 'ACCEPTED')
        self.assertFalse(result['gate_authority']); self.assertFalse(result['generation_authorized'])
        self.assertFalse(result['reservation_released'])
        self.assertNotIn('rationale', json.dumps(result))

    def test_legacy_claim_never_masquerades_as_reserved(self):
        from factory_runtime.google_qa_reconcile import BASE
        result = self.inspect({k:v for k,v in self.item.items() if k in BASE})
        self.assertEqual(result['status'], 'LEGACY_UNRESERVED_REQUIRES_RECONCILIATION')
        self.assertFalse(result['generation_authorized'])

    def test_wrong_scope_partial_hold_and_malformed_rows_rejected(self):
        for field, value in [('source_commit',{'S':'d'*40}), ('request_digest',{'S':'sha256:'+'d'*64}),
            ('PK',{'S':'another activation'}), ('pricing_digest',{'S':'bad'}),
            ('reservation_status',{'S':'RELEASED'}), ('status',{'S':'FAILED'}),
            ('reserved_micro_usd',{'N':'50001'}), ('reserved_micro_usd',{'N':'1.0'}),
            ('approved_cap_micro_usd',{'N':'1000001'}), ('claimed_at',{'S':'2026-10-04T00:00:00+00:00'}),
            ('approval_expires_at',{'S':self.now.isoformat()}), ('claimed_at',{'S':'2026-10-03'}),
            ('extra',{'S':'ignored field'})]:
            with self.subTest(field=field,value=value), self.assertRaises(StateError):
                self.inspect({**self.item,field:value})
        missing = copy.deepcopy(self.item); del missing['pricing_digest']
        with self.assertRaises(StateError): self.inspect(missing)
        with self.assertRaises(StateError): self.inspect({})

    def test_completed_forged_assessment_and_usage_rejected(self):
        for change in ('authority','candidate','provider','usage','unknown','duplicate','missing'):
            item = self.completed(); value = json.loads(item['response']['S'])
            if change == 'authority': value['assessment']['gate_authority'] = True
            elif change == 'candidate': value['assessment']['candidate_commit'] = 'e'*40
            elif change == 'provider': value['provider_family'] = 'anthropic'
            elif change == 'usage': value['input_tokens'] = True
            elif change == 'unknown': value['extra'] = True
            elif change == 'missing': del value['assessment']['findings']
            item['response']['S'] = json.dumps(value)
            if change == 'duplicate': item['response']['S'] = item['response']['S'][:-1]+',"gate_authority":false}'
            with self.subTest(change=change), self.assertRaises(StateError): self.inspect(item)

    def test_read_timeout_sanitized_no_retry_and_invalid_scope_before_read(self):
        client = Mock(); client.get_item.side_effect = TimeoutError('PRIVATE')
        with self.assertRaises(StateError) as caught:
            observe(client, root=ROOT, source_commit=self.source, observed_at=self.now)
        self.assertNotIn('PRIVATE', str(caught.exception))
        self.assertEqual([call[0] for call in client.mock_calls], ['get_item'])
        client.reset_mock()
        with self.assertRaises(StateError):
            observe(client, root=ROOT, source_commit='invalid', observed_at=self.now)
        client.get_item.assert_not_called()


if __name__ == '__main__': unittest.main()
