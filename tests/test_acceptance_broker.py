import base64
import hashlib
import io
import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from factory_runtime.acceptance_broker import AcceptanceBrokerExecutor
from factory_state.model import StateError


ARN = 'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-provider-broker:4'


class Client:
    def __init__(self):
        self.meta = SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts': 1}),
                                    endpoint_url='https://lambda.ca-central-1.amazonaws.com')
        self.calls = []
        self.mutate = lambda response: response

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        event = json.loads(kwargs['Payload'])
        output = b'fingerprint.py result'
        reply = {key: event[key] for key in ('activation_id', 'dispatch_id', 'source_commit',
                 'contract_digest', 'task_id', 'target_alias', 'model_id', 'input_digest')}
        reply.update(output_base64=base64.b64encode(output).decode(),
                     output_digest='sha256:' + hashlib.sha256(output).hexdigest(),
                     cost_usd='0.12', provider_calls=1)
        return {'StatusCode': 200, 'ExecutedVersion': '4',
                'Payload': io.BytesIO(json.dumps(self.mutate(reply)).encode())}


class AcceptanceBrokerTests(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        self.executor = AcceptanceBrokerExecutor(self.client, ARN)
        self.request = dict(activation_id='acceptance-1', dispatch_id='dispatch-1',
                            source_commit='a' * 40, contract_digest='sha256:' + 'b' * 64,
                            task_id='deterministic-text-fingerprint',
                            target_alias='coding_primary_sol_live', model_id='gpt-5.6-sol',
                            input_bytes=b'approved input', maximum_cost_usd=Decimal('0.25'))

    def test_exact_bounded_call_has_no_provider_credential_in_role_event(self):
        self.assertEqual(self.executor.execute(**self.request), b'fingerprint.py result')
        event = json.loads(self.client.calls[0]['Payload'])
        self.assertEqual(self.client.calls[0]['FunctionName'], ARN)
        self.assertEqual(event['input_digest'],
                         'sha256:' + hashlib.sha256(self.request['input_bytes']).hexdigest())
        self.assertEqual(event['dispatch_id'], 'dispatch-1')
        self.assertNotIn('credential', json.dumps(event))

    def test_wrong_task_or_cost_fails_before_invocation(self):
        for change in (dict(task_id='other'), dict(maximum_cost_usd=Decimal('0.26'))):
            with self.subTest(change=change):
                with self.assertRaisesRegex(StateError, 'owner-approved'):
                    self.executor.execute(**{**self.request, **change})
        self.assertEqual(self.client.calls, [])

    def test_changed_response_or_overspend_never_returns_output(self):
        for change in (dict(dispatch_id='other'), dict(cost_usd='0.26'),
                       dict(provider_calls=2), dict(output_digest='sha256:' + '0' * 64)):
            with self.subTest(change=change):
                self.client.mutate = lambda response, changed=change: {**response, **changed}
                with self.assertRaises(StateError):
                    self.executor.execute(**self.request)

    def test_only_pinned_region_version_and_no_retry(self):
        self.client.meta.config.retries['total_max_attempts'] = 2
        with self.assertRaisesRegex(StateError, 'no retries'):
            AcceptanceBrokerExecutor(self.client, ARN)
        self.assertEqual(self.client.calls, [])


if __name__ == '__main__':
    unittest.main()
