import asyncio
import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from factory_runtime.acceptance_provider_io import (
    AcceptanceContractPricingSource, AcceptanceOpenAIHTTPTransport,
)
from factory_runtime.openai_provider import OpenAIProviderPricingError, OpenAIProviderProtocolError
from factory_runtime.provider_broker_service import ResolvedProviderTarget


TARGET = ResolvedProviderTarget('openai', 'gpt-5.6-sol', 'acceptance-v1')


class FakeResponse:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, limit):
        return self.body[:limit]


class FakeOpener:
    calls = 0
    body = b'{"status":"completed"}'

    def open(self, request, *, timeout):
        self.calls += 1
        self.request = request
        self.timeout = timeout
        return FakeResponse(self.body)


class AcceptanceProviderIOTests(unittest.TestCase):
    def test_checked_in_quote_is_expired(self):
        with self.assertRaisesRegex(OpenAIProviderPricingError, 'expired'):
            asyncio.run(AcceptanceContractPricingSource(ROOT).quote(target=TARGET))

    def test_fresh_quote_requires_matching_contract_evidence(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT / 'factory', root / 'factory')
        shutil.copytree(ROOT / 'docs', root / 'docs')
        path = root / 'factory/autonomy/operating-contract.yaml'
        contract = yaml.safe_load(path.read_text())
        observed = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat().replace('+00:00', 'Z')
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace('+00:00', 'Z')
        contract['pricing_reference'].update(observed_at=observed, expires_at=expires)
        path.write_text(yaml.safe_dump(contract, sort_keys=False))
        evidence = root / contract['pricing_reference']['evidence']
        with self.assertRaisesRegex(OpenAIProviderPricingError, 'invalid'):
            asyncio.run(AcceptanceContractPricingSource(root).quote(target=TARGET))
        data = json.loads(evidence.read_text())
        data.update(observed_at=observed, expires_at=expires)
        evidence.write_text(json.dumps(data))
        schema_path = root / 'factory/schemas/autonomy-operating-contract.schema.json'
        schema = json.loads(schema_path.read_text())
        schema['properties']['pricing_reference']['properties']['observed_at']['const'] = observed
        schema['properties']['pricing_reference']['properties']['expires_at']['const'] = expires
        schema_path.write_text(json.dumps(schema))
        quote = asyncio.run(AcceptanceContractPricingSource(root).quote(target=TARGET))
        self.assertEqual(quote.input_usd_per_million_tokens, 4)
        self.assertEqual(quote.output_usd_per_million_tokens, 20)

    def test_one_exact_bounded_http_call(self):
        opener = FakeOpener()
        transport = AcceptanceOpenAIHTTPTransport(opener=opener)
        headers = {'Authorization': 'Bearer fake-token-12345678',
                   'Content-Type': 'application/json', 'Accept': 'application/json'}
        response = asyncio.run(transport.post_json(
            endpoint='https://api.openai.com/v1/responses', headers=headers,
            body=b'{}', timeout_seconds=12))
        self.assertEqual((opener.calls, opener.timeout, response.status_code), (1, 12, 200))
        self.assertEqual(opener.request.full_url, 'https://api.openai.com/v1/responses')
        self.assertEqual(opener.request.get_method(), 'POST')
        self.assertEqual(response.body, opener.body)

    def test_http_rejects_wrong_endpoint_and_oversize_response(self):
        opener = FakeOpener()
        transport = AcceptanceOpenAIHTTPTransport(opener=opener)
        headers = {'Authorization': 'Bearer fake-token-12345678',
                   'Content-Type': 'application/json', 'Accept': 'application/json'}
        with self.assertRaises(OpenAIProviderProtocolError):
            asyncio.run(transport.post_json(endpoint='https://example.com/', headers=headers,
                                             body=b'{}', timeout_seconds=12))
        self.assertEqual(opener.calls, 0)
        opener.body = b'x' * (256 * 1024 + 1)
        with self.assertRaisesRegex(OpenAIProviderProtocolError, 'byte cap'):
            asyncio.run(transport.post_json(endpoint='https://api.openai.com/v1/responses',
                                             headers=headers, body=b'{}', timeout_seconds=12))
        self.assertEqual(opener.calls, 1)


if __name__ == '__main__':
    unittest.main()
