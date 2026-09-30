import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from request_acceptance_inspector_agreement import (
    CONFIRMATION,
    MODEL,
    preflight,
    request_agreement,
)


class InspectorAgreementRequestTests(unittest.TestCase):
    def _client(self):
        calls = []

        class Client:
            def get_use_case_for_model_access(self):
                calls.append(("get_use_case_for_model_access",))
                return {"formData": b"private use case"}

            def list_foundation_model_agreement_offers(self, **kwargs):
                calls.append(("list_foundation_model_agreement_offers", kwargs))
                return {
                    "modelId": MODEL,
                    "offers": [{"offerToken": "private offer token"}],
                }

            def create_foundation_model_agreement(self, **kwargs):
                calls.append(("create_foundation_model_agreement", kwargs))
                return {"modelId": MODEL}

        return Client(), calls

    def test_preflight_returns_token_without_mutation(self):
        client, calls = self._client()
        token = preflight(client)
        self.assertEqual(token, "private offer token")
        self.assertEqual(len(calls), 2)

    def test_wrong_confirmation_fails_before_aws_calls(self):
        client, calls = self._client()
        with self.assertRaisesRegex(RuntimeError, "explicit owner"):
            request_agreement(client, "NO")
        self.assertEqual(calls, [])

    def test_exact_confirmation_requests_one_agreement(self):
        client, calls = self._client()
        result = request_agreement(client, CONFIRMATION)
        self.assertEqual(result["status"], "INSPECTOR_AGREEMENT_REQUEST_SUBMITTED")
        self.assertEqual(result["model_calls"], 0)
        self.assertFalse(result["task_material_sent"])
        self.assertEqual(
            calls[-1],
            (
                "create_foundation_model_agreement",
                {"offerToken": "private offer token", "modelId": MODEL},
            ),
        )
        self.assertNotIn("private", str(result))


if __name__ == "__main__":
    unittest.main()
