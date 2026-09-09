from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.live_provider_activation import (  # noqa: E402
    LiveProviderActivationError,
    authorize_live_qualification,
    validate_live_provider_preparation,
)
from factory_runtime.provider_credentials import (  # noqa: E402
    EnvironmentProviderCredentialLeaseSource,
    ProviderCredentialLeaseError,
)
from factory_runtime.provider_broker_service import ResolvedProviderTarget  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class LiveProviderActivationTests(unittest.IsolatedAsyncioTestCase):
    def test_checked_in_preparation_is_quality_first_bounded_and_disabled(self):
        preparation = validate_live_provider_preparation(ROOT)
        self.assertEqual(preparation.owner, "Tim Brydges")
        self.assertEqual(preparation.baseline_model_id, "gpt-5.6-sol")
        self.assertEqual(preparation.challenger_model_id, "gpt-5.6-terra")
        self.assertEqual(preparation.max_cost_usd_per_call, Decimal("0.25"))
        self.assertEqual(preparation.max_cost_usd_per_candidate_run, Decimal("2.00"))
        self.assertEqual(preparation.max_cost_usd_per_qualification_session, Decimal("5.00"))
        self.assertTrue(preparation.all_live_targets_disabled)
        self.assertRegex(preparation.corpus_digest, r"^sha256:[0-9a-f]{64}$")

    def test_live_authorization_fails_before_credentials_while_targets_disabled(self):
        preparation = validate_live_provider_preparation(ROOT)
        with self.assertRaisesRegex(LiveProviderActivationError, "prepared but disabled"):
            authorize_live_qualification(
                ROOT,
                actor="timbrydges",
                target_alias=preparation.baseline_alias,
                corpus_digest=preparation.corpus_digest,
                source_commit="1" * 40,
                reserved_cost_usd=Decimal("1.00"),
            )

    def test_non_owner_is_rejected_before_target_activation_check(self):
        preparation = validate_live_provider_preparation(ROOT)
        with self.assertRaisesRegex(LiveProviderActivationError, "only the Factory owner"):
            authorize_live_qualification(
                ROOT,
                actor="someone-else",
                target_alias=preparation.baseline_alias,
                corpus_digest=preparation.corpus_digest,
                source_commit="1" * 40,
                reserved_cost_usd=Decimal("1.00"),
            )

    def test_spend_reservation_cannot_exceed_session_cap(self):
        preparation = validate_live_provider_preparation(ROOT)
        with self.assertRaisesRegex(LiveProviderActivationError, "session cap"):
            authorize_live_qualification(
                ROOT,
                actor="timbrydges",
                target_alias=preparation.baseline_alias,
                corpus_digest=preparation.corpus_digest,
                source_commit="1" * 40,
                reserved_cost_usd=Decimal("5.01"),
            )

    def test_catalog_drift_to_enabled_live_target_breaks_preparation(self):
        with tempfile.TemporaryDirectory() as temp:
            copy_root = Path(temp) / "repo"
            shutil.copytree(ROOT / "factory", copy_root / "factory")
            models = copy_root / "factory/profiles/provider-models.yaml"
            text = models.read_text(encoding="utf-8")
            text = text.replace(
                "coding_primary_sol_live:\n    provider_family: openai\n    model_id: \"gpt-5.6-sol\"\n    execution_mode: live\n    enabled: false",
                "coding_primary_sol_live:\n    provider_family: openai\n    model_id: \"gpt-5.6-sol\"\n    execution_mode: live\n    enabled: true",
                1,
            )
            models.write_text(text, encoding="utf-8")
            preparation = validate_live_provider_preparation(copy_root)
            self.assertFalse(preparation.all_live_targets_disabled)

    async def test_credential_source_returns_only_bounded_in_memory_lease(self):
        source = EnvironmentProviderCredentialLeaseSource(
            environment={"FACTORY_OPENAI_API_KEY": "sk-test-provider-secret-1234567890"},
            lease_ttl_seconds=300,
        )
        target = ResolvedProviderTarget(
            provider_family="openai",
            model_id="gpt-5.6-sol",
            selector_version="live-prep-v1",
        )
        lease = await source.issue(target=target)
        self.assertEqual(lease.provider_family, "openai")
        self.assertEqual(lease.audience, "api.openai.com")
        self.assertEqual(lease.token, "sk-test-provider-secret-1234567890")
        self.assertLessEqual((lease.expires_at - lease.issued_at).total_seconds(), 300)
        self.assertNotIn(lease.token, repr(lease))

    async def test_credential_source_fails_closed_when_secret_is_absent(self):
        source = EnvironmentProviderCredentialLeaseSource(environment={})
        target = ResolvedProviderTarget(
            provider_family="openai",
            model_id="gpt-5.6-sol",
            selector_version="live-prep-v1",
        )
        with self.assertRaisesRegex(ProviderCredentialLeaseError, "unavailable"):
            await source.issue(target=target)


if __name__ == "__main__":
    unittest.main()
