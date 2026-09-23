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
    SecretsManagerProviderCredentialLeaseSource,
)
from factory_runtime.provider_broker_service import ResolvedProviderTarget  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class LiveProviderActivationTests(unittest.IsolatedAsyncioTestCase):
    SECRET_ARN = (
        "arn:aws:secretsmanager:ca-central-1:666730517561:secret:"
        "tims-software-factory/provider/openai/acceptance-Ab12Cd")
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

    def test_exact_owner_approved_target_can_authorize_only_after_two_enable_switches(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            shutil.copytree(ROOT / "factory", root / "factory")
            models = root / "factory/profiles/provider-models.yaml"
            policy = root / "factory/profiles/provider-live-activation.yaml"
            models.write_text(models.read_text().replace(
                'model_id: "gpt-5.6-sol"\n    execution_mode: live\n    enabled: false',
                'model_id: "gpt-5.6-sol"\n    execution_mode: live\n    enabled: true',
                1,
            ))
            policy.write_text(policy.read_text().replace(
                "coding_primary_sol_live:\n    model_id: gpt-5.6-sol\n    role: quality_baseline\n    enabled: false",
                "coding_primary_sol_live:\n    model_id: gpt-5.6-sol\n    role: quality_baseline\n    enabled: true",
                1,
            ))
            preparation = validate_live_provider_preparation(root)
            authorization = authorize_live_qualification(
                root,
                actor="timbrydges",
                target_alias="coding_primary_sol_live",
                corpus_digest=preparation.corpus_digest,
                source_commit="1" * 40,
                reserved_cost_usd=Decimal("1.00"),
            )
            self.assertEqual(authorization.model_id, "gpt-5.6-sol")
            self.assertEqual(
                authorization.owner_authorization_event,
                "autonomy-financial-authorization-2026-09-23",
            )

    def test_unapproved_challenger_stays_denied_even_if_enabled(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            shutil.copytree(ROOT / "factory", root / "factory")
            for relative in (
                "factory/profiles/provider-models.yaml",
                "factory/profiles/provider-live-activation.yaml",
            ):
                path = root / relative
                text = path.read_text()
                marker = "coding_primary_terra_live:"
                before, after = text.split(marker, 1)
                after = after.replace("enabled: false", "enabled: true", 1)
                path.write_text(before + marker + after)
            preparation = validate_live_provider_preparation(root)
            with self.assertRaisesRegex(
                LiveProviderActivationError, "lacks exact owner authorization"
            ):
                authorize_live_qualification(
                    root,
                    actor="timbrydges",
                    target_alias="coding_primary_terra_live",
                    corpus_digest=preparation.corpus_digest,
                    source_commit="1" * 40,
                    reserved_cost_usd=Decimal("1.00"),
                )

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

    async def test_secrets_manager_source_reads_only_exact_current_secret(self):
        class Client:
            calls = []

            def get_secret_value(self, **kwargs):
                self.calls.append(kwargs)
                return {
                    "ARN": LiveProviderActivationTests.SECRET_ARN,
                    "Name": "tims-software-factory/provider/openai/acceptance",
                    "VersionId": "version-1",
                    "VersionStages": ["AWSCURRENT"],
                    "SecretString": "sk-test-provider-secret-1234567890",
                }

        client = Client()
        source = SecretsManagerProviderCredentialLeaseSource(
            client=client, secret_arn=self.SECRET_ARN)
        target = ResolvedProviderTarget(
            provider_family="openai",
            model_id="gpt-5.6-sol",
            selector_version="live-prep-v1",
        )
        lease = await source.issue(target=target)
        self.assertEqual(client.calls, [{
            "SecretId": self.SECRET_ARN,
            "VersionStage": "AWSCURRENT",
        }])
        self.assertEqual(lease.token, "sk-test-provider-secret-1234567890")
        self.assertLessEqual((lease.expires_at - lease.issued_at).total_seconds(), 300)
        self.assertNotIn(lease.token, repr(source))
        self.assertNotIn(lease.token, repr(lease))

    async def test_secrets_manager_source_rejects_identity_stage_and_binary_drift(self):
        target = ResolvedProviderTarget(
            provider_family="openai",
            model_id="gpt-5.6-sol",
            selector_version="live-prep-v1",
        )
        cases = (
            {"ARN": "wrong", "Name": "wrong", "VersionStages": ["AWSCURRENT"],
             "SecretString": "sk-test-provider-secret-1234567890"},
            {"ARN": self.SECRET_ARN,
             "Name": "tims-software-factory/provider/openai/acceptance",
             "VersionStages": ["AWSPREVIOUS"],
             "SecretString": "sk-test-provider-secret-1234567890"},
            {"ARN": self.SECRET_ARN,
             "Name": "tims-software-factory/provider/openai/acceptance",
             "VersionStages": ["AWSCURRENT"], "SecretBinary": b"forbidden",
             "SecretString": "sk-test-provider-secret-1234567890"},
        )
        for result in cases:
            class Client:
                def get_secret_value(self, **kwargs):
                    return result
            source = SecretsManagerProviderCredentialLeaseSource(
                client=Client(), secret_arn=self.SECRET_ARN)
            with self.subTest(result=result):
                with self.assertRaises(ProviderCredentialLeaseError):
                    await source.issue(target=target)


if __name__ == "__main__":
    unittest.main()
