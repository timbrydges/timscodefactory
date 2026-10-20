import asyncio
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from factory_runtime.openai_provider import ProviderCredentialLease
from factory_runtime.provider_broker_service import ResolvedProviderTarget
from factory_runtime.provider_credentials import ProviderCredentialLeaseError
from factory_runtime.renewable_credentials import RenewableProviderCredentialSource


class RenewableCredentialTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.target = ResolvedProviderTarget("openai", "test-model", "v1")
        self.calls = 0
        self.result = ProviderCredentialLease(
            "fake-token-for-offline-tests", "openai", "api.openai.com",
            self.now, self.now + timedelta(seconds=600))

    async def issuer(self):
        self.calls += 1
        await asyncio.sleep(0)
        return self.result

    def source(self, **kwargs):
        return RenewableProviderCredentialSource(
            target=self.target, issuer=kwargs.pop("issuer", self.issuer),
            clock=lambda: self.now, **kwargs)

    async def test_disabled_has_no_issuer_access(self):
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source().issue(target=self.target)
        self.assertEqual(self.calls, 0)

    async def test_exact_target_binding_precedes_issuer(self):
        source = self.source(enabled=True)
        for field in ("model_id", "selector_version", "provider_family"):
            with self.assertRaises(ProviderCredentialLeaseError):
                await source.issue(target=replace(self.target, **{field: "other"}))
        self.assertEqual(self.calls, 0)

    async def test_concurrent_requests_share_one_issuance(self):
        source = self.source(enabled=True)
        results = await asyncio.gather(*(source.issue(target=self.target) for _ in range(20)))
        self.assertEqual(self.calls, 1)
        self.assertTrue(all(item is self.result for item in results))
        self.assertNotIn(self.result.token, repr(source))
        self.assertNotIn(self.result.token, repr(results))

    async def test_refresh_before_expiry_preserves_absolute_expiry(self):
        source = self.source(enabled=True)
        first = await source.issue(target=self.target)
        self.now += timedelta(seconds=389)
        self.assertIs(await source.issue(target=self.target), first)
        self.now += timedelta(seconds=1)
        self.result = replace(self.result, issued_at=self.now,
                              expires_at=self.now + timedelta(seconds=600))
        second = await source.issue(target=self.target)
        self.assertIs(second, self.result)
        self.assertEqual(self.calls, 2)

    async def test_exchange_latency_consumes_lifetime_and_latches_failure(self):
        async def slow():
            self.calls += 1
            self.now += timedelta(seconds=391)
            return self.result
        source = self.source(enabled=True, issuer=slow)
        for _ in range(2):
            with self.assertRaises(ProviderCredentialLeaseError):
                await source.issue(target=self.target)
        self.assertEqual(self.calls, 1)

    async def test_failure_has_no_secret_text_or_retry(self):
        async def broken():
            self.calls += 1
            raise RuntimeError("secret-token-never-print")
        source = self.source(enabled=True, issuer=broken)
        for _ in range(2):
            with self.assertRaises(ProviderCredentialLeaseError) as caught:
                await source.issue(target=self.target)
            self.assertNotIn("secret-token", str(caught.exception))
        self.assertEqual(self.calls, 1)

    async def test_cancelled_exchange_is_not_repeated(self):
        async def cancelled():
            self.calls += 1
            raise asyncio.CancelledError()
        source = self.source(enabled=True, issuer=cancelled)
        with self.assertRaises(asyncio.CancelledError):
            await source.issue(target=self.target)
        with self.assertRaises(ProviderCredentialLeaseError):
            await source.issue(target=self.target)
        self.assertEqual(self.calls, 1)

    async def test_invalid_issuer_results_stop_renewal(self):
        original = self.result
        invalid = [None, replace(original, audience="other"),
                   replace(original, provider_family="other"),
                   replace(original, token="short"),
                   replace(original, token="x" * 32769),
                   replace(original, token="secret\nheader-injection"),
                   replace(original, issued_at=self.now.replace(tzinfo=None)),
                   replace(original, expires_at=self.now.replace(tzinfo=None)),
                   replace(original, issued_at=self.now + timedelta(seconds=1)),
                   replace(original, expires_at=self.now + timedelta(seconds=3601)),
                   replace(original, expires_at=self.now + timedelta(seconds=210)),
                   replace(original, expires_at=self.now - timedelta(seconds=1))]
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                self.result = value
                source = self.source(enabled=True)
                before = self.calls
                for _ in range(2):
                    with self.assertRaises(ProviderCredentialLeaseError):
                        await source.issue(target=self.target)
                self.assertEqual(self.calls, before + 1)

    async def test_backwards_clock_drops_cached_token(self):
        source = self.source(enabled=True)
        await source.issue(target=self.target)
        self.now -= timedelta(seconds=1)
        with self.assertRaises(ProviderCredentialLeaseError):
            await source.issue(target=self.target)
        self.now += timedelta(seconds=2)
        with self.assertRaises(ProviderCredentialLeaseError):
            await source.issue(target=self.target)
        self.assertEqual(self.calls, 1)

    def test_invalid_configuration(self):
        for options in ({"enabled": 1}, {"minimum_remaining_seconds": True},
                        {"minimum_remaining_seconds": 0},
                        {"maximum_lifetime_seconds": 3601},
                        {"minimum_remaining_seconds": 300, "maximum_lifetime_seconds": 300}):
            with self.assertRaises(ValueError):
                self.source(**options)


if __name__ == "__main__":
    unittest.main()
