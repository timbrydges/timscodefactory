import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from factory_runtime.credential_issuance import CredentialIssuanceLedger, IssuanceAuthorization
from factory_runtime.openai_provider import ProviderCredentialLease
from factory_runtime.provider_broker_service import ResolvedProviderTarget
from factory_runtime.provider_credentials import ProviderCredentialLeaseError
from factory_runtime.renewable_credentials import RenewableProviderCredentialSource


class IssuanceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'issuance.db'
        self.now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.target = ResolvedProviderTarget('openai', 'fake-model', 'v1')
        self.auth = IssuanceAuthorization('sha256:' + 'a' * 64, 'idp-test', 'sa-test',
            self.target, self.now, self.now + timedelta(hours=1), 2, ('test:scope',), 1)
        self.calls = 0

    def ledger(self, auth=None):
        return CredentialIssuanceLedger(self.path, auth or self.auth, operator_authorized=True)

    async def issuer(self):
        self.calls += 1
        await asyncio.sleep(0)
        return ProviderCredentialLease('fake-secret-never-persist', 'openai', 'api.openai.com',
            self.now, self.now + timedelta(seconds=600))

    def source(self, ledger, issuer=None):
        return RenewableProviderCredentialSource(target=self.target, issuer=issuer or self.issuer,
            clock=lambda: self.now, enabled=True, issuance_ledger=ledger)

    def claim(self, ledger):
        return ledger.claim(now=self.now, target=self.target)

    def test_no_admission_authority_creates_no_file(self):
        with self.assertRaises(ProviderCredentialLeaseError):
            CredentialIssuanceLedger(self.path, self.auth)
        self.assertFalse(self.path.exists())

    def test_default_paused_and_restart_does_not_unpause(self):
        with self.assertRaises(ProviderCredentialLeaseError):
            self.claim(self.ledger())
        with self.assertRaises(ProviderCredentialLeaseError):
            self.claim(self.ledger())

    def test_binding_cannot_be_replaced(self):
        self.ledger()
        for change in ({'approval_digest': 'sha256:' + 'b' * 64}, {'maximum_exchanges': 3},
                       {'identity_provider_id': 'other'}, {'service_account_id': 'other'},
                       {'scopes': ('other:scope',)},
                       {'target': replace(self.target, model_id='other')}):
            with self.assertRaises(ProviderCredentialLeaseError):
                self.ledger(replace(self.auth, **change))

    def test_started_attempt_blocks_after_restart(self):
        ledger = self.ledger(); ledger.pause(False)
        self.claim(ledger)
        with self.assertRaises(ProviderCredentialLeaseError):
            self.claim(self.ledger())

    def test_uncertain_result_cannot_be_reset_by_readmission(self):
        ledger = self.ledger(); ledger.pause(False)
        claim = self.claim(ledger); ledger.finish(claim, succeeded=False)
        renewed = self.ledger(); renewed.pause(False)
        with self.assertRaises(ProviderCredentialLeaseError):
            self.claim(renewed)
        with self.assertRaises(ProviderCredentialLeaseError):
            renewed.finish(claim, succeeded=True, now=self.now)

    def test_count_and_interval_survive_restart(self):
        ledger = self.ledger(); ledger.pause(False)
        ledger.finish(self.claim(ledger), succeeded=True, now=self.now)
        with self.assertRaises(ProviderCredentialLeaseError):
            self.claim(self.ledger())
        self.now += timedelta(seconds=1)
        ledger = self.ledger()
        ledger.finish(self.claim(ledger), succeeded=True, now=self.now)
        self.now += timedelta(seconds=1)
        with self.assertRaises(ProviderCredentialLeaseError):
            self.claim(self.ledger())

    def test_concurrent_connections_claim_once(self):
        ledger = self.ledger(); ledger.pause(False)
        def attempt(_):
            try:
                return self.claim(self.ledger())
            except ProviderCredentialLeaseError:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(value is not None for value in claims), 1)

    async def test_cache_and_successful_renewal_use_bounded_slots(self):
        ledger = self.ledger(); ledger.pause(False)
        source = self.source(ledger)
        first = await source.issue(target=self.target)
        self.assertIs(await source.issue(target=self.target), first)
        self.now += timedelta(seconds=390)
        await source.issue(target=self.target)
        self.now += timedelta(seconds=390)
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(self.ledger()).issue(target=self.target)
        self.assertEqual(self.calls, 2)
        self.assertNotIn(b'fake-secret', self.path.read_bytes())

    async def test_cancelled_exchange_blocks_new_instance(self):
        async def cancelled():
            self.calls += 1
            raise asyncio.CancelledError()
        ledger = self.ledger(); ledger.pause(False)
        with self.assertRaises(asyncio.CancelledError):
            await self.source(ledger, cancelled).issue(target=self.target)
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(self.ledger()).issue(target=self.target)
        self.assertEqual(self.calls, 1)

    async def test_malformed_result_blocks_new_instance(self):
        async def malformed():
            self.calls += 1
            return None
        ledger = self.ledger(); ledger.pause(False)
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(ledger, malformed).issue(target=self.target)
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(self.ledger()).issue(target=self.target)
        self.assertEqual(self.calls, 1)

    async def test_expiry_during_exchange_does_not_return_credential(self):
        async def delayed():
            self.now += timedelta(hours=1)
            return await self.issuer()
        ledger = self.ledger(); ledger.pause(False)
        with self.assertRaises(ProviderCredentialLeaseError):
            await self.source(ledger, delayed).issue(target=self.target)
        self.assertEqual(self.calls, 1)

    async def test_pause_invalidates_cached_lease(self):
        ledger = self.ledger(); ledger.pause(False)
        source = self.source(ledger)
        await source.issue(target=self.target)
        self.ledger().pause()
        with self.assertRaises(ProviderCredentialLeaseError):
            await source.issue(target=self.target)
        self.assertEqual(self.calls, 1)

    def test_window_target_and_clock_checks(self):
        ledger = self.ledger(); ledger.pause(False)
        for now, target in [(self.now - timedelta(seconds=1), self.target),
                            (self.auth.expires_at, self.target),
                            (self.now, replace(self.target, selector_version='v2'))]:
            with self.assertRaises(ProviderCredentialLeaseError):
                ledger.check(now=now, target=target)
        ledger.check(now=self.now + timedelta(seconds=2), target=self.target)
        with self.assertRaises(ProviderCredentialLeaseError):
            self.claim(self.ledger())

    def test_invalid_authorization(self):
        for change in ({'maximum_exchanges': True}, {'maximum_exchanges': 0},
                       {'maximum_exchanges': 1001}, {'minimum_interval_seconds': 0},
                       {'expires_at': self.now}, {'expires_at': self.now + timedelta(days=2)},
                       {'starts_at': self.now.replace(tzinfo=None)},
                       {'identity_provider_id': 'invalid\nvalue'}, {'scopes': ()},
                       {'scopes': ['test:scope']}, {'scopes': ('z', 'a')},
                       {'scopes': ('a', 'a')}):
            with self.assertRaises(ValueError):
                replace(self.auth, **change).canonical()


if __name__ == '__main__':
    unittest.main()
