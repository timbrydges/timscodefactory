"""Offline construction does not read credentials, claims or live evidence."""
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import test_security_material as fixtures
from factory_runtime.security_composition import disabled_backend
from factory_runtime.security_provider_claims import SecurityProviderClaims
from factory_runtime.worker import digest
from factory_state.model import StateError


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.SecurityMaterialTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        material=self.f.load()
        db=Mock(meta=SimpleNamespace(endpoint_url='https://dynamodb.ca-central-1.amazonaws.com',
            config=SimpleNamespace(retries={'total_max_attempts':1})))
        self.db=db;self.states=Mock();self.ledger=Mock();self.keys=Mock();self.history=Mock()
        self.args=dict(material=material,qa_binding=self.f.qa,
            qa_request=self.f.f.load().prepared('qa').scope.request,
            envelope={},pricing={},readiness={},states=self.states,ledger=self.ledger,
            claims=SecurityProviderClaims(db),key_loader=self.keys,
            historical_key_loader=self.history,clock=lambda:self.f.f.f.now)

    def test_composition_is_disabled_and_has_no_credential_route_or_io(self):
        backend=disabled_backend(**self.args)
        self.assertFalse(backend.enabled);self.assertIsNone(backend.load_credential)
        self.assertEqual(backend.evidence.binding,backend.prepared.scope.binding.qa)
        self.assertIs(backend.verify_prerequisites.states,self.states)
        with self.assertRaisesRegex(StateError,'disabled'):
            backend.check_activation(None,backend.prepared.scope.request,now=self.f.f.f.now)
        for obj in (self.db,self.states,self.ledger,self.keys,self.history):
            self.assertEqual(obj.mock_calls,[])

    def test_mismatched_contract_or_qa_request_rejected(self):
        bad=replace(self.args['material'],contract_bytes=b'old contract')
        with self.assertRaises(StateError):disabled_backend(**{**self.args,'material':bad})
        request=replace(self.args['qa_request'],input_digest=digest(b'other'))
        with self.assertRaises(StateError):disabled_backend(**{**self.args,'qa_request':request})

    def test_expired_proof_cannot_be_composed(self):
        with self.assertRaises(StateError):
            disabled_backend(**{**self.args,'clock':lambda:self.f.f.f.now+timedelta(hours=2)})


if __name__ == '__main__':unittest.main()
