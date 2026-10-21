import base64
import json
import unittest
from unittest.mock import Mock

from factory_runtime.source_app_jwt import issue_app_credential, prepare_app_claims
from factory_state.model import StateError


class AppJwtTests(unittest.TestCase):
    def test_claims_and_algorithm_with_fake_signer_only(self):
        signer=Mock(return_value=b'x'*256)
        result=issue_app_credential('Iv23offlineOnly',clock=lambda:1000,sign_rs256=signer,
            enabled=True,owner_authorized=True)
        parts=result.value.split('.')
        decode=lambda p:json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4)))
        self.assertEqual(decode(parts[0]),{'alg':'RS256','typ':'JWT'})
        self.assertEqual(decode(parts[1]),{'iat':940,'exp':1300,'iss':'Iv23offlineOnly'})
        signer.assert_called_once_with(('.'.join(parts[:2])).encode())
        self.assertNotIn(result.value,repr(result))

    def test_disabled_never_calls_signer(self):
        signer=Mock()
        for enabled, authorized in ((False,True),(True,False),(1,True)):
            with self.assertRaises(StateError):
                issue_app_credential('Iv23offlineOnly',clock=lambda:1000,sign_rs256=signer,
                    enabled=enabled,owner_authorized=authorized)
        signer.assert_not_called()

    def test_invalid_claims(self):
        for client,now in (('bad\nvalue',1000),('Iv23offlineOnly',True),('Iv23offlineOnly',1.1)):
            with self.assertRaises(StateError):prepare_app_claims(client,now)

    def test_failure_redaction_and_no_retry(self):
        signer=Mock(side_effect=OSError('secret-path'))
        with self.assertRaises(StateError) as caught:
            issue_app_credential('Iv23offlineOnly',clock=lambda:1000,sign_rs256=signer,
                enabled=True,owner_authorized=True)
        self.assertNotIn('secret-path',str(caught.exception))
        signer.assert_called_once()

    def test_expired_during_signing_rejected(self):
        with self.assertRaises(StateError):
            issue_app_credential('Iv23offlineOnly',clock=Mock(side_effect=[1000,1240]),
                sign_rs256=Mock(return_value=b'x'*256),enabled=True,owner_authorized=True)
