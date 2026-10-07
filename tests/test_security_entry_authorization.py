"""Real allowance signatures at the file boundary; no live AWS requests."""
import base64
from datetime import timedelta
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from factory_runtime import security_role_lambda as entry
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical
from scripts.scope_dispatch_canary import fixture_keys, sign
from test_security_provider_scope import fixture, NOW


class EntryAuthorizationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.keys,self.private=fixture_keys(temp.name,('tim_brydges',))
        scope,pricing,readiness,payload=fixture()
        self.material=SimpleNamespace(prepared=lambda:SimpleNamespace(scope=scope))
        self.doc={'allowance':{'payload':payload,'signature_base64':base64.b64encode(
            sign(payload,self.private['tim_brydges'],temp.name)).decode()},
            'pricing':pricing,'readiness':readiness}
        self.env={'FACTORY_SECURITY_ENABLED':'true','AWS_REGION':'ca-central-1',
            'AWS_LAMBDA_FUNCTION_NAME':entry.NAME}
        self.save()

    def save(self):
        raw=canonical(self.doc);(self.root/'SECURITY_ALLOWANCE.json').write_bytes(raw)
        self.env['FACTORY_SECURITY_ALLOWANCE_DIGEST']=digest(raw)

    def load(self, now=NOW):
        return entry.load_allowance(self.root,self.env,material=self.material,keys=lambda _:self.keys,now=now)

    def test_exact_signed_allowance_loads_without_cloud_calls(self):
        self.assertEqual(self.load(),self.doc)

    def test_recomputed_file_pin_does_not_authorize_changed_signed_limits(self):
        self.doc['allowance']['payload']['reserved_micro_usd']=250001;self.save()
        with self.assertRaises(StateError):self.load()

    def test_expired_revoked_and_changed_pricing_rejected(self):
        with self.assertRaises(StateError):self.load(NOW+timedelta(hours=2))
        owner=self.keys.pop('tim_brydges')
        with self.assertRaises(StateError):self.load()
        self.keys['tim_brydges']=owner
        self.doc['pricing']['input_micro_usd_per_million']+=1;self.save()
        with self.assertRaises(StateError):self.load()

    def test_wrong_custody_stops_before_backend_or_credential_loading(self):
        context=SimpleNamespace(invoked_function_arn=
            'arn:aws:lambda:ca-central-1:666730517561:function:'+entry.NAME+':1',
            get_remaining_time_in_millis=lambda:180000)
        sts=Mock(get_caller_identity=Mock(return_value={'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/another-role/test'}))
        # Deployment/event validation is covered separately. This isolates the
        # actual signed allowance load followed by the execution-custody boundary.
        with patch.object(entry,'load_deployment',return_value=SimpleNamespace(material=self.material)), \
                patch.object(entry.BoundedSecurityRoleRuntime,'validate_event'), \
                patch.object(entry,'signer_loader',return_value=lambda _:self.keys), \
                patch.object(entry,'_aws_session'),patch.object(entry,'client',return_value=sts) as client, \
                patch.object(entry,'disabled_backend') as backend,patch.object(entry,'_credential') as credentials:
            with self.assertRaises(StateError):
                entry.dispatch({},context,root=self.root,env=self.env,clock=lambda:NOW)
            self.assertEqual(client.call_count,1)
            self.assertEqual(client.call_args.args[1],'sts')
            backend.assert_not_called();credentials.assert_not_called()


if __name__ == '__main__':unittest.main()
