import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from factory_runtime import handoff003_entrypoint as entry
from factory_runtime.handoff003_packets import PINNED
from factory_runtime.handoff003_workflow import HandoffStopped
from factory_state.model import StateError
from factory_state.scope import canonical
from factory_state.signers import public_key_der
import test_handoff003_workflow as workflow_fixtures


class HandoffEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.fixture = workflow_fixtures.HandoffWorkflowTests(); self.fixture.setUp()
        self.directory = tempfile.TemporaryDirectory(); self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in PINNED:
            target = self.root/name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((workflow_fixtures.ROOT/name).read_bytes())
        self.allowance, args, _ = self.fixture.setup_role('builder')
        now = int(self.fixture.now.timestamp())
        registry = {'schema_version': '1.0', 'enabled': True, 'signers': [
            {'identity': identity, 'public_key_pem': pem.decode(),
             'fingerprint': 'sha256:'+hashlib.sha256(public_key_der(pem)).hexdigest(),
             'enrollment_commit': 'a'*40, 'not_before': now-60, 'expires_at': now+3600, 'revoked': False}
            for identity, pem in self.fixture.keys.items()]}
        self.doc = {'schema_version': '1.0', 'role': 'builder', 'source_commit': 'a'*40,
            'qualification': args['qualification'], 'readiness': args['readiness'], 'allowance': self.allowance,
            'signer_registry': registry, 'credential': {'kind': 'secretsmanager',
                'secret_arn': entry.SECRETS['builder'], 'version_id': 'b'*32, 'json_key': 'api_key'},
            'predecessors': None, 'predecessor_request_digests': None, 'candidate_commit': None}
        (self.root/'BUILD.json').write_bytes(canonical({'source_commit': 'a'*40}))
        self.env = {'FACTORY_HANDOFF003_ENABLED': 'true', 'FACTORY_HANDOFF003_ROLE': 'builder',
            'AWS_REGION': entry.REGION, 'AWS_LAMBDA_FUNCTION_NAME': 'tims-factory-handoff-003-builder'}
        self.context = Mock(invoked_function_arn='arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-003-builder:1')
        self.context.get_remaining_time_in_millis.return_value = 180000
        self.save()

    def save(self):
        raw = canonical(self.doc)
        (self.root/entry.ACTIVATION).write_bytes(raw)
        self.env['FACTORY_HANDOFF003_ACTIVATION_SHA256'] = hashlib.sha256(raw).hexdigest()
        self.event = {'kind': 'handoff003_run_once', 'source_commit': 'a'*40,
            'activation_sha256': self.env['FACTORY_HANDOFF003_ACTIVATION_SHA256']}

    def dispatch(self):
        return entry.dispatch(self.event, self.context, root=self.root, env=self.env, clock=lambda: self.fixture.now)

    def test_disabled_rejection_precedes_files_or_aws(self):
        self.env['FACTORY_HANDOFF003_ENABLED'] = 'false'
        with patch.object(entry, 'load_activation') as load, patch.object(entry, '_aws_session') as session:
            with self.assertRaisesRegex(StateError, 'disabled'): self.dispatch()
            load.assert_not_called(); session.assert_not_called()

    def test_latest_alias_or_wrong_function_rejected_before_aws(self):
        for arn in ('arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-003-builder',
            'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-003-builder:$LATEST',
            'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-003-builder:acceptance',
            'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-handoff-003-qa:1'):
            self.context.invoked_function_arn = arn
            with patch.object(entry, '_aws_session') as session:
                with self.assertRaises(StateError): self.dispatch()
                session.assert_not_called()

    def test_digest_source_secret_and_enrollment_tampering_rejected_before_aws(self):
        original = canonical(self.doc)
        mutations = [lambda: self.doc.update(source_commit='c'*40),
            lambda: self.doc['credential'].update(secret_arn=entry.SECRETS['qa']),
            lambda: self.doc['signer_registry']['signers'][0].update(revoked=True),
            lambda: self.doc['allowance']['payload'].update(retries=1)]
        for mutate in mutations:
            self.doc = json.loads(original); mutate(); self.save()
            with patch.object(entry, '_aws_session') as session:
                with self.assertRaises(StateError): self.dispatch()
                session.assert_not_called()
        self.doc = json.loads(original); self.save()
        (self.root/entry.ACTIVATION).write_bytes(original+b' ')
        with patch.object(entry, '_aws_session') as session:
            with self.assertRaises(StateError): self.dispatch()
            session.assert_not_called()

    def test_exact_deployment_uses_isolated_execution_role_and_loaded_allowance(self):
        aws = Mock()
        aws.get_caller_identity.return_value = {'Account': entry.ACCOUNT,
            'Arn': 'arn:aws:sts::666730517561:assumed-role/tims-factory-executor-builder/test'}
        with patch.object(entry, '_aws_session'), patch.object(entry, '_client', return_value=aws), \
                patch.object(entry, '_signing_session'), patch.object(entry, 'HandoffKmsSigner'), \
                patch.object(entry, 'run_once', return_value={'signed': 'fixture'}) as run:
            self.assertEqual(self.dispatch(), {'signed': 'fixture'})
            self.assertEqual(run.call_args.args[0], self.allowance)
            self.assertEqual(run.call_args.kwargs['role'], 'builder')
            self.assertTrue(run.call_args.kwargs['enabled'])
            aws.get_secret_value.assert_not_called()

    def test_failed_post_call_response_retained_without_authority(self):
        aws = Mock()
        aws.get_caller_identity.return_value = {'Account': entry.ACCOUNT,
            'Arn': 'arn:aws:sts::666730517561:assumed-role/tims-factory-executor-builder/test'}
        with patch.object(entry, '_aws_session'), patch.object(entry, '_client', return_value=aws), \
                patch.object(entry, '_signing_session'), patch.object(entry, 'HandoffKmsSigner'), \
                patch.object(entry, 'run_once', side_effect=HandoffStopped('signing', b'{"synthetic":"result"}')):
            result = self.dispatch()
            self.assertEqual(result['status'], 'HANDOFF_FAILED_NO_RETRY')
            self.assertFalse(result['attempt_reusable'])
            self.assertFalse(result['gate_authority'])

    def test_provider_failure_returns_only_safe_category_without_receipt(self):
        aws=Mock()
        aws.get_caller_identity.return_value={'Account':entry.ACCOUNT,
            'Arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-executor-builder/test'}
        failure=HandoffStopped('provider',failure={'failure_category':'timeout','http_status':None})
        with patch.object(entry,'_aws_session'),patch.object(entry,'_client',return_value=aws), \
                patch.object(entry,'_signing_session'),patch.object(entry,'HandoffKmsSigner'), \
                patch.object(entry,'run_once',side_effect=failure):
            self.assertEqual(self.dispatch(),{'status':'HANDOFF_FAILED_NO_RETRY','role':'builder',
                'failure_stage':'provider','failure_category':'timeout','http_status':None,
                'attempt_reusable':False,'reservation_status':'HELD','gate_authority':False})
