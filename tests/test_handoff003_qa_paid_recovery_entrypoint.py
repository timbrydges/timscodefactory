import hashlib,json,shutil,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical
from factory_state.signers import public_key_der
from factory_runtime import handoff003_qa_paid_recovery_entrypoint as e
from factory_runtime.handoff003_packets import PINNED
import test_handoff003_qa_paid_recovery_authorization as fixture
ROOT=fixture.ROOT

class RecoveryEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.RecoveryAuthorizationTests();self.fixture.setUp();f=self.fixture
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        scope='factory/evidence/handoff-003-qa-recovery-002-scope.json'
        names=set(PINNED)|{scope}|set(json.loads((ROOT/scope).read_bytes())['historical_files'])
        for name in names:
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,p)
        qa=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        entries=[]
        for identity,pem in {**f.keys,e.IDENTITIES['qa']:qa}.items():
            entries.append(dict(identity=identity,public_key_pem=pem.decode(),fingerprint='sha256:'+hashlib.sha256(public_key_der(pem)).hexdigest(),
                enrollment_commit='a'*40,not_before=int(f.now.timestamp())-60,expires_at=int(f.now.timestamp())+3600,revoked=False))
        registry=dict(schema_version='1.0',enabled=True,signers=entries)
        p=self.root/e.REGISTRY;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(canonical(registry))
        (self.root/'BUILD.json').write_bytes(canonical({'source_commit':'a'*40}))
        self.doc=dict(schema_version='1.0',source_commit='a'*40,qualification=f.q,readiness=f.r,allowance=f.signed(),signer_registry=registry,credential=e.ROUTE)
        self.env={e.ENABLED:'true','AWS_REGION':'ca-central-1','AWS_LAMBDA_FUNCTION_NAME':e.NAME}
        self.context=SimpleNamespace(invoked_function_arn=e.ARN+'1',get_remaining_time_in_millis=lambda:240000)
        self.save()
    def save(self):
        raw=canonical(self.doc);(self.root/e.ACTIVATION).write_bytes(raw);self.env[e.HASH]=hashlib.sha256(raw).hexdigest()
        self.event=dict(kind='handoff003_qa_paid_recovery002_run_once',source_commit='a'*40,activation_sha256=self.env[e.HASH])
    def invoke(self):return e.dispatch(self.event,self.context,root=self.root,env=self.env,clock=lambda:self.fixture.now)
    def test_valid_activation_and_exact_store_wiring(self):
        doc,keys=e.load_activation(self.root,self.env,self.fixture.now)
        self.assertEqual(set(keys),{OWNER_IDENTITY,e.IDENTITIES['qa']})
        with patch.object(e,'_aws_session'),patch.object(e,'_client'),patch.object(e,'assert_session'),patch.object(e,'RecoveryKmsSigner'),patch.object(e,'run_once',return_value={'ok':True}) as run:
            self.assertEqual(self.invoke(),{'ok':True})
            self.assertIs(type(run.call_args.kwargs['store']),e.RecoveryAttemptStore)
            self.assertTrue(run.call_args.kwargs['enabled'])
    def test_disabled_alias_short_deadline_and_tampering_stop_before_aws(self):
        cases=[lambda:self.env.update({e.ENABLED:'false'}),lambda:setattr(self.context,'invoked_function_arn',e.ARN+'$LATEST'),
            lambda:setattr(self.context,'get_remaining_time_in_millis',lambda:200000),lambda:self.event.update(extra=True),
            lambda:self.doc.update(credential={**e.ROUTE,'version_id':'wrong'}),lambda:self.doc.update(source_commit='b'*40),
            lambda:self.doc['allowance'].update(signature=''),lambda:self.doc['signer_registry']['signers'][0].update(revoked=True)]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                self.setUp();mutate()
                if 'extra' not in self.event:self.save()
                with patch.object(e,'_aws_session') as aws:
                    with self.assertRaises(StateError):self.invoke()
                    aws.assert_not_called()
    def test_failure_response_contains_only_bounded_diagnostic(self):
        with patch.object(e,'_aws_session'),patch.object(e,'_client'),patch.object(e,'assert_session'),patch.object(e,'RecoveryKmsSigner'),patch.object(e,'run_once',side_effect=e.RecoveryStopped('provider','timeout')):
            result=self.invoke()
        self.assertEqual(result['failure_code'],'timeout');self.assertFalse(result['attempt_reusable']);self.assertFalse(result['hold_release_authorized'])

if __name__=='__main__':unittest.main()
