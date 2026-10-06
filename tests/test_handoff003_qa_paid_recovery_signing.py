import copy,unittest
from unittest.mock import Mock
import sign_handoff003_qa_paid_recovery_allowance as s
import test_handoff003_qa_paid_recovery_entrypoint as fixture
from factory_state.model import StateError
from factory_state.scope import canonical

class RecoverySigningTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.RecoveryEntrypointTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f;doc=copy.deepcopy(f.doc)
        evidence={'pricing':{'observed':'synthetic-price'},'readiness':{'observed':'synthetic-readiness'}}
        doc['qualification']['evidence_digest']=s.digest(evidence['pricing']);doc['readiness']['evidence_digest']=s.digest(evidence['readiness'])
        from factory_runtime.handoff003_qa_paid_recovery_authorization import draft
        window={'issued_at':int(f.fixture.now.timestamp()),'expires_at':int(f.fixture.now.timestamp())+600}
        doc['qualification'].update(window);doc['readiness'].update(window)
        payload=draft(root=f.root,source_commit='a'*40,qualification=doc['qualification'],readiness=doc['readiness'],now=f.fixture.now,**window)
        doc['allowance']={'payload':payload,'signature':''}
        self.plan={'kind':'handoff003_qa_paid_recovery002_owner_signing_plan','activation':doc,'evidence':evidence}
        self.args=dict(root=f.root,approved_digest=s.digest(self.plan),source_commit='a'*40,now=f.fixture.now)
    def test_exact_plan_validates_but_mixed_source_or_evidence_cannot_sign(self):
        self.assertEqual(s.validate_plan(self.plan,**self.args)['retries'],0)
        for mutation in ('source','evidence','signature'):
            bad=copy.deepcopy(self.plan)
            if mutation=='source':bad['activation']['source_commit']='b'*40
            if mutation=='evidence':bad['evidence']['pricing']['observed']='changed'
            if mutation=='signature':bad['activation']['allowance']['signature']='already-signed'
            kms=Mock()
            with self.assertRaises(StateError):s.sign(bad,**{**self.args,'approved_digest':s.digest(bad)},kms=kms,sts=Mock())
            kms.sign.assert_not_called()
    def test_signed_material_verified_with_real_owner_signature(self):
        doc=copy.deepcopy(self.plan['activation']);import base64
        doc['allowance']['signature']=base64.b64encode(self.f.fixture.private.sign(canonical(doc['allowance']['payload']))).decode()
        result,_=s.material(doc,self.f.root,self.f.fixture.now,unsigned=False)
        self.assertEqual(result['source_commit'],'a'*40)
    def test_workflow_is_exclusive_owner_main_first_attempt(self):
        import yaml
        workflow=yaml.safe_load((s.ROOT/'.github/workflows/factory-paid-qa-owner-signing.yml').read_bytes())
        self.assertEqual(workflow['name'],'factory-owner-signing') # Existing AWS OIDC trust binds this claim.
        self.assertLessEqual(len(workflow[True]['workflow_dispatch']['inputs']),25)
        for name,job in workflow['jobs'].items():
            if name=='sign_handoff003_qa_paid_recovery002_allowance':
                for guard in ("github.actor_id == '214414801'","github.ref == 'refs/heads/main'","github.run_attempt == 1",
                    "inputs.handoff003_qa_paid_recovery002_plan_digest != ''"):
                    self.assertIn(guard,job['if'])
            else:
                self.assertIn("inputs.handoff003_qa_paid_recovery002_plan_digest == ''",job['if'])
                self.assertIn("inputs.handoff003_qa_paid_recovery002_plan_base64 == ''",job['if'])
    def test_direct_cli_entrypoint_can_resolve_historical_verifier_without_cwd_path(self):
        import subprocess,sys,tempfile
        from pathlib import Path
        # -I excludes CWD/PYTHONPATH, matching a directly executed script's
        # absence of the repository root. Keep installed cryptography available.
        code="""import runpy,sys
from pathlib import Path
root=Path(sys.argv[1])
sys.path.insert(0,str(root/'scripts'))
runpy.run_path(str(root/'scripts/sign_handoff003_qa_paid_recovery_allowance.py'),run_name='cli_import_proof')
from factory_runtime.handoff003_qa_paid_recovery_authorization import bindings
assert bindings(root,'a'*40)['role']=='qa'
"""
        with tempfile.TemporaryDirectory() as outside:
            subprocess.run([sys.executable,'-I','-c',code,str(s.ROOT)],cwd=outside,check=True,capture_output=True,timeout=30)

if __name__=='__main__':unittest.main()
