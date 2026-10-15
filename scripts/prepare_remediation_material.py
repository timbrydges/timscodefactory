"""Read authenticated main CI proof into a bounded task005 material file."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
sys.path.insert(0, str(ROOT))
from scripts.prepare_review_test_proof import prepare as import_proof, github_api
from factory_runtime.remediation_material import RemediationMaterial
from factory_runtime.remediation_profile import TASK, BASELINE, BASELINE_SHA256
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical


def prepare(commit, run_id, *, api=github_api, root=ROOT, clock=None):
    proof = import_proof(commit, run_id, api=api, root=root, clock=clock, task=TASK)
    baseline = (root/BASELINE).read_bytes()
    if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
        raise StateError('Task005 candidate changed during authenticated import')
    raw = canonical({'kind':'remediation005_deployment_material', 'task_id':TASK,
        'candidate_files':json.loads(baseline)['files'], 'test_proof':proof})
    RemediationMaterial.load(raw, expected_digest=digest(raw), deployed_commit=commit, clock=clock)
    return raw


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('commit'); p.add_argument('run_id', type=int); p.add_argument('output', type=Path)
    args = p.parse_args()
    if args.output.exists(): raise StateError('Material output already exists')
    raw = prepare(args.commit, args.run_id)
    with args.output.open('xb') as stream: stream.write(raw)
    print(json.dumps({'path':str(args.output.resolve()), 'sha256':digest(raw),
        'signing_authorized':False, 'execution_authorized':False}))
