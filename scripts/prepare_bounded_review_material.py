"""Authenticate GitHub Docker proof and compile fixed three-role deployment bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))
from scripts.prepare_review_test_proof import prepare as import_proof, github_api, BASELINE, PINNED
from factory_runtime.review_material import PinnedReviewMaterial
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical


def prepare(commit, run_id, *, api=github_api, root=ROOT, clock=None):
    proof = import_proof(commit,run_id,api=api,root=root,clock=clock)
    baseline = (root/BASELINE).read_bytes()
    if hashlib.sha256(baseline).hexdigest() != PINNED[BASELINE]:
        raise StateError('candidate changed during authenticated preparation')
    raw = canonical({'kind':'bounded_review001_deployment_material','test_proof':proof,
                     'candidate_files':json.loads(baseline)['files']})
    PinnedReviewMaterial.load(raw,expected_digest=digest(raw),deployed_commit=commit,clock=clock)
    return raw


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('commit');parser.add_argument('run_id',type=int);parser.add_argument('output',type=Path)
    args=parser.parse_args()
    if args.output.exists():raise StateError('deployment material output already exists')
    raw=prepare(args.commit,args.run_id)
    with args.output.open('xb') as stream:stream.write(raw)
    print(json.dumps({'material_digest':digest(raw),'source_commit':args.commit,
                      'model_calls':0,'state_writes':0,'execution_authorized':False}))
