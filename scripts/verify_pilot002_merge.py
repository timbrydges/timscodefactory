"""Read-only observation of the exact merged pilot candidate; no execution or state writes."""
import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.pilot002_repository import verify_merged_candidate


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('repository',type=Path)
    p.add_argument('candidate_commit')
    p.add_argument('merge_commit')
    p.add_argument('pull_request',type=int)
    p.add_argument('builder_response',type=Path)
    p.add_argument('output',type=Path)
    args=p.parse_args()
    if args.output.exists():raise RuntimeError('Evidence output already exists')
    with args.builder_response.open('rb') as stream:raw=stream.read(32769)
    def read(endpoint):
        result=subprocess.run(['gh','api','--hostname','github.com',endpoint],
            capture_output=True,timeout=30,check=False,
            env={k:v for k,v in os.environ.items() if k!='GH_DEBUG'})
        if result.returncode or len(result.stdout)>65536:
            raise RuntimeError('GitHub merge observation failed')
        return json.loads(result.stdout)
    value=verify_merged_candidate(ROOT,args.repository,builder_response=raw,
        candidate_commit=args.candidate_commit,merge_commit=args.merge_commit,
        pull_request=args.pull_request,github_read=read)
    value['observed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    with args.output.open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2)
    print('MERGED_CANDIDATE_BINDING_OBSERVED: no execution, authority or state writes')


if __name__=='__main__':main()
