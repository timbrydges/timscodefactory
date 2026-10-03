"""Prepare a QA-only trust proposal without changing the active registry."""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.qa_enrollment import propose

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('observation',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('proposal requires clean reviewed source')
    source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    with args.observation.open('rb') as stream: raw=stream.read(16385)
    if len(raw)>16384: raise ValueError('observation exceeds bound')
    result=propose(ROOT,json.loads(raw),now=datetime.now(timezone.utc),enrollment_commit=source)
    with args.output.open('x',encoding='utf-8') as stream: json.dump(result,stream,indent=2)
    print(json.dumps({k:result[k] for k in ('status','identity','maximum_trust_seconds','model_calls','state_writes')}))
