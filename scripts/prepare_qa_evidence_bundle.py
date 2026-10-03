"""Combine bounded saved QA evidence offline; no signing or provider access."""
import argparse
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.qa_evidence import combine
from factory_runtime.review_preparation import prepare

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('local_report',type=Path)
    parser.add_argument('output',type=Path)
    google=parser.add_mutually_exclusive_group()
    google.add_argument('--google-response',type=Path)
    google.add_argument('--google-record',type=Path)
    args=parser.parse_args()
    with args.local_report.open('rb') as stream: raw=stream.read(65537)
    if len(raw)>65536: raise ValueError('local QA report exceeds bound')
    response=None
    if args.google_response:
        with args.google_response.open('rb') as stream: response=stream.read(65537)
    record=None
    if args.google_record:
        with args.google_record.open('rb') as stream: record=stream.read(20001)
    bundle=combine(json.loads(raw),prepare(ROOT,role='qa'),root=ROOT,google_response=response,google_record=record)
    with args.output.open('x',encoding='utf-8') as stream:
        stream.write(json.dumps(bundle,indent=2)+'\n')
    print(json.dumps({k:bundle[k] for k in ('status','review_status','candidate_commit','gate_authority')}))
