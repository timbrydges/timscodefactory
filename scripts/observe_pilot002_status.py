"""Read Pilot 002 status from AWS with existing operator credentials; write a redacted local report."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from factory_runtime.pilot002_status import observe,REGION


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('output',type=Path)
    args=p.parse_args()
    if args.output.exists():raise RuntimeError('Report already exists')
    import boto3
    from botocore.config import Config
    session=boto3.Session(region_name=REGION)
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10)
    clients={name:session.client(service,config=config) for name,service in
             (('sts','sts'),('lam','lambda'),('db','dynamodb'))}
    report=observe(**clients)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
    print(report['status']+': read-only observation; no execution authority')
    return 0 if report['status']=='OBSERVED' else 2


if __name__=='__main__':raise SystemExit(main())
