"""Private, approval-gated key fingerprints; never invokes a model or changes IAM."""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import logging
import os
from pathlib import Path
import re
import ssl
import subprocess

PROJECT='gen-lang-client-0247455615'
NUMBER='775833138497'
RESOURCE='projects/'+NUMBER+'/locations/global/keys/cb9311fc-42e2-4de4-bf83-80082e6282c1'
VERSION='db69f4bf-38c0-43d5-8bbf-ce20d8e07282'
SECRET='arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/google/qa-rYGeOE'
ROOT=Path(__file__).resolve().parents[1]


def pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('duplicate field')
        result[key]=value
    return result


def fingerprint(key,nonce):
    if not isinstance(key,str) or not 16<=len(key)<=512 or any(ord(c)<33 or ord(c)>126 for c in key):
        raise ValueError('key format')
    if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{64}',nonce):raise ValueError('nonce format')
    return hashlib.sha256(b'pilot002-google-binding-v1\0'+bytes.fromhex(nonce)+key.encode('ascii')).hexdigest()


def google_get(host,path,token):
    allowed={('cloudresourcemanager.googleapis.com','/v1/projects/'+PROJECT),
        ('apikeys.googleapis.com','/v2/'+RESOURCE),('apikeys.googleapis.com','/v2/'+RESOURCE+'/keyString')}
    if (host,path) not in allowed:raise ValueError('route')
    context=ssl.create_default_context();context.set_alpn_protocols(['http/1.1'])
    connection=http.client.HTTPSConnection(host,443,timeout=20,context=context)
    connection.set_debuglevel(0)
    try:
        connection.request('GET',path,headers={'Authorization':'Bearer '+token,'Accept':'application/json',
            'Accept-Encoding':'identity','Connection':'close'})
        response=connection.getresponse()
        if response.status!=200:raise ValueError('Google metadata rejected')
        if response.getheader('Content-Type','').split(';',1)[0].strip().lower()!='application/json':raise ValueError('format')
        if response.getheader('Content-Encoding','identity').lower()!='identity':raise ValueError('encoding')
        data=response.read(65537)
        if not 0<len(data)<=65536:raise ValueError('size')
        result=json.loads(data,object_pairs_hook=pairs)
        if not isinstance(result,dict):raise ValueError('object')
        return result
    finally:connection.close()


def google_key():
    # Existing Cloud Shell identity only. Captured token/errors are never printed.
    env=dict(os.environ);env['CLOUDSDK_CORE_LOG_HTTP']='false'
    process=subprocess.run(['gcloud','auth','print-access-token','--quiet'],capture_output=True,
        text=True,timeout=30,check=False,env=env)
    if process.returncode:raise ValueError('Google authorization unavailable')
    token=process.stdout.strip()
    if not token or len(token)>16384 or any(ord(c)<33 or ord(c)>126 for c in token):raise ValueError('token format')
    project=google_get('cloudresourcemanager.googleapis.com','/v1/projects/'+PROJECT,token)
    if project.get('projectId')!=PROJECT or str(project.get('projectNumber'))!=NUMBER or project.get('lifecycleState')!='ACTIVE':
        raise ValueError('project identity')
    metadata=google_get('apikeys.googleapis.com','/v2/'+RESOURCE,token)
    if metadata.get('name')!=RESOURCE or metadata.get('displayName')!='Tims Software Factory QA' or metadata.get('deleteTime'):
        raise ValueError('key identity')
    value=google_get('apikeys.googleapis.com','/v2/'+RESOURCE+'/keyString',token)
    if set(value)!={'keyString'}:raise ValueError('key response')
    return value['keyString']


def aws_key():
    import boto3
    from botocore.config import Config
    logging.getLogger('botocore').setLevel(logging.CRITICAL)
    cfg=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10,proxies={})
    session=boto3.Session(region_name='ca-central-1')
    if session.client('sts',config=cfg).get_caller_identity()['Account']!='666730517561':raise ValueError('AWS identity')
    client=session.client('secretsmanager',endpoint_url='https://secretsmanager.ca-central-1.amazonaws.com',config=cfg)
    value=client.get_secret_value(SecretId=SECRET,VersionId=VERSION)
    if value.get('ARN')!=SECRET or value.get('VersionId')!=VERSION:raise ValueError('secret identity')
    # PR 344 established this exact version uses raw text, not JSON.
    return value.get('SecretString')


def run(side,nonce,output,*,approved=False):
    if approved is not True or side not in ('aws','google'):raise ValueError('owner approval required')
    fingerprint('format-validation-only',nonce)
    output=Path(output).resolve()
    if output.is_relative_to(ROOT):raise ValueError('output must be outside repository')
    with output.open('x',encoding='utf-8') as stream:
        stream.write('{"status":"STARTED_NO_AUTOMATIC_RETRY"}\n');stream.flush()
        result={'status':'FINGERPRINT_FAILED','side':side,'nonce':nonce,'project':PROJECT,
            'project_number':NUMBER,'key_resource':RESOURCE,'secret_arn':SECRET,'secret_version':VERSION,
            'generation_requests':0,'binding_verified':False}
        try:
            key=aws_key() if side=='aws' else google_key()
            result['fingerprint']=fingerprint(key,nonce);key=None
            result['status']='FINGERPRINT_OBSERVED_NOT_YET_COMPARED'
        except Exception:pass
        result['observed_at']=datetime.now(timezone.utc).isoformat()
        stream.seek(0);json.dump(result,stream,indent=2);stream.truncate();stream.flush()
    return result


def compare(aws,google,*,now=None):
    now=now or datetime.now(timezone.utc)
    for report,side in ((aws,'aws'),(google,'google')):
        if report.get('status')!='FINGERPRINT_OBSERVED_NOT_YET_COMPARED' or report.get('side')!=side:raise ValueError('observation')
        for field,value in {'project':PROJECT,'project_number':NUMBER,'key_resource':RESOURCE,'secret_arn':SECRET,'secret_version':VERSION}.items():
            if report.get(field)!=value:raise ValueError('binding identity')
        stamp=datetime.fromisoformat(report['observed_at'])
        if stamp.tzinfo is None or not 0<=(now-stamp).total_seconds()<=300:raise ValueError('stale observation')
        if not re.fullmatch('[0-9a-f]{64}',report.get('fingerprint','')):raise ValueError('fingerprint format')
        fingerprint('format-validation-only',report.get('nonce'))
    if aws['nonce']!=google['nonce'] or aws['fingerprint']!=google['fingerprint']:raise ValueError('keys differ')
    return {'status':'GOOGLE_CREDENTIAL_PROJECT_BOUND','project':PROJECT,'key_resource':RESOURCE,
        'secret_version':VERSION,'observed_at':now.isoformat(),'billing_verified':False,'live_execution_authorized':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('side',choices=['aws','google']);parser.add_argument('nonce');parser.add_argument('output')
    parser.add_argument('--owner-approved-private-comparison',action='store_true');args=parser.parse_args()
    try:print(json.dumps(run(args.side,args.nonce,args.output,approved=args.owner_approved_private_comparison),indent=2))
    except Exception:raise SystemExit('Private comparison stopped. Reconcile output; do not automatically repeat.') from None
