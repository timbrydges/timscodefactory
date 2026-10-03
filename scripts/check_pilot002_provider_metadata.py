"""Approval-gated credential/model metadata checks. Never generates content."""
import argparse
from datetime import datetime, timezone
import http.client
import json
import logging
from pathlib import Path
import ssl
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_state.model import StateError
from factory_runtime.pilot002_entrypoint import _pairs
from prepare_pilot002_access import SECRETS, BUILDER_VERSION, REGION, ACCOUNT

VERSIONS={'builder':BUILDER_VERSION,'qa':'db69f4bf-38c0-43d5-8bbf-ce20d8e07282'}
ROUTES={'builder':('api.openai.com','/v1/models/gpt-5.6-sol','gpt-5.6-sol'),
    'qa':('generativelanguage.googleapis.com','/v1beta/models/gemini-3.8-flash','gemini-3.8-flash')}


def read_credential(client,role):
    response=client.get_secret_value(SecretId=SECRETS[role],VersionId=VERSIONS[role])
    if response.get('ARN')!=SECRETS[role] or response.get('VersionId')!=VERSIONS[role]:raise ValueError('credential identity')
    value=response.get('SecretString');kind='raw'
    if not isinstance(value,str) or not 0<len(value)<=8192:raise ValueError('credential format')
    if value.lstrip().startswith('{'):
        obj=json.loads(value,object_pairs_hook=_pairs)
        if not isinstance(obj,dict) or set(obj)!={'api_key'}:raise ValueError('credential JSON format')
        value=obj['api_key'];kind='api_key_json'
    if not isinstance(value,str) or not 16<=len(value)<=512 or any(ord(c)<33 or ord(c)>126 for c in value):
        raise ValueError('credential key format')
    return value,kind


def check(role, *, load_credential, enabled=False):
    if enabled is not True or role not in ROUTES:raise StateError('Pilot 002 metadata check not enabled or unsupported role')
    host,path,model=ROUTES[role]
    result={'role':role,'model_id':model,'status':'METADATA_CHECK_FAILED','http_requests':0,
        'generation_requests':0,'live_generation_readiness':False,'project_binding_verified':False}
    connection=None;credential=None;headers=None;stage='credential'
    try:
        credential,kind=load_credential()
        if not isinstance(credential,str) or not 16<=len(credential)<=512 or any(ord(c)<33 or ord(c)>126 for c in credential):
            raise ValueError('credential format')
        if kind not in ('raw','api_key_json'):raise ValueError('credential format label')
        result['credential_format']=kind
        headers={'Accept':'application/json','Accept-Encoding':'identity','Connection':'close'}
        headers['Authorization' if role=='builder' else 'x-goog-api-key']=('Bearer ' if role=='builder' else '')+credential
        context=ssl.create_default_context();context.set_alpn_protocols(['http/1.1'])
        connection=http.client.HTTPSConnection(host,443,timeout=20,context=context)
        connection.set_debuglevel(0);stage='request';result['http_requests']=1
        connection.request('GET',path,body=None,headers=headers)
        credential=None;headers=None
        response=connection.getresponse();result['http_status']=response.status;stage='response'
        if response.status!=200:
            result['status']='METADATA_ENDPOINT_REJECTED'
            return result
        if (response.getheader('Content-Type','').split(';',1)[0].strip().lower()!='application/json' or
                response.getheader('Content-Encoding','identity').lower()!='identity'):raise ValueError('response format')
        raw=response.read(65537)
        if not isinstance(raw,bytes) or not 0<len(raw)<=65536:raise ValueError('response size')
        metadata=json.loads(raw,object_pairs_hook=_pairs)
        if not isinstance(metadata,dict):raise ValueError('response object')
        if role=='builder':
            if metadata.get('id')!=model or metadata.get('object')!='model':raise ValueError('model differs')
        elif metadata.get('name')!='models/'+model:raise ValueError('model differs')
        result['status']='AUTHENTICATED_MODEL_METADATA_OBSERVED'
        return result
    except Exception:
        # No exceptions, response bodies, credentials or headers enter the report.
        result['failed_stage']=stage
        return result
    finally:
        credential=None;headers=None
        if connection is not None:
            try:connection.close()
            except Exception:pass


def run(output, *, approved=False):
    if approved is not True:raise StateError('Owner approval required before credential reads or provider requests')
    output=Path(output).resolve()
    if output.is_relative_to(ROOT):raise ValueError('Save audit outside repository')
    # Exclusive marker prevents accidentally reusing the same audit output.
    with output.open('x',encoding='utf-8') as stream:
        stream.write('{"status":"STARTED_RECONCILE_WITHOUT_AUTOMATIC_RETRY"}\n');stream.flush()
        import boto3
        from botocore.config import Config
        # Suppress SDK wire-level debug dumps; AWS service audit logging is unchanged.
        logging.getLogger('botocore').setLevel(logging.CRITICAL)
        session=boto3.Session(region_name=REGION)
        cfg=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10,proxies={})
        if session.client('sts',config=cfg).get_caller_identity()['Account']!=ACCOUNT:raise StateError('Wrong AWS account')
        client=session.client('secretsmanager',region_name=REGION,
            endpoint_url='https://secretsmanager.'+REGION+'.amazonaws.com',config=cfg)
        results={role:check(role,load_credential=lambda role=role:read_credential(client,role),enabled=True) for role in ROUTES}
        result={'status':'CREDENTIAL_METADATA_AUDIT_COMPLETE_NOT_ACTIVATION',
            'observed_at':datetime.now(timezone.utc).isoformat(),'roles':results,'generation_requests':0,
            'attempt_claims':0,'model_budget_used_micro_usd':0,'google_project_binding_verified':False}
        stream.seek(0);json.dump(result,stream,indent=2);stream.truncate();stream.flush()
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--execute-owner-approved-metadata-checks',action='store_true')
    args=parser.parse_args()
    try:result=run(args.output,approved=args.execute_owner_approved_metadata_checks)
    except Exception:raise SystemExit('Metadata audit stopped; inspect the sanitized output marker and do not automatically repeat.') from None
    print(json.dumps(result,indent=2))
