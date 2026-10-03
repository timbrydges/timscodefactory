"""Prepare or execute one owner-approved Builder input-token measurement."""
import argparse
from datetime import datetime,timezone
import hashlib
import http.client
import json
import logging
from pathlib import Path
import ssl
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime.pilot002_protocols import request_bytes,MAX_INPUT_TOKENS
from factory_state.scope import canonical
from check_pilot002_provider_metadata import read_credential,REGION,ACCOUNT
from check_pilot002_google_binding import pairs


def sha(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()


def prepare(root=ROOT):
    raw=request_bytes(root,role='builder');body=json.loads(raw)
    fixed={'model':'gpt-5.6-sol','store':False,'background':False,'stream':False,'tools':[],
        'service_tier':'default','truncation':'disabled','prompt_cache_options':{'mode':'explicit'},
        'max_output_tokens':4096,'reasoning':{'effort':'low'},'text':{'format':{'type':'json_object'}}}
    if set(body)!=set(fixed)|{'instructions','input'} or any(type(body[k]) is not type(v) or body[k]!=v for k,v in fixed.items()):
        raise ValueError('unreviewed Builder request')
    # Preserve every supported input/context field; omit fixed execution-only controls.
    count={k:body[k] for k in ('model','instructions','input','tools','reasoning','text','truncation')}
    encoded=canonical(count)
    return {'status':'PREPARED_NOT_EXECUTED','endpoint':'https://api.openai.com/v1/responses/input_tokens',
        'generation_request_digest':sha(raw),'count_request_digest':sha(encoded),
        'count_request':count,'count_request_bytes':len(encoded),'generation_requests':0}


def measure(plan,load_credential):
    connection=None
    result={'status':'TOKEN_MEASUREMENT_FAILED','generation_request_digest':plan['generation_request_digest'],
        'count_request_digest':plan['count_request_digest'],'http_requests':0,'generation_requests':0,
        'cost_qualified':False,'live_execution_authorized':False}
    stage='credential'
    try:
        key,kind=load_credential()
        if kind!='raw' or not isinstance(key,str) or not 16<=len(key)<=512 or any(ord(c)<33 or ord(c)>126 for c in key):
            raise ValueError('credential format')
        context=ssl.create_default_context();context.set_alpn_protocols(['http/1.1'])
        connection=http.client.HTTPSConnection('api.openai.com',443,timeout=30,context=context)
        connection.set_debuglevel(0);stage='request';result['http_requests']=1
        connection.request('POST','/v1/responses/input_tokens',body=canonical(plan['count_request']),
            headers={'Authorization':'Bearer '+key,'Content-Type':'application/json','Accept':'application/json',
                'Accept-Encoding':'identity','Connection':'close'})
        key=None
        response=connection.getresponse();stage='response';result['http_status']=response.status
        if response.status!=200:
            result['status']='TOKEN_ENDPOINT_REJECTED';return result
        if response.getheader('Content-Type','').split(';',1)[0].strip().lower()!='application/json':raise ValueError('format')
        if response.getheader('Content-Encoding','identity').lower()!='identity':raise ValueError('encoding')
        raw=response.read(8193)
        if not 0<len(raw)<=8192:raise ValueError('size')
        value=json.loads(raw,object_pairs_hook=pairs)
        if (not isinstance(value,dict) or set(value)!={'object','input_tokens'} or
                value['object']!='response.input_tokens' or type(value['input_tokens']) is not int or
                not 0<value['input_tokens']<=MAX_INPUT_TOKENS):raise ValueError('invalid count')
        result.update(status='INPUT_TOKEN_COUNT_OBSERVED',input_tokens=value['input_tokens'])
        return result
    except Exception:
        result['failed_stage']=stage;return result
    finally:
        if connection is not None:
            try:connection.close()
            except Exception:pass


def run(output,expected_digest,*,approved=False):
    if approved is not True:raise ValueError('owner approval required')
    plan=prepare()
    if expected_digest!=plan['count_request_digest']:raise ValueError('count request differs from approval')
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT):raise ValueError('clean checkout required')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    output=Path(output).resolve()
    if output.is_relative_to(ROOT):raise ValueError('output must be outside repository')
    with output.open('x',encoding='utf-8') as stream:
        stream.write('{"status":"STARTED_NO_AUTOMATIC_RETRY"}\n');stream.flush()
        import boto3
        from botocore.config import Config
        logging.getLogger('botocore').setLevel(logging.CRITICAL)
        cfg=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=10,proxies={})
        session=boto3.Session(region_name=REGION)
        if session.client('sts',config=cfg).get_caller_identity()['Account']!=ACCOUNT:raise ValueError('AWS account')
        client=session.client('secretsmanager',endpoint_url='https://secretsmanager.'+REGION+'.amazonaws.com',config=cfg)
        result=measure(plan,lambda:read_credential(client,'builder'))
        result.update(source_commit=commit,observed_at=datetime.now(timezone.utc).isoformat(),attempt_claims=0)
        stream.seek(0);json.dump(result,stream,indent=2);stream.truncate();stream.flush()
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output');parser.add_argument('--expected-digest')
    parser.add_argument('--owner-approved-token-count',action='store_true');args=parser.parse_args()
    try:
        result=run(args.output,args.expected_digest,approved=True) if args.owner_approved_token_count else prepare()
        print(json.dumps(result,indent=2))
    except Exception:raise SystemExit('Token preflight stopped. Reconcile output; do not automatically repeat.') from None
