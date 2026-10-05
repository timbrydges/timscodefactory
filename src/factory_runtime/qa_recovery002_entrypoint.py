"""Disabled recovery-only boundary; activation, keys and prices are deployment-owned."""
import base64
import hashlib
import json
import os
import re
from pathlib import Path
from datetime import datetime,timezone

from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
from .qa_recovery002 import RecoveryAttemptStore,CANDIDATE
from .qa_recovery002_authorization import verify
from .qa_recovery002_runtime import run_once
from .pilot002_adapter import Pilot002Adapter
from .pilot002_protocols import request_bytes
from .pilot002_entrypoint import _read,_pairs,_aws_session,_client,_credential,REGION,ACCOUNT

GOOGLE_ROUTE={'kind':'secretsmanager','secret_arn':'arn:aws:secretsmanager:ca-central-1:666730517561:secret:tims-software-factory/provider/google/qa-rYGeOE','version_id':'db69f4bf-38c0-43d5-8bbf-ce20d8e07282','json_key':None}

ACTIVATION='QA_RECOVERY002_ACTIVATION.json'
FUNCTION='tims-factory-qa-recovery-002'
ENABLED='FACTORY_QA_RECOVERY002_ENABLED'
ACTIVATION_SHA='FACTORY_QA_RECOVERY002_ACTIVATION_SHA256'


def load_activation(root,env,now):
    raw=_read(root,ACTIVATION,131072)
    expected=env.get(ACTIVATION_SHA,'')
    if not re.fullmatch('[0-9a-f]{64}',expected) or hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('activation digest')
    doc=json.loads(raw,object_pairs_hook=_pairs)
    fields={'schema_version','kind','source_commit','candidate_commit','builder_response_base64',
        'qualification','readiness','signer_registry','credential','capture_failed_review_response'}
    if (type(doc) is not dict or set(doc)!=fields or doc['schema_version']!='1.0' or
            doc['kind']!='qa_recovery002_activation' or doc['candidate_commit']!=CANDIDATE or
            doc['credential']!=GOOGLE_ROUTE or doc['capture_failed_review_response'] is not True):
        raise ValueError('recovery activation schema')
    build=json.loads(_read(root,'BUILD.json',1024),object_pairs_hook=_pairs)
    source=doc['source_commit']
    if type(source) is not str or not re.fullmatch('[0-9a-f]{40}',source) or build!={'source_commit':source}:
        raise ValueError('runtime source')
    keys=validate_trusted_signers(doc['signer_registry'],now=now)
    if set(keys)!={OWNER_IDENTITY}:raise ValueError('owner enrollment')
    encoded=doc['builder_response_base64']
    if type(encoded) is not str or len(encoded)>44000:raise ValueError('builder context')
    context={'root':root,'source_commit':source,'candidate_commit':CANDIDATE,
        'builder_response':base64.b64decode(encoded,validate=True)}
    return doc,context,keys


def dispatch(event,context,*,root,env,clock):
    if env.get(ENABLED)!='true':raise StateError('QA recovery entry point disabled')
    try:
        expected='arn:aws:lambda:'+REGION+':'+ACCOUNT+':function:'+FUNCTION
        if (context.invoked_function_arn!=expected or context.get_remaining_time_in_millis()<120000 or
                env.get('AWS_REGION')!=REGION or env.get('AWS_LAMBDA_FUNCTION_NAME')!=FUNCTION):
            raise ValueError('recovery runtime identity or time')
        if type(event) is not dict or set(event)!={'kind','allowance'} or event['kind']!='qa_recovery002_run_once' or len(canonical(event))>32768:
            raise ValueError('recovery event')
        now=clock();doc,bound,keys=load_activation(root,env,now)
        adapter=Pilot002Adapter(**bound,role='qa',qualification=doc['qualification'],clock=clock,enabled=False)
        request=request_bytes(root,role='qa',builder_response=bound['builder_response'],candidate_commit=CANDIDATE)
        verify(event['allowance'],**bound,request_bytes=request,pricing=adapter.pricing,
            readiness=doc['readiness'],trusted_keys=keys,now=now)
        session=_aws_session(env)
        store=RecoveryAttemptStore(_client(session,'dynamodb'),root=root,enabled=True)
    except Exception:
        raise StateError('QA recovery entry point rejected preparation; no invocation') from None
    # Workflow emits only fixed stages or bounded untrusted response evidence.
    return run_once(event['allowance'],**bound,qualification=doc['qualification'],readiness=doc['readiness'],
        trusted_keys=keys,store=store,load_credential=lambda:_credential(session,doc['credential']),
        clock=clock,enabled=True)


def handler(event,context):
    return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),
        env=os.environ,clock=lambda:datetime.now(timezone.utc))
