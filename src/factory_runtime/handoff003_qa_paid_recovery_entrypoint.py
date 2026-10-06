"""Disabled immutable QA recovery handler; invocation fields cannot select authority."""
import base64
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
from factory_state.model import OWNER_IDENTITY,StateError
from factory_state.scope import canonical
from factory_state.signers import validate_trusted_signers
from .handoff003_qa_paid_recovery_authorization import draft,verify,RecoveryAttemptStore,TASK,SCOPE_DIGEST
from .handoff003_qa_paid_recovery_runtime import run_once,RecoveryStopped,CANDIDATE
from .handoff003_protocols import request_bytes
from .handoff003_signing import HandoffKmsSigner,assert_session
from .handoff003_receipts import IDENTITIES
from .handoff003_entrypoint import SECRETS,_client
from .pilot002_entrypoint import _read,_pairs,_aws_session,_credential

NAME='tims-factory-handoff-003-qa-recovery-002'
ARN='arn:aws:lambda:ca-central-1:666730517561:function:'+NAME+':'
ENABLED='FACTORY_HANDOFF003_QA_PAID_RECOVERY002_ENABLED'
HASH='FACTORY_HANDOFF003_QA_PAID_RECOVERY002_ACTIVATION_SHA256'
ACTIVATION='HANDOFF003_QA_PAID_RECOVERY002_ACTIVATION.json'
ROUTE={'kind':'secretsmanager','secret_arn':SECRETS['qa'],'version_id':'db69f4bf-38c0-43d5-8bbf-ce20d8e07282','json_key':None}
REGISTRY='factory/profiles/scope-signers.json'

def current_registry(root):
    registry=json.loads(_read(root,REGISTRY,65536),object_pairs_hook=_pairs)
    registry['signers']=[v for v in registry['signers'] if v['identity'] in (OWNER_IDENTITY,IDENTITIES['qa'])]
    return registry

def load_activation(root,env,now,*,allow_unsigned=False):
    raw=_read(root,ACTIVATION,262144)
    if not re.fullmatch('[0-9a-f]{64}',env.get(HASH,'')) or hashlib.sha256(raw).hexdigest()!=env[HASH]:raise StateError('Recovery activation digest differs')
    doc=json.loads(raw,object_pairs_hook=_pairs)
    fields={'schema_version','source_commit','qualification','readiness','allowance','signer_registry','credential'}
    if type(doc) is not dict or set(doc)!=fields or doc['schema_version']!='1.0':raise StateError('Recovery activation schema differs')
    source=doc['source_commit']
    if (not isinstance(source,str) or not re.fullmatch('[0-9a-f]{40}',source) or
            json.loads(_read(root,'BUILD.json',1024),object_pairs_hook=_pairs)!={'source_commit':source} or
            doc['credential']!=ROUTE or canonical(doc['signer_registry'])!=canonical(current_registry(root))):
        raise StateError('Recovery source, credential route or trusted enrollment differs')
    keys=validate_trusted_signers(doc['signer_registry'],now=now)
    if set(keys)!={OWNER_IDENTITY,IDENTITIES['qa']}:raise StateError('Current owner and QA enrollment required')
    builder=json.loads(_read(root,'factory/evidence/handoff-003-live/builder-live-result.json',131072),object_pairs_hook=_pairs)
    request=request_bytes(root,role='qa',builder_response=base64.b64decode(builder['output_base64'],validate=True),candidate_commit=CANDIDATE)
    args=dict(root=root,source_commit=source,qualification=doc['qualification'],readiness=doc['readiness'],now=now)
    if allow_unsigned is True:
        envelope=doc['allowance']
        if type(envelope) is not dict or set(envelope)!={'payload','signature'} or envelope['signature']!='':raise StateError('Empty signature required for preparation')
        payload=envelope['payload']
        expected=draft(**args,issued_at=payload.get('issued_at'),expires_at=payload.get('expires_at'))
        if canonical(payload)!=canonical(expected):raise StateError('Unsigned recovery bindings differ')
    else:verify(doc['allowance'],**args,trusted_keys=keys,request_bytes=request)
    if doc['allowance']['payload']['expires_at']-now.timestamp()<210:raise StateError('Insufficient fresh recovery window')
    return doc,keys

class RecoveryKmsSigner(HandoffKmsSigner):
    def __init__(self,*,kms,sts,trusted_keys,source_commit,request_digest):
        super().__init__(role='qa',kms=kms,sts=sts,trusted_keys=trusted_keys,model_id='gemini-3.7-flash',
            source_commit=source_commit,request_digest=request_digest,predecessor_receipt_digest=None)
        self.expected={'kind':'handoff003_qa_paid_recovery002_result','task_id':TASK,'role':'qa','producer_identity':IDENTITIES['qa'],
            'model_id':'gemini-3.7-flash','source_commit':source_commit,'scope_digest':SCOPE_DIGEST,
            'request_digest':request_digest,'transport_invocations':1}

def dispatch(event,context,*,root,env,clock):
    if env.get(ENABLED)!='true':raise StateError('QA recovery entry point disabled')
    try:
        arn=context.invoked_function_arn
        if (not isinstance(arn,str) or not arn.startswith(ARN) or not re.fullmatch('[1-9][0-9]*',arn[len(ARN):]) or
                env.get('AWS_REGION')!='ca-central-1' or env.get('AWS_LAMBDA_FUNCTION_NAME')!=NAME or
                context.get_remaining_time_in_millis()<210000):raise StateError('Exact recovery version and runtime required')
        doc,keys=load_activation(root,env,clock())
        if event!={'kind':'handoff003_qa_paid_recovery002_run_once','source_commit':doc['source_commit'],'activation_sha256':env[HASH]}:
            raise StateError('Recovery event binding differs')
        session=_aws_session(env);sts=_client(session,'sts');assert_session(sts,'tims-factory-review-qa')
        signer=RecoveryKmsSigner(kms=_client(session,'kms'),sts=sts,trusted_keys=keys,
            source_commit=doc['source_commit'],request_digest=doc['allowance']['payload']['request_digest'])
        return run_once(doc['allowance'],root=root,source_commit=doc['source_commit'],qualification=doc['qualification'],
            readiness=doc['readiness'],trusted_keys=keys,store=RecoveryAttemptStore(_client(session,'dynamodb')),
            load_credential=lambda:_credential(session,doc['credential']),sign_receipt=signer.sign,clock=clock,enabled=True)
    except RecoveryStopped as error:
        return {'status':'QA_RECOVERY_FAILED_NO_RETRY','failure_stage':error.stage,'failure_code':error.failure_code,
            'attempt_reusable':False,'hold_release_authorized':False,'gate_authority':False}
    except Exception:raise StateError('QA recovery entry point stopped; reconcile without retry') from None

def handler(event,context):
    return dispatch(event,context,root=Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task')),env=os.environ,clock=lambda:datetime.now(timezone.utc))
