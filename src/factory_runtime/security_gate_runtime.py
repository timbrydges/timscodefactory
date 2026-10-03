"""Disabled-by-default Security publisher and controller entrypoints.

The operator must journal the single signing invocation externally. A nonce is
not a durable replay ledger. The controller independently requires the live lease.
"""
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from factory_state.dynamodb import DynamoDBStateStore
from factory_state.kms_signer import ALGORITHM, public_pem
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import load_trusted_signers
from . import security_gate as gate


def boundary(event, *, root, env, role, now):
    if (env.get(gate.ENABLED)!='true' or
            any(env.get(flag,'false')!='false' for flag in (
                'FACTORY_QA_GATE_ENABLED','FACTORY_SECURITY_VALIDATION_ENABLED',
                'FACTORY_SECURITY_ATTESTATION_ENABLED')) or
            (role=='controller' and env.get('FACTORY_AUTONOMY_CONTROLLER_ENABLED')!='false') or
            (role=='security' and (env.get('FACTORY_REVIEW_ROLE')!='security' or
                env.get('FACTORY_OPERATIONAL_EXECUTION_ENABLED')!='false' or
                env.get('FACTORY_REVIEW_KEY_ARN')!=gate.KEY))):
        raise StateError('Security gate is disabled or deployed to the wrong role')
    commit = json.loads((root/'BUILD.json').read_bytes())['source_commit']
    config = gate.approval(root,env.get(gate.CONFIG),commit=commit,now=now)
    common = {'source_commit':commit,'authorization_id':gate.AUTHORIZATION,'nonce':config['nonce']}
    if role=='security':
        valid = event=={'kind':'publish_security_gate',**common}
    else:
        valid = (event=={'kind':'issue_security_gate_lease',**common} or
            isinstance(event,dict) and set(event)=={'kind',*common,'result'} and
            event['kind']=='complete_security_gate' and all(event[k]==v for k,v in common.items()))
    if not valid:
        raise StateError('Security gate event differs from exact deployment approval')
    return commit, config


def publish(event, *, root, env, kms, sts, clock):
    commit, config = boundary(event,root=root,env=env,role='security',now=clock())
    facts = gate.evidence(root)
    caller = sts.get_caller_identity()
    prefix = 'arn:aws:sts::666730517561:assumed-role/tims-factory-review-security/'
    arn = caller.get('Arn','')
    if (caller.get('Account')!='666730517561' or not isinstance(arn,str) or
            not arn.startswith(prefix) or not arn[len(prefix):] or '/' in arn[len(prefix):]):
        raise StateError('Security gate signer cloud identity differs')
    now = clock()
    gate.approval(root,env.get(gate.CONFIG),commit=commit,now=now)
    keys = load_trusted_signers(root/gate.REGISTRY,now=now)
    if public_pem(kms.get_public_key(KeyId=gate.KEY),expected_arn=gate.KEY)!=keys[gate.IDENTITY]:
        raise StateError('Security gate KMS key differs from enrollment')
    now = clock()
    gate.approval(root,env.get(gate.CONFIG),commit=commit,now=now)
    payload = gate.payload_for(facts,config,issued_at=int(now.timestamp()))
    message = canonical(payload)
    if len(message)>4096:
        raise StateError('Security gate exceeds KMS RAW message limit')
    try:
        response = kms.sign(KeyId=gate.KEY,Message=message,MessageType='RAW',SigningAlgorithm=ALGORITHM)
        if response.get('KeyId')!=gate.KEY or response.get('SigningAlgorithm')!=ALGORITHM:
            raise StateError('Security gate signing response differs')
        signature = response.get('Signature')
        SignedScopeStore('unused',None,keys)._verify(payload,signature,gate.IDENTITY,clock())
    except Exception:
        raise StateError('Security gate signing outcome uncertain; preserve journal and never retry') from None
    return {'payload':payload,'signature_base64':base64.b64encode(signature).decode()}


def _setup(event, role):
    root = Path(os.environ.get('LAMBDA_TASK_ROOT','/var/task'))
    clock = lambda: datetime.now(timezone.utc)
    commit, _ = boundary(event,root=root,env=os.environ,role=role,now=clock())
    gate.evidence(root)  # Reject changed evidence before constructing any AWS clients.
    import boto3
    from botocore.config import Config
    session = boto3.Session(region_name='ca-central-1')
    config = Config(connect_timeout=5,read_timeout=10,retries={'total_max_attempts':1,'mode':'standard'})
    return root, commit, clock, session, config


def signer_handler(event, context):
    root, _, clock, session, config = _setup(event,'security')
    return publish(event,root=root,env=os.environ,clock=clock,
        kms=session.client('kms',endpoint_url='https://kms.ca-central-1.amazonaws.com',config=config),
        sts=session.client('sts',endpoint_url='https://sts.ca-central-1.amazonaws.com',config=config))


def controller_handler(event, context):
    root, commit, clock, session, config = _setup(event,'controller')
    service = gate.SecurityGateController(root,
        DynamoDBStateStore('tims-software-factory-state',session.client('dynamodb',config=config)),
        os.environ[gate.CONFIG],commit=commit,clock=clock)
    if event['kind']=='issue_security_gate_lease':
        return service.issue_lease()
    return service.complete(event['result'])
