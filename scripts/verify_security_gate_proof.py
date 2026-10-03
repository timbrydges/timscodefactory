"""Offline historical verification; no new gate or release authority."""
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from factory_runtime import security_gate as gate
from factory_runtime.review_preparation import pinned
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY, Evidence, FactoryStateMachine, Lease, StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import load_trusted_signers

PROOF='factory/evidence/security-gate-001-live-proof-2026-10-03.json'
SHA='9f48a0176826c406b8398a4e34eeeab0ad6b44b0f41494ac6a8c19c61e8a5c3f'


def verify_document(proof, *, root):
    try:
        facts=gate.evidence(root); before=gate.baseline(root)
        result=proof['signed_result']; payload=result['payload']; config=proof['authorization']
        issued=datetime.fromtimestamp(payload['issued_at'],timezone.utc)
        if (config['approved'] is not True or config['owner_identity']!='tim_brydges' or
                config['synthetic_scope_accepted'] is not True or
                not config['not_before']<=issued.timestamp()<config['expires_at'] or
                not 0<config['expires_at']-config['not_before']<=3600 or
                config['source_commit']!=proof['source_commit'] or
                canonical(payload)!=canonical(gate.payload_for(facts,config,issued_at=payload['issued_at']))):
            raise StateError('Security gate signed scope or authorization differs')
        pinned(root,gate.HISTORICAL_REGISTRY,gate.HISTORICAL_REGISTRY_SHA)
        signed=SignedScopeStore('unused',None,load_trusted_signers(root/gate.HISTORICAL_REGISTRY,now=issued))._verify(
            payload,base64.b64decode(result['signature_base64'],validate=True),gate.IDENTITY,issued)
        eid='security-gate-'+signed.removeprefix('sha256:')
        if signed!=proof['signed_payload_digest'] or eid!=proof['evidence_id']:
            raise StateError('Security gate signature digest differs')
        leased=DynamoDBStateStore._deserialize_payload(json.dumps(proof['leased_state']))
        final=DynamoDBStateStore._deserialize_payload(json.dumps(proof['final_state']))
        if not config['not_before']<=leased.updated_at.timestamp()<=issued.timestamp()<=final.updated_at.timestamp()<config['expires_at']:
            raise StateError('Security lease/signature ordering differs')
        lease=Lease(gate.LEASE_ID,'deep_security_reviewer',gate.IDENTITY,
                    datetime.fromtimestamp(config['expires_at'],timezone.utc))
        first=FactoryStateMachine(before)
        if first.issue_lease(CONTROLLER_IDENTITY,lease,expected_version=14,now=leased.updated_at)!=leased:
            raise StateError('Security lease history differs')
        item=Evidence(eid,'deep_security_reviewer',gate.IDENTITY,before.task_id,gate.LEASE_ID,
                      facts['candidate_commit'],signed,issued,True)
        second=FactoryStateMachine(leased)
        if second.transition(CONTROLLER_IDENTITY,'RELEASE_READY',expected_version=15,evidence=(item,),now=final.updated_at)!=final:
            raise StateError('Security completion history differs')
        if len(proof['audit_events'])!=2: raise StateError('Security audit missing')
        for machine,prior,after,stored in zip((first,second),(before,leased),(leased,final),proof['audit_events']):
            audit=machine.last_audit_event
            token='sec-'+hashlib.sha256(canonical(audit)).hexdigest()[:32]
            expected={'PK':{'S':f'FACTORY#{before.factory_id}#TASK#{before.task_id}'},
                'SK':{'S':f'EVENT#{audit["at"]}#{token}'},
                'actor_identity':{'S':CONTROLLER_IDENTITY},
                'event_type':{'S':audit['event_type']},
                'from_version':{'N':str(audit['from_version'])},'to_version':{'N':str(audit['to_version'])},
                'from_state':{'S':prior.state},'to_state':{'S':after.state}}
            if ({k:stored[k] for k in expected}!=expected or json.loads(stored['details']['S'])!=audit['details']):
                raise StateError('Security stored audit differs')
        if (proof['state']!='RELEASE_READY' or proof['version']!=16 or
                proof['signing_invocations']!=1 or proof['signing_retries']!=0 or
                proof['controller_invocations']!=2 or proof['earlier_failed_controller_invocations']!=1 or
                proof['total_controller_invocations']!=3 or proof['schedule']!='DISABLED' or
                any(proof[k]!=0 for k in ('security_concurrency','controller_concurrency','google_broker_concurrency')) or
                proof['gate_flags_disabled'] is not True or
                proof['model_calls']!=0 or proof['candidate_executions']!=0 or
                proof['shutdown']['disabled'] is not True or proof['shutdown']['errors'] or
                proof['access_removed']['logging_only'] is not True or
                proof['access_removed']['functions_disabled'] is not True or
                proof['production_release_authorized'] is not False):
            raise StateError('Security completion or shutdown differs')
        expiration=proof['permission_policy']['PolicyDocument']['Statement'][0]['Condition']['DateLessThan']['aws:CurrentTime']
        if expiration!=proof['original_access_expiration'] or datetime.fromisoformat(expiration).timestamp()!=config['expires_at']:
            raise StateError('Original permission expiration was extended')
        for key in ('shutdown','access_removed'):
            if not final.updated_at.timestamp()<=datetime.fromisoformat(proof[key]['verified_at']).timestamp()<config['expires_at']:
                raise StateError('Cleanup was not verified within the approved window')
    except (KeyError,TypeError,ValueError,AttributeError):
        raise StateError('Security gate proof malformed') from None
    return {'status':'HISTORICAL_SECURITY_GATE_VERIFIED','state':final.state,'version':final.version,
        'signed_payload_digest':signed,'scope':facts['acceptance_scope'],
        'retained_findings':facts['retained_findings'],'new_execution_authorized':False,
        'production_release_authorized':False}


def verify(root=ROOT): return verify_document(pinned(root,PROOF,SHA),root=root)


if __name__=='__main__': print(json.dumps(verify(),indent=2))
