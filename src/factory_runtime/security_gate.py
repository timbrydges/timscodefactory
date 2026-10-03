"""One proposed Security gate: pinned evidence, fresh lease, independent Security signature.

No live authority is provided by these functions or by historical provenance.
Deployment-owned approval is required; callers cannot supply it in an event.
"""
import base64
import hashlib
import json
import re
from dataclasses import replace
from datetime import datetime, timezone

from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY, Evidence, FactoryStateMachine, Lease, StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import load_trusted_signers
from .security_validation_attestation import IDENTITY, KEY, REGISTRY
from .security_validation import validate_execution
from .review_preparation import prepare, pinned, digest

AUTHORIZATION = 'security-gate-001'
LEASE_ID = AUTHORIZATION
BASELINE = 'factory/evidence/security-gate-001-baseline.json'
BASELINE_SHA = '7411ca47feb0ba3e0478e3b84400a084ce75e504816974c61d703ceebe2378e4'
ATTESTATION = 'factory/evidence/security-bounded-validation-live-proof-2026-10-03.json'
ATTESTATION_SHA = 'bdde5f70dc045363558edf4b4024abf1568a76c0b0bb5d75cb1dc0551fa24c41'
HISTORICAL_REGISTRY = 'factory/evidence/security-validation-signers-2026-10-03.json'
HISTORICAL_REGISTRY_SHA = '6da51e17c4052b73f4649480aca52f8e9d3e7ced86c00a6b0b3764ca480cd25b'
ACCEPTANCE = 'factory/evidence/security-scope-acceptance-001.json'
ACCEPTANCE_SHA = 'bd1ca825d4c6ad0f70686be37410566c42a5ee82f217e798bf09cd784747eaa7'
ENABLED = 'FACTORY_SECURITY_GATE_ENABLED'
CONFIG = 'FACTORY_SECURITY_GATE_CONFIG'


def evidence(root):
    packet=prepare(root,role='security')
    record=pinned(root,ATTESTATION,ATTESTATION_SHA)
    result=record['result']; payload=result['payload']; report=result['report']
    issued=datetime.fromtimestamp(payload['issued_at'],timezone.utc)
    pinned(root,HISTORICAL_REGISTRY,HISTORICAL_REGISTRY_SHA)
    keys=load_trusted_signers(root/HISTORICAL_REGISTRY,now=issued)
    signed=SignedScopeStore('unused',None,keys)._verify(payload,
        base64.b64decode(result['signature_base64'],validate=True),IDENTITY,issued)
    accepted=pinned(root,ACCEPTANCE,ACCEPTANCE_SHA)
    if (signed!=record['signed_payload_digest'] or signed!=accepted['signed_validation_digest'] or
            payload['registry_sha256']!=HISTORICAL_REGISTRY_SHA or
            payload['gate_authority'] is not False or payload['report_verified'] is not True or
            payload['report_digest']!=report['report_digest'] or
            accepted['approved'] is not True or accepted['candidate_commit']!=packet['candidate_commit'] or
            accepted['scope']!=report['scope'] or
            accepted['accepted_findings']!=[f['id'] for f in report['findings']] or
            not validate_execution(report,packet,root=root)):
        raise StateError('Security validation or owner scope acceptance differs')
    return {'candidate_commit':packet['candidate_commit'],'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'],'executor_payload_digest':signed,
        'executor_report_digest':report['report_digest'],'owner_scope_acceptance_sha256':ACCEPTANCE_SHA,
        'acceptance_scope':report['scope'],'retained_findings':accepted['accepted_findings'],
        'general_use_findings_remain_open':True,'os_sandbox_claimed':False}


def baseline(root):
    pinned(root, BASELINE, BASELINE_SHA)
    state = DynamoDBStateStore._deserialize_payload((root/BASELINE).read_text())
    if (state.factory_id != 'tims-software-factory' or state.task_id != 'deterministic-text-fingerprint' or
            state.state != 'SECURITY_REVIEW' or state.version != 14 or any(not x.revoked for x in state.leases)):
        raise StateError('Security baseline differs')
    return state


def approval(root, raw, *, commit, now):
    """Trusted deployment configuration only. Never read approval from task input."""
    try:
        value = json.loads(raw) if isinstance(raw,str) and len(raw)<=2500 else None
        fields = {'authorization_id','owner_identity','approved','source_commit','not_before',
                  'expires_at','nonce','synthetic_scope_accepted'}
        if (not isinstance(value,dict) or set(value)!=fields or
                value['authorization_id']!=AUTHORIZATION or value['owner_identity']!='tim_brydges' or
                value['approved'] is not True or value['synthetic_scope_accepted'] is not True or
                not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit) or
                value['source_commit']!=commit or not isinstance(value['nonce'],str) or
                not re.fullmatch('[0-9a-f]{32}',value['nonce']) or
                type(value['not_before']) is not int or type(value['expires_at']) is not int or
                not 0 < value['expires_at']-value['not_before'] <= 3600 or
                now.tzinfo is None or now.utcoffset() is None or
                not value['not_before'] <= now.timestamp() < value['expires_at']):
            raise ValueError()
        keys = load_trusted_signers(root/REGISTRY, now=now)
        entry = next(e for e in json.loads((root/REGISTRY).read_bytes())['signers'] if e['identity']==IDENTITY)
        if IDENTITY not in keys or value['expires_at']>entry['expires_at']:
            raise ValueError()
    except (TypeError, ValueError, KeyError, StopIteration):
        raise StateError('Security gate approval absent, changed or expired') from None
    return value


def payload_for(facts, config, *, issued_at):
    return {'kind':'security_gate_result','purpose':'security-to-release-ready-synthetic-only',
        'producer_identity':IDENTITY,'key_arn':KEY,'authorization_id':AUTHORIZATION,
        'source_commit':config['source_commit'],'nonce':config['nonce'],
        'factory_id':'tims-software-factory','task_id':'deterministic-text-fingerprint',
        'baseline_sha256':BASELINE_SHA,'lease_id':LEASE_ID,'lease_version':15,
        'target_state':'RELEASE_READY','verdict':'ACCEPTED',**facts,
        'issued_at':issued_at,'expires_at':config['expires_at'],
        'gate_authority':True,'production_release_authorized':False,'model_calls':0}


class SecurityGateController:
    def __init__(self, root, states, raw_config, *, commit, clock):
        self.root, self.states, self.raw_config = root, states, raw_config
        self.commit, self.clock = commit, clock

    def _checked(self):
        now = self.clock()
        config = approval(self.root,self.raw_config,commit=self.commit,now=now)
        facts = evidence(self.root)
        before = baseline(self.root)
        lease = Lease(LEASE_ID,'deep_security_reviewer',IDENTITY,datetime.fromtimestamp(config['expires_at'],timezone.utc))
        state = self.states.load_state(before.factory_id,before.task_id)
        if state is None:
            raise StateError('Security task missing')
        return now, config, facts, before, lease, state

    def _persist(self, before, machine, after):
        token = 'security-' + hashlib.sha256(canonical(machine.last_audit_event)).hexdigest()[:32]
        self.states.persist_transition(before,after,caller_identity=CONTROLLER_IDENTITY,
            event_id=token,audit_event=machine.last_audit_event)

    @staticmethod
    def _leased(before, lease, state):
        return replace(before,version=15,updated_at=state.updated_at,
                       leases=before.leases+(lease,))

    def issue_lease(self):
        now, config, _, before, lease, state = self._checked()
        if (state==self._leased(before,lease,state) and
                config['not_before'] <= state.updated_at.timestamp() <= now.timestamp()):
            return {'status':'LEASE_ALREADY_ISSUED','state':'SECURITY_REVIEW','version':15,'lease_id':LEASE_ID}
        if state!=before:
            raise StateError('Security baseline drift; no lease or history reset permitted')
        machine = FactoryStateMachine(state)
        after = machine.issue_lease(CONTROLLER_IDENTITY,lease,expected_version=14,now=now)
        self._persist(state,machine,after)
        return {'status':'LEASE_ISSUED','state':'SECURITY_REVIEW','version':15,'lease_id':LEASE_ID}

    def complete(self, result):
        now, config, facts, before, lease, state = self._checked()
        if not isinstance(result,dict) or set(result)!={'payload','signature_base64'}:
            raise StateError('Security gate result fields differ')
        payload = result['payload']
        if (not isinstance(payload,dict) or type(payload.get('issued_at')) is not int or
                canonical(payload)!=canonical(payload_for(facts,config,issued_at=payload['issued_at'])) or
                not config['not_before']<=payload['issued_at']):
            raise StateError('Security gate payload differs from approved evidence and lease')
        keys = load_trusted_signers(self.root/REGISTRY,now=now)
        try:
            raw_signature = base64.b64decode(result['signature_base64'],validate=True)
        except (ValueError,TypeError):
            raise StateError('Security gate signature encoding invalid') from None
        signed_digest = SignedScopeStore('unused',None,keys)._verify(payload,raw_signature,IDENTITY,now)
        evidence_id = 'security-gate-' + signed_digest.removeprefix('sha256:')
        imported = self._leased(before,lease,state)
        completed = replace(imported,state='RELEASE_READY',version=16,
            leases=tuple(replace(x,revoked=True) for x in imported.leases),
            consumed_evidence_ids=before.consumed_evidence_ids|{evidence_id})
        if state==completed and payload['issued_at']<=state.updated_at.timestamp()<=now.timestamp():
            return {'status':'ALREADY_ADVANCED','state':'RELEASE_READY','version':16}
        if (state!=imported or not config['not_before']<=state.updated_at.timestamp()<=now.timestamp() or
                payload['issued_at']<state.updated_at.timestamp()):
            raise StateError('Security lease missing or task drift; no transition permitted')
        item = Evidence(evidence_id,'deep_security_reviewer',IDENTITY,before.task_id,LEASE_ID,
            facts['candidate_commit'],signed_digest,datetime.fromtimestamp(payload['issued_at'],timezone.utc),True)
        machine = FactoryStateMachine(state)
        after = machine.transition(CONTROLLER_IDENTITY,'RELEASE_READY',expected_version=15,evidence=(item,),now=now)
        self._persist(state,machine,after)
        return {'status':'ADVANCED','state':'RELEASE_READY','version':16,'evidence_id':evidence_id,
                'model_calls':0,'schedule_enabled':False,'release_dispatched':False}
