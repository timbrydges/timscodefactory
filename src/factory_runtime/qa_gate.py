"""One proposed QA gate: pinned evidence, fresh lease, independent QA signature.

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
from .qa_enrollment import BUNDLE, BUNDLE_SHA, PROOF, PROOF_SHA, IDENTITY, KEY, REGISTRY
from .qa_evidence import validate_execution
from .google_qa_records import parse_record
from .review_preparation import prepare, pinned, digest

AUTHORIZATION = 'qa-gate-001'
LEASE_ID = 'qa-gate-001'
BASELINE = 'factory/evidence/qa-gate-001-baseline.json'
BASELINE_SHA = 'eac3eea1934914008f10be0546f9c4ae6140cd8ebaf609d25baa61d5c11c1313'
ATTESTATION = 'factory/evidence/qa-executor-attestation-live-proof-2026-10-03.json'
ATTESTATION_SHA = 'd14e6f5476ce3e8087925dfe50d24cf925ce93a42b841677d33c26e61b936411'
ENABLED = 'FACTORY_QA_GATE_ENABLED'
CONFIG = 'FACTORY_QA_GATE_CONFIG'


def evidence(root):
    """Verify historical tests and recorded Google result, without promoting either."""
    packet = prepare(root, role='qa')
    record = pinned(root, ATTESTATION, ATTESTATION_SHA)
    result = record['result']; payload = result['payload']
    issued = datetime.fromtimestamp(payload['issued_at'], timezone.utc)
    keys = load_trusted_signers(root/REGISTRY, now=issued)
    signature_digest = SignedScopeStore('unused', None, keys)._verify(
        payload, base64.b64decode(result['signature_base64'], validate=True), IDENTITY, issued)
    if (payload['kind'] != 'qa_execution_attestation' or payload['purpose'] != 'executor-provenance-only' or
            payload['identity'] != IDENTITY or payload['key_arn'] != KEY or
            payload['gate_authority'] is not False or payload['production_release_authorized'] is not False or
            any(payload[k] != packet[k] for k in ('candidate_commit','contract_digest','packet_digest')) or
            signature_digest != record['signed_payload_digest'] or
            payload['registry_sha256'] != hashlib.sha256((root/REGISTRY).read_bytes()).hexdigest() or
            payload['report_digest'] != result['report']['report_digest'] or
            not validate_execution(result['report'], packet, root=root)):
        raise StateError('QA executor provenance differs or tests failed')
    bundle = pinned(root, BUNDLE, BUNDLE_SHA)
    proof = pinned(root, PROOF, PROOF_SHA)
    google = parse_record(canonical(bundle['google_assessment']), packet, root=root)
    if (google['assessment']['verdict'] != 'ACCEPTED' or
            bundle['review_status'] != 'READY_FOR_INDEPENDENT_PUBLICATION_REVIEW' or
            bundle['google_response_digest'] != digest(google) or
            proof['combined_bundle_digest'] != digest(bundle) or
            proof['reconciliation']['response_digest'] != digest(google) or
            proof['reconciliation']['status'] != 'COMPLETE_UNSIGNED_HOLD_RETAINED'):
        raise StateError('recorded Google evidence differs or was not accepted')
    return {'candidate_commit':packet['candidate_commit'],'contract_digest':packet['contract_digest'],
        'packet_digest':packet['packet_digest'],'executor_payload_digest':signature_digest,
        'executor_report_digest':payload['report_digest'],'google_record_digest':digest(google),
        'google_evidence_type':'OWNER_ACCEPTED_RECORDED_UNSIGNED_RESPONSE'}


def baseline(root):
    pinned(root, BASELINE, BASELINE_SHA)
    state = DynamoDBStateStore._deserialize_payload((root/BASELINE).read_text())
    if (state.factory_id != 'tims-software-factory' or state.task_id != 'deterministic-text-fingerprint' or
            state.state != 'QA' or state.version != 12 or any(not x.revoked for x in state.leases)):
        raise StateError('QA baseline differs')
    return state


def approval(root, raw, *, commit, now):
    """Trusted deployment configuration only. Never read approval from task input."""
    try:
        value = json.loads(raw) if isinstance(raw,str) and len(raw)<=2500 else None
        fields = {'authorization_id','owner_identity','approved','source_commit','not_before',
                  'expires_at','nonce','recorded_google_evidence_accepted'}
        if (not isinstance(value,dict) or set(value)!=fields or
                value['authorization_id']!=AUTHORIZATION or value['owner_identity']!='tim_brydges' or
                value['approved'] is not True or value['recorded_google_evidence_accepted'] is not True or
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
        raise StateError('QA gate approval absent, changed or expired') from None
    return value


def payload_for(facts, config, *, issued_at):
    return {'kind':'qa_gate_result','purpose':'qa-to-security-review-only',
        'producer_identity':IDENTITY,'key_arn':KEY,'authorization_id':AUTHORIZATION,
        'source_commit':config['source_commit'],'nonce':config['nonce'],
        'factory_id':'tims-software-factory','task_id':'deterministic-text-fingerprint',
        'baseline_sha256':BASELINE_SHA,'lease_id':LEASE_ID,'lease_version':13,
        'target_state':'SECURITY_REVIEW','verdict':'ACCEPTED',**facts,
        'issued_at':issued_at,'expires_at':config['expires_at'],
        'gate_authority':True,'production_release_authorized':False,'model_calls':0}


class QaGateController:
    def __init__(self, root, states, raw_config, *, commit, clock):
        self.root, self.states, self.raw_config = root, states, raw_config
        self.commit, self.clock = commit, clock

    def _checked(self):
        now = self.clock()
        config = approval(self.root,self.raw_config,commit=self.commit,now=now)
        facts = evidence(self.root)
        before = baseline(self.root)
        lease = Lease(LEASE_ID,'qa_engineer',IDENTITY,datetime.fromtimestamp(config['expires_at'],timezone.utc))
        state = self.states.load_state(before.factory_id,before.task_id)
        if state is None:
            raise StateError('QA task missing')
        return now, config, facts, before, lease, state

    def _persist(self, before, machine, after):
        token = 'qa-' + hashlib.sha256(canonical(machine.last_audit_event)).hexdigest()[:32]
        self.states.persist_transition(before,after,caller_identity=CONTROLLER_IDENTITY,
            event_id=token,audit_event=machine.last_audit_event)

    @staticmethod
    def _leased(before, lease, state):
        return replace(before,version=13,updated_at=state.updated_at,
                       leases=before.leases+(lease,))

    def issue_lease(self):
        now, config, _, before, lease, state = self._checked()
        if (state==self._leased(before,lease,state) and
                config['not_before'] <= state.updated_at.timestamp() <= now.timestamp()):
            return {'status':'LEASE_ALREADY_ISSUED','state':'QA','version':13,'lease_id':LEASE_ID}
        if state!=before:
            raise StateError('QA baseline drift; no lease or history reset permitted')
        machine = FactoryStateMachine(state)
        after = machine.issue_lease(CONTROLLER_IDENTITY,lease,expected_version=12,now=now)
        self._persist(state,machine,after)
        return {'status':'LEASE_ISSUED','state':'QA','version':13,'lease_id':LEASE_ID}

    def complete(self, result):
        now, config, facts, before, lease, state = self._checked()
        if not isinstance(result,dict) or set(result)!={'payload','signature_base64'}:
            raise StateError('QA gate result fields differ')
        payload = result['payload']
        if (not isinstance(payload,dict) or type(payload.get('issued_at')) is not int or
                canonical(payload)!=canonical(payload_for(facts,config,issued_at=payload['issued_at'])) or
                not config['not_before']<=payload['issued_at']):
            raise StateError('QA gate payload differs from approved evidence and lease')
        keys = load_trusted_signers(self.root/REGISTRY,now=now)
        try:
            raw_signature = base64.b64decode(result['signature_base64'],validate=True)
        except (ValueError,TypeError):
            raise StateError('QA gate signature encoding invalid') from None
        signed_digest = SignedScopeStore('unused',None,keys)._verify(payload,raw_signature,IDENTITY,now)
        evidence_id = 'qa-gate-' + signed_digest.removeprefix('sha256:')
        imported = self._leased(before,lease,state)
        completed = replace(imported,state='SECURITY_REVIEW',version=14,
            leases=tuple(replace(x,revoked=True) for x in imported.leases),
            consumed_evidence_ids=before.consumed_evidence_ids|{evidence_id})
        if state==completed and payload['issued_at']<=state.updated_at.timestamp()<=now.timestamp():
            return {'status':'ALREADY_ADVANCED','state':'SECURITY_REVIEW','version':14}
        if (state!=imported or not config['not_before']<=state.updated_at.timestamp()<=now.timestamp() or
                payload['issued_at']<state.updated_at.timestamp()):
            raise StateError('QA lease missing or task drift; no transition permitted')
        item = Evidence(evidence_id,'qa_engineer',IDENTITY,before.task_id,LEASE_ID,
            facts['candidate_commit'],signed_digest,datetime.fromtimestamp(payload['issued_at'],timezone.utc),True)
        machine = FactoryStateMachine(state)
        after = machine.transition(CONTROLLER_IDENTITY,'SECURITY_REVIEW',expected_version=13,evidence=(item,),now=now)
        self._persist(state,machine,after)
        return {'status':'ADVANCED','state':'SECURITY_REVIEW','version':14,'evidence_id':evidence_id,
                'model_calls':0,'schedule_enabled':False,'release_dispatched':False}
