"""Offline QA model override; historical Pilot 002 contract and builder stay immutable."""
import copy
from factory_state.model import StateError
from factory_state.scope import canonical
from . import pilot002_packets as original
from .pilot002_packets import digest,REVIEW_BINDINGS,FILES,_decode
from .qa_recovery003 import RecoveryAttemptStore,SCOPE_SHA256,CANDIDATE

MODEL='gemini-3.7-flash'


def review_packet(root,*,role,builder_response,candidate_commit):
    if role!='qa' or candidate_commit!=CANDIDATE:raise StateError('Recovery 003 requires exact QA candidate')
    RecoveryAttemptStore(None,root=root)
    packet=copy.deepcopy(original.review_packet(root,role=role,builder_response=builder_response,candidate_commit=candidate_commit))
    historical=packet['contract_digest']
    contract=packet['untrusted_contract']
    providers=[p for p in contract['providers'] if p['role']=='qa']
    if len(providers)!=1 or providers[0]['model_id']!='gemini-3.8-flash':raise StateError('Historical QA binding differs')
    providers[0]['model_id']=MODEL
    contract['recovery_override']={'original_contract_digest':historical,'scope_digest':'sha256:'+SCOPE_SHA256,'role':'qa','model_id':MODEL}
    packet.update(model_id=MODEL,contract_digest=digest(contract),original_contract_digest=historical,recovery_scope_digest='sha256:'+SCOPE_SHA256)
    del packet['packet_digest']
    return original._finish(packet)


def parse_review(raw, *, root, role, builder_response, candidate_commit):
    packet = review_packet(root, role=role, builder_response=builder_response, candidate_commit=candidate_commit)
    value = _decode(raw)
    if (set(value) != set(REVIEW_BINDINGS) | {'verdict', 'rationale', 'findings'} or
            any(value[k] != packet[k] for k in REVIEW_BINDINGS) or
            value['verdict'] not in ('ACCEPTED', 'REJECTED') or
            not isinstance(value['rationale'], str) or not 1 <= len(value['rationale'].strip()) <= 2000 or
            not isinstance(value['findings'], list) or len(value['findings']) > 16):
        raise StateError('Pilot 002 assessment fields or bindings differ')
    for f in value['findings']:
        if (not isinstance(f, dict) or set(f) != {'severity', 'path', 'detail'} or
                f['severity'] not in ('info','low','medium','high','critical') or
                not isinstance(f['path'], str) or f['path'] not in FILES or
                not isinstance(f['detail'], str) or not 1 <= len(f['detail'].strip()) <= 1000):
            raise StateError('Pilot 002 finding is malformed')
    if value['verdict'] == 'ACCEPTED' and any(f['severity'] in ('high','critical') for f in value['findings']):
        raise StateError('Pilot 002 high or critical findings cannot be accepted')
    return {**value, 'status':'UNAUTHENTICATED_ASSESSMENT', 'tests_executed':False,
        'gate_authority':False, 'production_release_authorized':False}
