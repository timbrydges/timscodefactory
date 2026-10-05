"""Disabled adapter composition; qualifications are trusted deployment inputs."""
import copy
import hashlib
import re
import threading
from datetime import datetime

from factory_state.model import StateError
from factory_state.scope import canonical
from .qa_recovery003_packets import digest
from .qa_recovery003_protocols import _packet, request_bytes, parse_response, MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS
from .qa_recovery003_transport import Pilot002Transport


def _hash(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()


def _cost(input_tokens, output_tokens, qualification):
    # Integer micro-USD rates per million tokens; round up, never under-reserve.
    numerator=(input_tokens*qualification['input_micro_usd_per_million']+
        output_tokens*qualification['output_micro_usd_per_million'])
    return (numerator+999999)//1000000


def _fresh(now, qualification):
    if (not isinstance(now,datetime) or now.tzinfo is None or now.utcoffset() is None or
            not qualification['issued_at']<=now.timestamp()<qualification['expires_at']):
        raise StateError('Pilot 002 adapter pricing expired or clock invalid')


class Pilot002Adapter:
    def __init__(self, root, *, role, source_commit, qualification, clock,
                 builder_response=None, candidate_commit=None, enabled=False):
        if role!='qa' or not isinstance(qualification,dict) or qualification.get('kind')!='pilot002_google_free_tier_qualification':raise StateError('Recovery 003 requires QA free-tier qualification')
        self._root=root
        self._context={'role':role,'builder_response':builder_response,'candidate_commit':candidate_commit}
        self._packet=_packet(root,role,builder_response,candidate_commit)
        self._request=request_bytes(root,**self._context)
        self._qualification=copy.deepcopy(qualification)
        self._clock=clock;self._enabled=enabled is True
        self._lock=threading.Lock();self._attempted=False;self._response_digest=None
        q=self._qualification;packet=self._packet
        bindings={'role':role,'model_id':packet['model_id'],'task_id':packet['task_id'],
            'source_commit':source_commit,'contract_digest':packet['contract_digest'],
            'packet_digest':packet['packet_digest'],'request_digest':_hash(self._request)}
        free=isinstance(q,dict) and q.get('kind')=='pilot002_google_free_tier_qualification'
        expected={'kind':'pilot002_google_free_tier_qualification' if free else 'pilot002_provider_rate_qualification',**bindings,'currency':'USD',
            'complete_request_bound_qualified':not free,'combined_output_bound_qualified':not free,
            'standard_text_only_no_cache_rates':True,'output_token_bound':MAX_OUTPUT_TOKENS}
        extra={'input_token_bound','input_micro_usd_per_million','output_micro_usd_per_million',
            'issued_at','expires_at','evidence_digest'}
        if free:extra.add('billing_observation')
        if (not isinstance(source_commit,str) or not re.fullmatch('[0-9a-f]{40}',source_commit) or
                not isinstance(q,dict) or set(q)!=set(expected)|extra or
                any(type(q[k]) is not type(v) or q[k]!=v for k,v in expected.items()) or
                type(q['input_token_bound']) is not int or not 0<q['input_token_bound']<=MAX_INPUT_TOKENS or
                any(type(q[k]) is not int or not 0<=q[k]<=1000000000
                    for k in ('input_micro_usd_per_million','output_micro_usd_per_million')) or
                type(q['issued_at']) is not int or type(q['expires_at']) is not int or
                not q['issued_at']<q['expires_at']<=q['issued_at']+86400 or
                not isinstance(q['evidence_digest'],str) or not re.fullmatch('sha256:[0-9a-f]{64}',q['evidence_digest'])):
            raise StateError('Pilot 002 rate qualification is missing, changed or unqualified')
        if free:
            observation=q['billing_observation']
            expected_billing={'google_project':'gen-lang-client-0247455615','billing_account_linked':False,
                'credential_project_verified':True,'data_scope':'public-synthetic-fixtures-only',
                'free_tier_data_use_accepted':True}
            if (role!='qa' or q['input_micro_usd_per_million']!=0 or q['output_micro_usd_per_million']!=0 or
                    not isinstance(observation,dict) or set(observation)!=set(expected_billing)|{'observed_at','evidence_digest'} or
                    any(type(observation[k]) is not type(v) or observation[k]!=v for k,v in expected_billing.items()) or
                    type(observation['observed_at']) is not int or
                    not observation['observed_at']<=q['issued_at']<q['expires_at']<=observation['observed_at']+300 or
                    not isinstance(observation['evidence_digest'],str) or
                    not re.fullmatch('sha256:[0-9a-f]{64}',observation['evidence_digest'])):
                raise StateError('Pilot 002 Google free-tier billing or data-use observation invalid')
        maximum=_cost(q['input_token_bound'],q['output_token_bound'],q)
        if not (maximum==0 if free else 0<maximum<=250000):raise StateError('Pilot 002 qualified cost exceeds cap or is zero')
        _fresh(clock(),q)
        self._pricing={'kind':'pilot002_google_free_tier_cost_bound' if free else 'pilot002_qualified_request_cost_bound',**bindings,'currency':'USD',
            'complete_request_bound_qualified':not free,'maximum_cost_micro_usd':maximum,
            'issued_at':q['issued_at'],'expires_at':q['expires_at'],'evidence_digest':digest(q)}
        self._transport=Pilot002Transport(root,**self._context,enabled=enabled)

    @property
    def pricing(self):return copy.deepcopy(self._pricing)

    def build_request(self, packet):
        if canonical(packet)!=canonical(self._packet):raise StateError('Pilot 002 adapter packet differs')
        return self._request

    def send_once(self, *, request_bytes, credential, expected_request_digest):
        if not self._enabled:raise StateError('Pilot 002 adapter disabled')
        if request_bytes!=self._request or expected_request_digest!=_hash(self._request):
            raise StateError('Pilot 002 adapter request differs')
        with self._lock:
            if self._attempted:raise StateError('Pilot 002 adapter already attempted; reconcile without retry')
            self._attempted=True
        _fresh(self._clock(),self._qualification)
        raw=self._transport.send_once(request_bytes=request_bytes,credential=credential,
            expected_request_digest=expected_request_digest)
        with self._lock:self._response_digest=_hash(raw)
        return raw

    def parse_response(self, raw, packet):
        self.build_request(packet)
        with self._lock:observed=self._response_digest
        if not isinstance(raw,bytes) or observed is None or _hash(raw)!=observed:
            raise StateError('Pilot 002 response was not returned by this transport attempt')
        result=parse_response(raw,self._root,**self._context)
        usage=result['usage'];q=self._qualification
        if usage['input_tokens']>q['input_token_bound']:
            raise StateError('Pilot 002 observed input exceeds qualified bound')
        cost=_cost(usage['input_tokens'],usage['output_tokens_including_reasoning'],q)
        if cost>self._pricing['maximum_cost_micro_usd']:
            raise StateError('Pilot 002 observed cost exceeds qualified bound')
        return {'model_id':self._packet['model_id'],'output_bytes':result['output_bytes'],'actual_micro_usd':cost}
