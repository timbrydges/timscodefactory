"""Deployment-owned review semantics; signature and state authority stay external."""
from dataclasses import dataclass
from datetime import datetime,timezone,timedelta
import hashlib
import json
import re
from typing import Callable
from factory_state.model import StateError
from factory_state.scope import canonical

STAGES={'independent_inspector':'INSPECTION','qa_engineer':'QA'}


@dataclass(frozen=True)
class ReviewBinding:
    factory_id: str
    task_id: str
    role_id: str
    source_commit: str
    contract_digest: str
    input_digest: str
    candidate_commit: str
    candidate_digest: str
    test_evidence_digest: str
    allowed_paths: tuple[str,...]

    def validate(self):
        if self.role_id not in STAGES:raise StateError('Unsupported review gate')
        for value in (self.factory_id,self.task_id):
            if type(value)is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}',value):
                raise StateError('Invalid fixed review identity')
        for value in (self.source_commit,self.candidate_commit):
            if type(value)is not str or not re.fullmatch('[0-9a-f]{40}',value):
                raise StateError('Exact review commit required')
        for value in (self.contract_digest,self.input_digest,self.candidate_digest,self.test_evidence_digest):
            if type(value)is not str or not re.fullmatch('sha256:[0-9a-f]{64}',value):
                raise StateError('Exact review digest required')
        if (type(self.allowed_paths)is not tuple or not 1<=len(self.allowed_paths)<=32 or
                any(
                    type(p)is not str or not p or len(p)>240 or p.startswith('/') or '\\' in p or
                    ':' in p or any(part in ('','.','..') for part in p.split('/')) for p in self.allowed_paths) or
                len(set(self.allowed_paths))!=len(self.allowed_paths)):
            raise StateError('Fixed relative review paths required')


class BoundReviewValidator:
    """Accept exact verdicts only after independent deployment-owned test checks.

    Configure explicitly in SignedResultProgressor. Never load this binding or
    the verifier from provider output, task input, or the historical handoff audit.
    """
    def __init__(self,binding:ReviewBinding,verify_tests:Callable):
        if type(binding)is not ReviewBinding or not callable(verify_tests):
            raise StateError('Deployment-owned review binding and test verifier required')
        binding.validate()
        self.binding=binding;self.verify_tests=verify_tests

    def __call__(self,state,request,output):
        b=self.binding
        if ((state.factory_id,state.task_id,state.state)!=(b.factory_id,b.task_id,STAGES[b.role_id]) or
                (request.source_commit,request.contract_digest,request.input_digest)!=(
                    b.source_commit,b.contract_digest,b.input_digest)):
            return False
        leases=[l for l in state.leases if l.lease_id==request.lease_id]
        if len(leases)!=1 or leases[0].role_id!=b.role_id:return False
        if type(output)is not bytes or not 0<len(output)<=32768:return False
        def unique(pairs):
            result={}
            for key,value in pairs:
                if key in result:raise ValueError('Duplicate review field')
                result[key]=value
            return result
        def invalid_constant(_):raise ValueError('Non-finite review value')
        try:value=json.loads(output.decode('utf-8'),object_pairs_hook=unique,parse_constant=invalid_constant)
        except (ValueError,UnicodeError,RecursionError):return False
        expected={'kind':'factory_review_v1','factory_id':b.factory_id,'task_id':b.task_id,
            'role_id':b.role_id,'source_commit':b.source_commit,'contract_digest':b.contract_digest,
            'input_digest':b.input_digest,'candidate_commit':b.candidate_commit,
            'candidate_digest':b.candidate_digest,'test_evidence_digest':b.test_evidence_digest}
        if (type(value)is not dict or set(value)!=set(expected)|{'verdict','rationale','findings'} or
                any(value[k]!=v for k,v in expected.items()) or value['verdict']!='ACCEPTED' or
                type(value['rationale'])is not str or not 1<=len(value['rationale'].strip())<=2000 or
                type(value['findings'])is not list or len(value['findings'])>16):return False
        for finding in value['findings']:
            if (type(finding)is not dict or set(finding)!={'severity','path','detail'} or
                    finding['severity'] not in ('info','low','medium') or finding['path'] not in b.allowed_paths or
                    type(finding['detail'])is not str or not 1<=len(finding['detail'].strip())<=1000):return False
        # Model statements that tests passed are deliberately absent from the schema.
        return self.verify_tests(b.candidate_commit,b.candidate_digest,b.test_evidence_digest) is True


class PinnedPythonTestEvidence:
    """Verify an operator-supplied test artifact; do not execute provider code.

    The deployment must authenticate the artifact digest and candidate binding.
    Hashes validate retained bytes, not whether an untrusted author ran tests.
    """
    def __init__(self,binding,proof_bytes,candidate_files,*,test_count,clock=None):
        binding.validate()
        if (type(proof_bytes)is not bytes or len(proof_bytes)>65536 or
                type(test_count)is not int or not 1<=test_count<=10000 or
                type(candidate_files)is not dict or set(candidate_files)!=set(binding.allowed_paths) or
                any(type(v)is not str or len(v.encode('utf-8'))>32768 for v in candidate_files.values())):
            raise StateError('Bounded independent test artifact required')
        if ('sha256:'+hashlib.sha256(proof_bytes).hexdigest()!=binding.test_evidence_digest or
                'sha256:'+hashlib.sha256(canonical(candidate_files)).hexdigest()!=binding.candidate_digest):
            raise StateError('Independent artifact or candidate digest differs')
        self.binding=binding;self.raw=proof_bytes;self.test_count=test_count
        self.files={p:hashlib.sha256(v.encode('utf-8')).hexdigest() for p,v in candidate_files.items()}
        self.clock=clock or (lambda:datetime.now(timezone.utc))

    def __call__(self,commit,candidate_digest,evidence_digest):
        b=self.binding
        if (commit,candidate_digest,evidence_digest)!=(b.candidate_commit,b.candidate_digest,b.test_evidence_digest):return False
        try:
            proof=json.loads(self.raw.decode('utf-8'))
            observed=datetime.fromisoformat(proof['observed_at']);now=self.clock()
            return (type(proof)is dict and observed.tzinfo is not None and now.tzinfo is not None and
                timedelta(0)<=now-observed<=timedelta(hours=1) and proof['source_commit']==b.source_commit and
                proof['candidate_commit']==b.candidate_commit and proof['files']==self.files and
                proof['runtime']=='python3.12-linux' and re.fullmatch(r'3\.12\.[0-9]+',proof['python_version']) is not None and
                type(proof['exit_code'])is int and proof['exit_code']==0 and
                proof['credentials_in_environment'] is False and proof['stdout']=='' and
                type(proof['stderr'])is str and 'skipped' not in proof['stderr'].lower() and
                re.search(r'Ran '+str(self.test_count)+r' tests in [0-9.]+s\n\nOK\n$',proof['stderr']) is not None)
        except (ValueError,TypeError,KeyError,AttributeError,RecursionError):return False
