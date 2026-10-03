"""Verify historical bounded Security execution; confer no gate authority."""
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from factory_runtime.review_preparation import prepare, pinned
from factory_runtime.security_validation import validate_execution
from factory_runtime.security_validation_attestation import IDENTITY, KEY
from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import load_trusted_signers

PROOF = 'factory/evidence/security-bounded-validation-live-proof-2026-10-03.json'
PROOF_SHA = 'bdde5f70dc045363558edf4b4024abf1568a76c0b0bb5d75cb1dc0551fa24c41'
REGISTRY = 'factory/evidence/security-validation-signers-2026-10-03.json'
REGISTRY_SHA = '6da51e17c4052b73f4649480aca52f8e9d3e7ced86c00a6b0b3764ca480cd25b'
SOURCE = '50e5473f9dcc9139901a6effa0cced7a459fec46'
PACKAGE_SHA = '508559681ece2a1f7d4db1ef84b1c0a5fb3da25c6d16d7945efd14d6bcd32cee'


def verify_document(proof, *, root):
    """Historical verification only, including for expired current enrollment."""
    try:
        result = proof['result']; payload = result['payload']; report = result['report']
        packet = prepare(root, role='security')
        if not validate_execution(report, packet, root=root):
            raise StateError('Bounded Security cases did not pass')
        issued = datetime.fromtimestamp(payload['issued_at'], timezone.utc)
        pinned(root, REGISTRY, REGISTRY_SHA)
        keys = load_trusted_signers(root/REGISTRY, now=issued)
        signed = SignedScopeStore('unused',None,keys)._verify(payload,
            base64.b64decode(result['signature_base64'],validate=True),IDENTITY,issued)
        expected = {'kind':'security_validation_attestation',
            'purpose':'bounded-validation-provenance-only','identity':IDENTITY,'key_arn':KEY,
            'executor_arn':'arn:aws:sts::666730517561:assumed-role/tims-factory-review-security/tims-factory-review-security',
            'source_commit':SOURCE,'nonce':payload['nonce'],
            'candidate_commit':packet['candidate_commit'],'contract_digest':packet['contract_digest'],
            'packet_digest':packet['packet_digest'],'report_digest':report['report_digest'],
            'registry_sha256':REGISTRY_SHA,'report_verified':True,'finding_count':3,
            'assessment_kind':'synthetic-only-validation-with-limitations',
            'scope':report['scope'],'case_count':5,'issued_at':payload['issued_at'],
            'expires_at':payload['expires_at'],'gate_authority':False,'production_release_authorized':False}
        if canonical(payload)!=canonical(expected) or signed!=proof['signed_payload_digest']:
            raise StateError('Security signed provenance differs')
        checks = {'status':'SECURITY_BOUNDED_VALIDATION_VERIFIED','source_commit':SOURCE,
            'package_sha256':PACKAGE_SHA,'active_version':'5',
            'disabled_version_arn':'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-review-security:4',
            'invocations':1,'signing_calls':1,'retries':0,'model_calls':0,'task_state_writes':0,
            'task_state':'SECURITY_REVIEW','task_version':14,'task_unchanged':True,
            'other_functions_unchanged':True,'permissions_unchanged':True,
            'prior_versions_and_aliases_preserved':True,'gate_authority':False,
            'production_release_authorized':False}
        if canonical({k:proof[k] for k in checks})!=canonical(checks):
            raise StateError('Security execution or preservation proof differs')
        counters = {'signing_calls':1,'model_calls':0,'task_state_writes':0,
                    'gate_authority':False,'production_release_authorized':False}
        if canonical({k:result[k] for k in counters})!=canonical(counters):
            raise StateError('Security result grants unexpected authority')
        shutdown = {'concurrency':0,'attestation_enabled':False,'validation_enabled':False,
                    'operational_execution_enabled':False}
        if canonical({k:proof['shutdown'][k] for k in shutdown})!=canonical(shutdown):
            raise StateError('Security shutdown not verified')
    except (KeyError, TypeError, ValueError, AttributeError):
        raise StateError('Security validation proof malformed') from None
    return {'status':'HISTORICAL_SYNTHETIC_VALIDATION_VERIFIED',
        'candidate_commit':packet['candidate_commit'],'scope':report['scope'],
        'signed_payload_digest':signed,'case_count':5,'open_findings':3,
        'owner_scope_acceptance_required':True,'gate_authority':False,
        'production_release_authorized':False}


def verify(root=ROOT):
    return verify_document(pinned(root,PROOF,PROOF_SHA),root=root)


if __name__=='__main__': print(json.dumps(verify(),indent=2))
