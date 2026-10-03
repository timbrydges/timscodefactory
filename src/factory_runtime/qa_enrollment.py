"""Prepare an offline QA trust proposal; never enroll, sign, or deploy."""
import base64
import copy
import hashlib
import json
import re
from datetime import datetime, timezone

from factory_state.model import StateError
from factory_state.scope import SignedScopeStore, canonical
from factory_state.signers import public_key_der, validate_trusted_signers
from .review_preparation import BOOTSTRAP, BOOTSTRAP_SHA, pinned, prepare

IDENTITY = 'qa_engineer_service'
KEY = 'arn:aws:kms:ca-central-1:666730517561:key/71cb555e-37e8-44ec-b638-86072e3231c6'
ROLE = 'arn:aws:iam::666730517561:role/tims-factory-review-qa'
REGISTRY = 'factory/profiles/scope-signers.json'
BUNDLE = 'factory/evidence/google-qa-combined-bundle-2026-10-03.json'
BUNDLE_SHA = '033a9fe40962c7c5942a81d4da9ca38c3f012d7d919285ffb5c9aaabd25a0384'
PROOF = 'factory/evidence/google-qa-live-proof-2026-10-03.json'
PROOF_SHA = 'c6e3431db1504cd3aed7aab33ff11d57dc82b3205a2eb8fcdd48c2b422799efb'


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def propose(root, observation, *, now, enrollment_commit):
    """Observation is an operator read, not a signature or permission grant."""
    if (now.tzinfo is None or now.utcoffset() is None or
            not isinstance(enrollment_commit, str) or not re.fullmatch('[0-9a-f]{40}', enrollment_commit)):
        raise StateError('QA enrollment proposal time or reviewed source invalid')
    packet = prepare(root, role='qa')
    bootstrap = pinned(root, BOOTSTRAP, BOOTSTRAP_SHA)
    bundle = pinned(root, BUNDLE, BUNDLE_SHA)
    proof = pinned(root, PROOF, PROOF_SHA)
    identity = next(entry for entry in bootstrap['identities'] if entry['role']=='qa')
    pem = identity['public_key_pem'].encode()
    fingerprint = 'sha256:' + hashlib.sha256(public_key_der(pem)).hexdigest()
    if identity['identity'] != IDENTITY or identity['key_arn'] != KEY or identity['fingerprint'] != fingerprint:
        raise StateError('QA bootstrap identity differs')
    challenge = identity['result']
    SignedScopeStore('unused', None, {IDENTITY:pem})._verify(challenge['payload'],
        base64.b64decode(challenge['signature_base64'], validate=True), IDENTITY,
        datetime.fromtimestamp(challenge['payload']['issued_at'], timezone.utc))
    try:
        observed = datetime.fromisoformat(observation['observed_at'])
        if (observed.tzinfo is None or not 0 <= (now-observed).total_seconds() <= 3600 or
                observation['account'] != '666730517561' or observation['key_arn'] != KEY or
                observation['key_state'] != 'Enabled' or observation['key_usage'] != 'SIGN_VERIFY' or
                observation['key_spec'] != 'ECC_NIST_EDWARDS25519' or
                'ED25519_SHA_512' not in observation['algorithms'] or
                base64.b64decode(observation['public_key_der_base64'], validate=True) != public_key_der(pem) or
                observation['fingerprint'] != fingerprint or observation['role_arn'] != ROLE or
                observation['role_trust'] != {'Version':'2012-10-17','Statement':[{
                    'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]}):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise StateError('fresh QA key observation differs from verified bootstrap') from None
    if (bundle['review_status'] != 'READY_FOR_INDEPENDENT_PUBLICATION_REVIEW' or
            not bundle['local_cases_passed'] or bundle['gate_authority'] is not False or
            any(bundle[k] != packet[k] for k in ('candidate_commit','contract_digest','packet_digest')) or
            proof['combined_bundle_digest'] != digest(bundle) or
            proof['reconciliation']['status'] != 'COMPLETE_UNSIGNED_HOLD_RETAINED'):
        raise StateError('QA evidence not ready for enrollment proposal')
    raw = (root/REGISTRY).read_bytes()
    registry = json.loads(raw)
    validate_trusted_signers(registry, now=now)
    if any(entry['identity']==IDENTITY or entry['fingerprint']==fingerprint for entry in registry['signers']):
        raise StateError('QA key already enrolled or reused; no duplicate proposal')
    entry = {'identity':IDENTITY,'public_key_pem':pem.decode(),'fingerprint':fingerprint,
        'enrollment_commit':enrollment_commit,'not_before':int(now.timestamp()),
        'expires_at':int(now.timestamp())+86400,'revoked':False}
    proposed = copy.deepcopy(registry)
    proposed['signers'].append(entry)
    if IDENTITY not in validate_trusted_signers(proposed, now=now):
        raise StateError('proposed QA entry is not active in its bounded window')
    return {'status':'QA_ENROLLMENT_PROPOSED_NOT_AUTHORIZED','identity':IDENTITY,
        'key_arn':KEY,'role_arn':ROLE,'candidate_commit':packet['candidate_commit'],
        'current_registry_sha256':hashlib.sha256(raw).hexdigest(),
        'observation_digest':digest(observation),'bundle_digest':digest(bundle),
        'added_entry':entry,'proposed_registry':proposed,'maximum_trust_seconds':86400,
        'model_calls':0,'signing_calls':0,'state_writes':0,'iam_changes':0,'new_keys':0,
        'gate_authority':False,'production_release_authorized':False,
        'requires':['Explicit owner approval before applying trust',
            'Fresh key observation and unchanged registry before application',
            'Separate publisher provenance, fresh lease and controller verification']}
