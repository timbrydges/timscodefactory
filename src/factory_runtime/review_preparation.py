"""Offline review material; neither provider authorization nor gate evidence."""
import base64
import hashlib
import json

from factory_state.model import StateError
from factory_state.scope import canonical
from .implementation_inspector import CANDIDATE, CONTRACT, FILES, PACKET, PACKET_SHA
from .inspection_completion import REVIEW, REVIEW_SHA
from .review_role_probe import IDENTITIES

BOOTSTRAP = 'factory/evidence/qa-security-bootstrap-live-proof-2026-10-02.json'
BOOTSTRAP_SHA = 'd3ccf8cd4fb845dad51373f921753a6b381628ccfb894043f61456a6153b03e8'
STATUS = 'PREPARED_NOT_AUTHORIZED'
BINDING = ('role', 'candidate_commit', 'contract_digest', 'packet_digest')
CRITERIA = {
    'qa': ['Canonical UTF-8 JSON and exact byte digest',
           'Repeatability, 4096-byte boundary and invalid input rejection',
           'Missing/unreadable input errors and test coverage gaps'],
    'security': ['Untrusted path and input handling, resource exhaustion and error disclosure',
                 'Imports, dependencies, dynamic execution and network access',
                 'Distinguish the CLI contract from an unproven filesystem sandbox'],
}


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def pinned(root, path, sha):
    raw = (root / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise StateError('review preparation source evidence changed')
    return json.loads(raw)


def prepare(root, *, role):
    if not isinstance(role, str) or role not in IDENTITIES:
        raise StateError('unknown review role')
    candidate = pinned(root, PACKET, PACKET_SHA)
    inspection = pinned(root, REVIEW, REVIEW_SHA)
    bootstrap = pinned(root, BOOTSTRAP, BOOTSTRAP_SHA)
    files = candidate['untrusted_candidate_files']
    if (candidate['candidate_commit'] != CANDIDATE or set(files) != set(FILES) or
            any(hashlib.sha256(files[k].encode()).hexdigest() != v for k, v in FILES.items()) or
            'sha256:' + hashlib.sha256(base64.b64decode(candidate['contract_base64'], validate=True)).hexdigest() != CONTRACT or
            inspection['payload']['candidate_commit'] != CANDIDATE):
        raise StateError('review candidate binding changed')
    identity = next(item for item in bootstrap['identities'] if item['role'] == role)
    material = {
        'schema_version': '1.0', 'status': STATUS, 'role': role,
        'reviewer_identity': IDENTITIES[role], 'candidate_commit': CANDIDATE,
        'contract_digest': CONTRACT, 'files_sha256': FILES,
        'candidate_repository': candidate['candidate_repository'],
        'candidate_packet_digest': 'sha256:' + PACKET_SHA,
        'prior_inspection_digest': 'sha256:' + REVIEW_SHA,
        'bootstrap_proof_digest': 'sha256:' + BOOTSTRAP_SHA,
        'verified_identity_fingerprint': identity['fingerprint'],
        'identity_is_operationally_enrolled': False,
        'required_state': 'QA' if role == 'qa' else 'SECURITY_REVIEW',
        'live_state_verified': False,
        'prerequisite': 'Fresh QA lease' if role == 'qa' else 'Accepted signed QA gate and fresh security lease',
        'criteria': CRITERIA[role],
        'untrusted_material': {'files': files, 'contract_base64': candidate['contract_base64']},
        'model_calls_authorized': 0, 'retries_authorized': 0,
        'state_writes_authorized': 0, 'production_release_authorized': False,
    }
    return {**material, 'packet_digest': digest(material)}


def validate_packet(packet, *, root):
    if (not isinstance(packet, dict) or not isinstance(packet.get('role'), str) or
            packet['role'] not in IDENTITIES):
        raise StateError('invalid review packet')
    # Reconstruct against pinned repository evidence; a recomputed caller hash
    # cannot swap candidates, remove prerequisites or invent authorization.
    expected = prepare(root, role=packet['role'])
    if canonical(packet) != canonical(expected):
        raise StateError('review packet differs from pinned preparation')


def parse_assessment(raw, packet, *, root):
    """Shape-check untrusted model bytes without signing or publishing them."""
    validate_packet(packet, root=root)
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 16384:
        raise StateError('review assessment size invalid')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise StateError('duplicate review assessment field')
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise StateError('malformed review assessment') from error
    if (not isinstance(value, dict) or
            set(value) != set(BINDING) | {'verdict', 'rationale', 'findings'} or
            any(value[k] != packet[k] for k in BINDING) or
            value['verdict'] not in ('ACCEPTED', 'REJECTED') or
            not isinstance(value['rationale'], str) or
            not 1 <= len(value['rationale'].strip()) <= 2000 or
            not isinstance(value['findings'], list) or len(value['findings']) > 16):
        raise StateError('review assessment fields or binding invalid')
    for finding in value['findings']:
        if (not isinstance(finding, dict) or set(finding) != {'severity', 'path', 'detail'} or
                finding['severity'] not in ('info', 'low', 'medium', 'high', 'critical') or
                not isinstance(finding['path'], str) or finding['path'] not in FILES or
                not isinstance(finding['detail'], str) or not 1 <= len(finding['detail'].strip()) <= 1000):
            raise StateError('review finding invalid')
    if value['verdict'] == 'ACCEPTED' and any(f['severity'] in ('high', 'critical') for f in value['findings']):
        raise StateError('accepted review cannot contain high or critical findings')
    return {**value, 'status': 'UNAUTHENTICATED_ASSESSMENT',
            'gate_authority': False, 'production_release_authorized': False}
