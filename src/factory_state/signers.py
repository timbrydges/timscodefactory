"""Load reviewed public-key enrollment; never generate or accept job-supplied keys."""
import base64
import hashlib
import json
from pathlib import Path

from .model import COMMIT_SHA, OWNER_IDENTITY, ROLE_IDENTITIES, StateError


def public_key_der(pem: bytes) -> bytes:
    try:
        lines = pem.decode('ascii').strip().splitlines()
        if lines[0] != '-----BEGIN PUBLIC KEY-----' or lines[-1] != '-----END PUBLIC KEY-----':
            raise ValueError('public PEM required')
        der = base64.b64decode(''.join(lines[1:-1]), validate=True)
        # Exact SubjectPublicKeyInfo encoding for Ed25519, with no parameters.
        if len(der) != 44 or der[:12] != bytes.fromhex('302a300506032b6570032100'):
            raise ValueError('Ed25519 public key required')
        return der
    except (ValueError, IndexError, UnicodeError, AttributeError) as error:
        raise StateError('invalid Ed25519 public key enrollment') from error


def load_trusted_signers(path: Path, *, now) -> dict[str, bytes]:
    """Path must come from trusted controller deployment, not task input.

    Enrollment commits record human-reviewed identity ownership. A valid key or
    commit-shaped string alone is not evidence of that review.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise StateError('signer time must be timezone-aware')
    document = json.loads(path.read_bytes())
    if (set(document) != {'schema_version', 'enabled', 'signers'} or
            document['schema_version'] != '1.0' or document['enabled'] is not True or
            not isinstance(document['signers'], list) or not document['signers']):
        raise StateError('trusted signing identities are not enrolled and enabled')
    keys, fingerprints = {}, set()
    for entry in document['signers']:
        if set(entry) != {'identity', 'public_key_pem', 'fingerprint', 'enrollment_commit',
                          'not_before', 'expires_at', 'revoked'}:
            raise StateError('invalid signer enrollment fields')
        identity = entry['identity']
        if identity not in {OWNER_IDENTITY, *ROLE_IDENTITIES.values()} or identity in keys:
            raise StateError('invalid or duplicate signing identity')
        if not isinstance(entry['enrollment_commit'], str) or not COMMIT_SHA.fullmatch(entry['enrollment_commit']):
            raise StateError('signer needs an exact reviewed enrollment commit')
        if (type(entry['not_before']) is not int or type(entry['expires_at']) is not int or
                type(entry['revoked']) is not bool):
            raise StateError('invalid signer activation window')
        pem = entry['public_key_pem'].encode('ascii')
        fingerprint = 'sha256:' + hashlib.sha256(public_key_der(pem)).hexdigest()
        if fingerprint != entry['fingerprint'] or fingerprint in fingerprints:
            raise StateError('signer fingerprint mismatch or shared signing key')
        fingerprints.add(fingerprint)
        # Keep duplicate identity detection independent of active status.
        keys[identity] = None
        if not entry['revoked'] and entry['not_before'] <= now.timestamp() < entry['expires_at']:
            keys[identity] = pem
    return {identity: pem for identity, pem in keys.items() if pem is not None}
