"""GitHub App JWT framing; key access belongs to a separately approved host."""
import base64
from dataclasses import dataclass, field
import json
import re

from factory_state.model import StateError


def _encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=')


@dataclass(frozen=True)
class AppCredential:
    value: str = field(repr=False)
    expires_at: int


def prepare_app_claims(client_id, now):
    if (type(client_id) is not str or not re.fullmatch(r'[A-Za-z0-9]{8,64}', client_id)
            or type(now) is not int or now < 60):
        raise StateError('exact app client ID and integer UTC timestamp required')
    return {'iat': now-60, 'exp': now+300, 'iss': client_id}


def issue_app_credential(client_id, *, clock, sign_rs256, enabled=False, owner_authorized=False):
    """Invoke one trusted RS256 signer, only with explicit authorization.

    No key path, subprocess or HTTP client is installed by this module.
    The caller must reserve its durable no-retry attempt before invoking it.
    """
    if enabled is not True or owner_authorized is not True:
        raise StateError('app signing requires explicit authorization')
    claims = prepare_app_claims(client_id, clock())
    encode_json = lambda value: _encode(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
    message = encode_json({'alg':'RS256','typ':'JWT'})+b'.'+encode_json(claims)
    try:
        signature = sign_rs256(message)
        if type(signature) is not bytes or len(signature) not in (256,384,512):
            raise ValueError()
        if clock() >= claims['exp']-60:
            raise ValueError()
    except Exception:
        raise StateError('app signing failed or expired; no retry') from None
    return AppCredential((message+b'.'+_encode(signature)).decode('ascii'), claims['exp'])
