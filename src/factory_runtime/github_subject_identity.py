"""GitHub job identity source. Disabled by default; never reads candidate input."""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .identity_diagnostics import IdentityFailure, identity_failure
from .credential_issuance import IssuanceAuthorization
from .openai_provider import OpenAIProviderDisabledError
from .provider_credentials import ProviderCredentialLeaseError
from .provider_http_transport import DirectOpenAITransport
from .workload_identity_response import _unique
from .workload_identity_transport import TrustedSubjectIdentity, _validate_subject_token


@dataclass(frozen=True)
class GitHubIdentityPolicy:
    request_origin: str
    audience: str
    repository: str
    repository_id: str
    workflow_ref: str
    ref: str = 'refs/heads/main'

    def claims(self):
        if (not re.fullmatch(r'https://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.actions\.githubusercontent\.com',
                            self.request_origin)
                or self.audience != 'https://api.openai.com/v1'
                or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.repository)
                or not re.fullmatch(r'[1-9][0-9]{0,19}', self.repository_id)
                or self.ref != 'refs/heads/main'
                or not re.fullmatch(re.escape(self.repository) +
                    r'/\.github/workflows/[A-Za-z0-9_-]+\.ya?ml@refs/heads/main', self.workflow_ref)):
            raise ValueError('exact trusted GitHub identity policy required')
        return dict(iss='https://token.actions.githubusercontent.com', aud=self.audience,
                    repository=self.repository, repository_id=self.repository_id,
                    ref=self.ref, workflow_ref=self.workflow_ref)


def request_target(url, origin, audience):
    """Pin origin before transmitting the job bearer; never follow redirects."""
    if (type(url) is not str or not 1 <= len(url) <= 8192
            or any(ord(c) < 33 or ord(c) > 126 for c in url)
            or type(origin) is not str
            or not re.fullmatch(r'https://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.actions\.githubusercontent\.com', origin)
            or audience != 'https://api.openai.com/v1'):
        raise ValueError('invalid GitHub request destination')
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or 'https://' + parsed.netloc != origin
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or not parsed.path.startswith('/') or '\\' in url):
        raise ValueError('GitHub request origin mismatch')
    query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    if any(key.lower() == 'audience' for key, value in query):
        raise ValueError('unexpected preconfigured audience')
    query.append(('audience', audience))
    return parsed.hostname, urlunsplit(('', '', parsed.path, urlencode(query), ''))


class DirectGitHubIdentityTransport(DirectOpenAITransport):
    def __init__(self, *, enabled=False):
        super().__init__(enabled=enabled, max_request_bytes=65536, max_response_bytes=65536)

    async def request(self, *, url, bearer, policy):
        if not self.enabled:
            raise OpenAIProviderDisabledError('GitHub identity transport disabled')
        policy.claims()
        request_target(url, policy.request_origin, policy.audience)
        if (type(bearer) is not str or not 16 <= len(bearer) <= 32768
                or any(ord(c) < 33 or ord(c) > 126 for c in bearer)):
            raise ValueError('invalid GitHub job bearer')
        body = json.dumps(dict(url=url, origin=policy.request_origin,
                               audience=policy.audience)).encode()
        return await self._run_request(
            {'Authorization': 'Bearer ' + bearer, 'Accept': 'application/json'},
            body, 10, kind='github-subject')


def _decode_claims(token):
    _validate_subject_token(token)
    payload = token.split('.')[1]
    raw = base64.b64decode(payload + '=' * (-len(payload) % 4), altchars=b'-_', validate=True)
    if base64.urlsafe_b64encode(raw).rstrip(b'=').decode() != payload:
        raise ValueError('noncanonical JWT payload')
    claims = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
    if type(claims) is not dict:
        raise ValueError('invalid JWT claims')
    return claims


class GitHubSubjectSource:
    """Only trusted host code supplies policy and environment reader.

    Claims are checked on an authenticated HTTPS response; this does not verify
    the JWT signature. OpenAI must still verify the signature and exact mapping.
    """
    def __init__(self, *, authorization, policy, environment, clock, enabled=False,
                 transport=None):
        if (type(authorization) is not IssuanceAuthorization
                or type(policy) is not GitHubIdentityPolicy or not callable(environment)
                or not callable(clock) or type(enabled) is not bool):
            raise ValueError('trusted GitHub source configuration required')
        self._authorization = authorization.canonical()
        self._claims = policy.claims()
        self._policy, self._environment, self._clock = policy, environment, clock
        self._enabled = enabled
        self._transport = transport if transport is not None else DirectGitHubIdentityTransport(enabled=enabled)

    async def __call__(self, authorization):
        if not self._enabled:
            raise ProviderCredentialLeaseError('GitHub identity source disabled')
        stage = 'github_authorization'
        try:
            if (type(authorization) is not IssuanceAuthorization
                    or authorization.canonical() != self._authorization):
                raise ValueError()
            now = self._clock()
            if (not isinstance(now, datetime) or now.tzinfo is None
                    or now.utcoffset() is None
                    or not authorization.starts_at <= now < authorization.expires_at):
                raise ValueError()
            async with asyncio.timeout(10):
                stage = 'github_environment'
                # These are job-owned values, not packet fields or candidate env.
                url = self._environment('ACTIONS_ID_TOKEN_REQUEST_URL')
                request_target(url, self._policy.request_origin, self._policy.audience)
                bearer = self._environment('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
                stage = 'github_transport'
                response = await self._transport.request(url=url, bearer=bearer, policy=self._policy)
                if response.status_code != 200:
                    raise IdentityFailure('github_http', 'http_error')
                stage = 'github_payload'
                if type(response.body) is not bytes or not 1 <= len(response.body) <= 65536:
                    raise ValueError()
                data = json.loads(response.body.decode('utf-8'), object_pairs_hook=_unique)
                if type(data) is not dict or 'value' not in data:
                    raise ValueError()
                token = data['value']
                claims = _decode_claims(token)
                stage = 'github_claims'
                if any(claims.get(key) != value for key, value in self._claims.items()):
                    raise ValueError()
                stage = 'github_lifetime'
                issued, expires = claims.get('iat'), claims.get('exp')
                received = self._clock()
                if (not isinstance(received, datetime) or received.tzinfo is None
                        or received.utcoffset() is None or received < now
                        or type(issued) is not int or type(expires) is not int
                        or not now.timestamp() - 1 <= issued <= received.timestamp()
                        or not 210 < expires - received.timestamp() <= 900
                        or not 0 < expires - issued <= 900):
                    raise ValueError()
                return TrustedSubjectIdentity(token, datetime.fromtimestamp(expires, timezone.utc))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise identity_failure(error, stage) from None
