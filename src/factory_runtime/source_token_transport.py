"""Disabled-by-default GitHub installation HTTP adapter; never loads a key."""
import http.client
import json

from factory_state.model import StateError


def _credential(value):
    if (type(value) is not str or not 16 <= len(value) <= 32768
            or any(not 33 <= ord(c) <= 126 for c in value)):
        raise StateError('invalid source credential')
    return value


class SourceTokenTransport:
    """One request per method; redirects and uncertain results fail closed.

    The host must separately authorize signing and supply a JWT. This adapter
    does not sign, read keys, retry, or discover installations/repositories.
    """
    def __init__(self, installation_id, repository_id, *, enabled=False,
                 connection=http.client.HTTPSConnection):
        if any(type(v) is not int or v <= 0 for v in (installation_id, repository_id)):
            raise StateError('exact positive installation and repository IDs required')
        self.installation_id = installation_id
        self.repository_id = repository_id
        self.enabled = enabled
        self.connection = connection

    def _request(self, method, path, credential, body, expected):
        if self.enabled is not True:
            raise StateError('source token transport disabled')
        credential = _credential(credential)
        conn = None
        try:
            conn = self.connection('api.github.com', timeout=20)
            conn.request(method, path, body=body, headers={
                'Authorization': 'Bearer '+credential,
                'Accept': 'application/vnd.github+json',
                'Content-Type': 'application/json',
                'User-Agent': 'factory-private-source',
            })
            response = conn.getresponse()
            if response.status != expected:
                raise StateError('unexpected status')
            raw = response.read(65537)
            if len(raw) > 65536:
                raise StateError('response too large')
            return raw
        except Exception:
            raise StateError('source token request uncertain; no retry') from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    raise StateError('source token connection cleanup uncertain; no retry') from None

    def issue(self, jwt, *, repository_ids, permissions):
        if (repository_ids != [self.repository_id]
                or any(type(v) is not int for v in repository_ids)
                or permissions != {'contents': 'read', 'metadata': 'read'}):
            raise StateError('source token request scope rejected')
        raw = self._request('POST',
            f'/app/installations/{self.installation_id}/access_tokens', jwt,
            json.dumps({'repository_ids': repository_ids, 'permissions': permissions}).encode(), 201)
        try:
            result = json.loads(raw)
            if type(result) is not dict:
                raise ValueError()
            return result
        except (ValueError, UnicodeError):
            raise StateError('source token response invalid; reconcile without retry') from None

    def revoke(self, token):
        self._request('DELETE', '/installation/token', token, None, 204)
        return True
