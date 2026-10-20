"""Operator-only, hash-pinned bootstrap. Configuration contains no credentials."""
from dataclasses import dataclass
from contextlib import closing
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from .credential_issuance import CredentialIssuanceLedger, IssuanceAuthorization
from .github_subject_identity import GitHubIdentityPolicy, GitHubSubjectSource
from .provider_broker_service import ResolvedProviderTarget
from .workload_identity_response import _unique
from .workload_identity_transport import JWTTokenExchange


@dataclass(frozen=True)
class GitHubHostConfiguration:
    authorization: IssuanceAuthorization
    policy: GitHubIdentityPolicy
    ledger_path: Path


def read_configuration(path, expected_digest, *, owner_authorized=False):
    if owner_authorized is not True:
        raise ValueError('explicit operator authorization required')
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError('regular operator configuration required')
    with path.open('rb') as handle:
        raw = handle.read(32769)
    actual = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if not 1 <= len(raw) <= 32768 or expected_digest != actual:
        raise ValueError('identity configuration digest mismatch')
    data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
    if (type(data) is not dict or set(data) != {'schema', 'authorization', 'policy', 'ledger_path'}
            or type(data['schema']) is not int or data['schema'] != 1):
        raise ValueError('unsupported identity configuration')
    auth = data['authorization']
    fields = {'identity_provider_id', 'service_account_id', 'target', 'starts_at',
              'expires_at', 'maximum_exchanges', 'scopes', 'minimum_interval_seconds'}
    if type(auth) is not dict or set(auth) != fields or type(auth['scopes']) is not list:
        raise ValueError('exact issuance authorization required')
    authorization = IssuanceAuthorization(
        approval_digest=actual, identity_provider_id=auth['identity_provider_id'],
        service_account_id=auth['service_account_id'],
        target=ResolvedProviderTarget(**auth['target']),
        starts_at=datetime.fromisoformat(auth['starts_at']),
        expires_at=datetime.fromisoformat(auth['expires_at']),
        maximum_exchanges=auth['maximum_exchanges'], scopes=tuple(auth['scopes']),
        minimum_interval_seconds=auth['minimum_interval_seconds'])
    authorization.canonical()
    policy_fields = {'request_origin', 'audience', 'repository', 'repository_id', 'workflow_ref', 'ref'}
    if type(data['policy']) is not dict or set(data['policy']) != policy_fields:
        raise ValueError('exact GitHub policy required')
    policy = GitHubIdentityPolicy(**data['policy'])
    policy.claims()
    ledger = Path(data['ledger_path'])
    if (not ledger.is_absolute() or not ledger.parent.is_dir()
            or any(parent.is_symlink() for parent in (ledger, *ledger.parents))):
        raise ValueError('absolute regular operator ledger location required')
    return GitHubHostConfiguration(authorization, policy, ledger)


def open_ledger(configuration, *, initialize=False):
    path = configuration.ledger_path
    if initialize:
        # Exclusive reservation: a consumed/uncertain ledger is never replaced.
        with path.open('xb'):
            pass
    else:
        if not path.is_file() or path.is_symlink():
            raise ValueError('existing admitted issuance ledger required')
        # Fail before the constructor can initialize an empty or unrelated file.
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
            row = db.execute('SELECT binding FROM issuance_policy WHERE id=1').fetchone()
            if row != (configuration.authorization.canonical(),):
                raise ValueError('existing issuance ledger binding mismatch')
            db.execute('SELECT claim, started, status FROM issuance_attempts LIMIT 0')
    return CredentialIssuanceLedger(path, configuration.authorization, operator_authorized=True)


def binding_from_configuration(path, expected_digest, *, clock, owner_authorized=False,
                               enabled=False):
    if type(enabled) is not bool:
        raise ValueError('explicit boolean identity activation required')
    if not enabled:
        return None
    configuration = read_configuration(path, expected_digest, owner_authorized=owner_authorized)
    ledger = open_ledger(configuration)
    source = GitHubSubjectSource(authorization=configuration.authorization,
        policy=configuration.policy, environment=os.getenv, clock=clock, enabled=True)
    exchange = JWTTokenExchange(authorization=configuration.authorization,
        subject_source=source, clock=clock, enabled=True)
    # Never resume a paused ledger implicitly, including on scheduler restart.
    return exchange.binding(ledger)
