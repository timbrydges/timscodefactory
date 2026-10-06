"""Separate permanent claims for the new budget; never reset the pilot ledger."""
from factory_state.model import StateError
from .handoff002_packets import TASK, CONTRACT, PINNED
from .pilot002_attempts import _PermanentAttemptStore

TABLE = 'tims-factory-handoff-002-attempts'
ROLES = ('builder', 'inspector', 'qa')


def key(role):
    if not isinstance(role, str) or role not in ROLES:
        raise StateError('Unknown handoff provider role')
    return {'PK': {'S': f'HANDOFF#002#TASK#{TASK}#ROLE#{role}'}}


class Handoff002AttemptStore(_PermanentAttemptStore):
    table = TABLE
    task = TASK
    contract_digest = 'sha256:' + PINNED[CONTRACT]
    row_key = staticmethod(key)
