"""Deployment-owned task005 identity; no event-selected profiles or authority."""
from factory_state.model import StateError

OLD_TASK = 'bounded-review-004'
TASK = 'bounded-review-005'
CANDIDATE = '4243fc88dcc34aac15cfd58df1289eed9f4cca92'
CANDIDATE_DIGEST = 'sha256:297e2a7bbdf2cf2277d2c811a2c1020dfed541c9c38710bccdc0da55b6bfcaf2'
PATHS = ('fingerprint.py', 'tests/test_fingerprint.py')
TEST_COUNT = 21
AGGREGATE_CEILING = 4450000
PROVIDER_HOLDS = {'builder':250000, 'inspector':175000, 'qa':75000, 'security':250000}
EXISTING_HOLDS = 3600000
NEW_AWS_HOLD = 100000


def task_number(task):
    if type(task) is not str or task not in (OLD_TASK, TASK):
        raise StateError('Unknown deployment-owned task profile')
    return '005' if task == TASK else '004'


def validate_candidate(task, commit, digest):
    task_number(task)
    if task == TASK and (commit, digest) != (CANDIDATE, CANDIDATE_DIGEST):
        raise StateError('Task005 requires the exact merged remediation candidate')


def claim_key(task, role):
    number = task_number(task)
    if role not in PROVIDER_HOLDS:
        raise StateError('Unknown bounded role')
    prefix = 'BOUNDED_SECURITY' if role == 'security' else 'BOUNDED_REVIEW'
    return f'{prefix}#{number}#ROLE#{role}'

BASELINE = "factory/evidence/remediation005-candidate.json"
BASELINE_SHA256 = "1e48e9a6458259c14c86608e7dcecbffaa569a9e02032a8368723e8c9b580c9e"

EVIDENCE = 'Fresh exact-source Linux proof: 21 fingerprint tests; independent authenticated role receipts.'
STOP = 'One attempt per role; no retries, candidate changes or release; stop on rejection, uncertainty or stale evidence.'

DISABLED_ENV = {key:'false' for key in (
    'FACTORY_REMEDIATION005_ENABLED', 'FACTORY_BOUNDED_REVIEW_ENABLED',
    'FACTORY_BOUNDED_CONTROLLER_ENABLED', 'FACTORY_SECURITY_ENABLED',
    'FACTORY_SECURITY_CONTROLLER_ENABLED')}
HANDLERS = {role:'factory_runtime.remediation_lambda.'+stage+'_handler' for role,stage in {
    'builder':'review_role', 'inspector':'review_role', 'qa':'review_role',
    'controller':'review_controller', 'security':'security_role', 'security-controller':'security_controller'}.items()}
