"""Read-only role probe; no signing, task creation, model call or state mutation."""
import json
import re
import subprocess
import sys

TABLE = 'tims-software-factory-state'
PK = 'FACTORY#tims-software-factory#TASK#bounded-review-001'
ROLE = 'arn:aws:sts::666730517561:assumed-role/tims-factory-signing-spec-reviewer/'


class ReadError(RuntimeError):
    pass


def read(service, operation, params):
    if (service, operation) not in {('sts', 'get-caller-identity'), ('dynamodb', 'get-item')}:
        raise ValueError('read-only operation required')
    result = subprocess.run(['aws', service, operation, '--region', 'ca-central-1',
        '--cli-input-json', json.dumps(params), '--output', 'json', '--no-cli-pager'],
        capture_output=True, timeout=30)
    if result.returncode:
        code = re.search(rb'An error occurred \(([^)]+)\)', result.stderr)
        raise ReadError(code.group(1).decode() if code else 'unclassified-read-error')
    return json.loads(result.stdout)


def run(run_id, commit, *, call=read):
    if not re.fullmatch(r'[0-9]+-1', run_id) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('first run attempt and exact source required')
    caller = call('sts', 'get-caller-identity', {})
    arn = caller.get('Arn', '')
    if (caller.get('Account') != '666730517561' or not arn.startswith(ROLE) or
            not arn[len(ROLE):] or '/' in arn[len(ROLE):]):
        raise ValueError('isolated Product Spec role required')
    def request(key):
        return call('dynamodb', 'get-item', {'TableName': TABLE, 'ConsistentRead': True,
                    'Key': {'PK': {'S': key}, 'SK': {'S': 'STATE'}}})
    result = request(PK)
    try:
        request(PK + '-outside-approved-scope')
    except ReadError as error:
        if str(error) != 'AccessDeniedException':
            raise
    else:
        raise ValueError('other-task read unexpectedly succeeded')
    return {'conclusion': 'success', 'source_commit': commit, 'workflow_run': run_id,
        'aws_caller_arn': arn, 'table': TABLE, 'allowed_partition': PK,
        'exact_task_read_allowed': True, 'task_exists': bool(result.get('Item')),
        'other_task_read_denied': True, 'state_payload_exported': False,
        'writes': 0, 'signatures': 0, 'model_calls': 0}


if __name__ == '__main__':
    print(json.dumps(run(*sys.argv[1:]), indent=2))
