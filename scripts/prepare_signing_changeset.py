"""Prepare, but never execute, the exact reviewed Factory signing deployment."""
import hashlib
import json
import re
import subprocess
from pathlib import Path


def aws(*args):
    response = subprocess.run(['aws', *args, '--region', 'ca-central-1', '--output', 'json', '--no-cli-pager'],
                              capture_output=True, timeout=60, check=True)
    return json.loads(response.stdout or b'{}')


def main():
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True)
    if dirty or not re.fullmatch('[a-f0-9]{40}', commit):
        raise RuntimeError('change set requires a clean exact checkout')
    identity = aws('sts', 'get-caller-identity')
    if identity.get('Account') != '666730517561':
        raise RuntimeError('wrong AWS account')
    template = root / 'infra/signing/keys.cloudformation.json'
    aws('cloudformation', 'validate-template', '--template-body', 'file://' + str(template))
    name = 'signing-' + commit[:12]
    # CREATE only: never implicitly update an existing deployment or replace its keys.
    change = aws('cloudformation', 'create-change-set', '--stack-name', 'tims-factory-signing',
        '--change-set-name', name, '--change-set-type', 'CREATE', '--capabilities', 'CAPABILITY_NAMED_IAM',
        '--template-body', 'file://' + str(template), '--description',
        'Owner approval required: four KMS keys, USD 4/month plus requests; source ' + commit,
        '--tags', 'Key=System,Value=tims-software-factory', 'Key=ManagedBy,Value=factory-signing-cloudformation')
    print(json.dumps({'source_commit': commit, 'change_set_arn': change['Id'],
        'template_sha256': hashlib.sha256(template.read_bytes()).hexdigest(),
        'status': 'PREPARED_NOT_EXECUTED', 'recurring_key_cost_usd_month': '4.00'}, indent=2))


if __name__ == '__main__':
    main()
