"""Stage an immutable package and CREATE change set; never execute it."""
import base64
import hashlib
import json
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

from prepare_google_qa_broker import ROOT, SECRET_ARN, SECRET_VERSION, render

STACK = 'tims-factory-google-qa-broker'
BUCKET = 'tims-software-factory-666730517561-ca-central-1'


def main():
    package, output = map(lambda p: Path(p).resolve(), sys.argv[1:3])
    if output.is_relative_to(ROOT) or output.exists():
        raise RuntimeError('use a new staging journal outside the checkout')
    commit = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip():
        raise RuntimeError('staging requires a clean reviewed checkout')
    meta = json.loads(package.with_suffix('.json').read_bytes())
    raw = package.read_bytes(); sha = hashlib.sha256(raw).digest()
    if (meta['source_commit'] != commit or meta['sha256'] != sha.hex() or
            meta['code_sha256'] != base64.b64encode(sha).decode()):
        raise RuntimeError('package metadata differs')
    with zipfile.ZipFile(package) as archive:
        if json.loads(archive.read('BUILD.json'))['source_commit'] != commit:
            raise RuntimeError('package source differs')
    template = render()
    if json.loads((ROOT/'infra/roles/google-qa-broker-disabled.cloudformation.json').read_bytes()) != template:
        raise RuntimeError('template differs from reviewed renderer')
    template_bytes = json.dumps(template,sort_keys=True,separators=(',',':')).encode()
    import boto3
    from botocore.config import Config
    session = boto3.Session(region_name='ca-central-1')
    config = Config(connect_timeout=5,read_timeout=30,retries={'total_max_attempts':1})
    client = lambda service: session.client(service,config=config)
    if client('sts').get_caller_identity()['Account'] != '666730517561':
        raise RuntimeError('wrong AWS account')
    sm, s3, cf = client('secretsmanager'), client('s3'), client('cloudformation')
    secret = sm.describe_secret(SecretId=SECRET_ARN)
    if 'AWSCURRENT' not in secret.get('VersionIdsToStages',{}).get(SECRET_VERSION,[]):
        raise RuntimeError('approved Google credential version changed')
    if s3.get_bucket_versioning(Bucket=BUCKET).get('Status') != 'Enabled':
        raise RuntimeError('artifact bucket must use versioning')
    try:
        cf.describe_stacks(StackName=STACK)
    except cf.exceptions.ClientError as error:
        if (error.response['Error']['Code'] != 'ValidationError' or
                'does not exist' not in error.response['Error']['Message']):
            raise
    else:
        raise RuntimeError('stack already exists; inspect, do not create another change set')
    cf.validate_template(TemplateBody=template_bytes.decode())
    nonce = uuid.uuid4().hex
    plan = {'status':'STAGING_NOT_EXECUTED','source_commit':commit,
        'change_set_name':'google-qa-disabled-'+nonce,'stack_name':STACK,
        'package':meta,'template_sha256':hashlib.sha256(template_bytes).hexdigest(),
        'artifact_bucket':BUCKET,'artifact_key':'google-qa-broker/'+commit+'/'+sha.hex()+'.zip',
        'model_calls':0,'permissions_applied':False,'owner_execution_approval_required':True}
    with output.open('x',encoding='utf-8') as stream: json.dump(plan,stream,indent=2)
    def save(): output.write_text(json.dumps(plan,indent=2)+'\n',encoding='utf-8')
    uploaded = s3.put_object(Bucket=BUCKET,Key=plan['artifact_key'],Body=raw,
        ServerSideEncryption='AES256',ChecksumSHA256=meta['code_sha256'])
    plan['artifact_version'] = uploaded.get('VersionId')
    save()
    if not plan['artifact_version']: raise RuntimeError('immutable artifact version absent')
    parameters = {'ArtifactBucket':BUCKET,'ArtifactKey':plan['artifact_key'],
                  'ArtifactVersion':plan['artifact_version'],'CodeSha256':meta['code_sha256']}
    created = cf.create_change_set(StackName=STACK,ChangeSetName=plan['change_set_name'],
        ChangeSetType='CREATE',TemplateBody=template_bytes.decode(),
        Parameters=[{'ParameterKey':k,'ParameterValue':v} for k,v in parameters.items()],
        Capabilities=['CAPABILITY_NAMED_IAM'],ClientToken=nonce,
        Description='Pending owner approval: disabled Google QA broker, exact secret and isolated attempt ledger.')
    plan.update(change_set_arn=created['Id'],stack_id=created['StackId']); save()
    for _ in range(30):
        change = cf.describe_change_set(ChangeSetName=plan['change_set_arn'])
        if change['Status'] not in ('CREATE_PENDING','CREATE_IN_PROGRESS'): break
        time.sleep(2)
    if change['Status']!='CREATE_COMPLETE' or change['ExecutionStatus']!='AVAILABLE':
        raise RuntimeError('change set not ready; inspect saved journal without retry')
    changes = [c['ResourceChange'] for c in change['Changes']]
    if (len(changes)!=5 or {c['LogicalResourceId'] for c in changes}!=set(template['Resources']) or
            any(c['Action']!='Add' for c in changes)):
        raise RuntimeError('change set is not exactly five approved additions')
    plan.update(status='PREPARED_PENDING_OWNER_APPROVAL',changes=changes); save()
    print(json.dumps(plan,sort_keys=True))


if __name__ == '__main__': main()
