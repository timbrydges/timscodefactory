"""Prepare one disabled Builder code/entrypoint update; never executes changes."""
import copy
import re
from prepare_pilot002_access import baseline,render as access_template,ACCOUNT,REGION,STACK
from factory_state.model import StateError

SOURCE='535233c6e7e7655ef79e885b9c1a164fd7bee1d4'
BUCKET='tims-software-factory-666730517561-ca-central-1'


def render(current,package,code):
    if current!=access_template(baseline()):raise StateError('Deployed baseline differs')
    if (package.get('source_commit')!=SOURCE or package.get('execution_enabled') is not False or
            package.get('model_calls')!=0 or package.get('handler')!='factory_runtime.pilot002_runtime_probe.handler' or
            'activation_sha256' in package or not re.fullmatch('[0-9a-f]{64}',package.get('sha256',''))):
        raise StateError('Unreviewed runtime package')
    if (set(code)!={'S3Bucket','S3Key','S3ObjectVersion'} or code['S3Bucket']!=BUCKET or
            code['S3Key']!='pilot-002/runtime/'+SOURCE+'/'+package['sha256']+'.zip' or
            not isinstance(code['S3ObjectVersion'],str) or not 0<len(code['S3ObjectVersion'])<=1024 or
            code['S3ObjectVersion']=='null'):raise StateError('Immutable artifact differs')
    result=copy.deepcopy(current)
    builder=result['Resources']['BuilderFunction']['Properties']
    builder.update(Code=copy.deepcopy(code),Handler='factory_runtime.pilot002_entrypoint.handler',Timeout=180,
        Description='Pilot 002 Builder staged entrypoint; disabled, no activation material')
    builder['Tags']=[{'Key':'SourceCommit','Value':SOURCE},{'Key':'Purpose','Value':'disabled-builder-entrypoint'}]
    return result


def validate(template,changes,package,code):
    if (template!=render(access_template(baseline()),package,code) or
            changes.get('Status')!='CREATE_COMPLETE' or changes.get('ExecutionStatus')!='AVAILABLE' or
            changes.get('NextToken') or changes.get('Parameters') or not str(changes.get('StackId','')).startswith(
                f'arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK}/')):
        raise StateError('Staging preview differs or incomplete')
    items=changes.get('Changes',[])
    if len(items)!=1:raise StateError('Only Builder can change')
    item=items[0];change=item.get('ResourceChange',{})
    if (item.get('Type')!='Resource' or change.get('LogicalResourceId')!='BuilderFunction' or
            change.get('ResourceType')!='AWS::Lambda::Function' or change.get('Action')!='Modify' or
            change.get('Replacement')!='False'):raise StateError('Unexpected runtime resource change')
    return {'status':'BUILDER_STAGE_VALIDATED_NOT_EXECUTED','source_commit':SOURCE,
        'execution_enabled':False,'reserved_concurrency':0,'activation_material_present':False,
        'provider_calls':0,'changed_functions':['builder'],'iam_changes':0}
