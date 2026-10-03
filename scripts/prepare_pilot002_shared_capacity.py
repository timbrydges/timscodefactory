"""Preview a separately approved shared-pool Builder run; never deploy or invoke."""
import copy
from factory_state.model import StateError


def render(current, previous):
    if current!=previous['rollback_template']:raise StateError('Disabled baseline drift')
    target=copy.deepcopy(previous['template'])
    builder=target['Resources']['BuilderFunction']['Properties']
    if builder.get('ReservedConcurrentExecutions')!=1:raise StateError('Expected reviewed one-slot proposal')
    if previous['package']['activation_sha256']!='ba34487e5726356ecde8fd07212ed6aaf7a32292b591ed4018455881d9a4cf7e':
        raise StateError('Existing signed plan material changed')
    del builder['ReservedConcurrentExecutions']
    return target


def validate(template, changes, previous):
    expected=render(previous['rollback_template'],previous)
    if (template!=expected or changes.get('Status')!='CREATE_COMPLETE' or
            changes.get('ExecutionStatus')!='AVAILABLE' or changes.get('NextToken') or
            changes.get('StackId')!=previous['stack_id']):raise StateError('Shared-pool preview differs')
    items=changes.get('Changes',[])
    if len(items)!=1:raise StateError('Only Builder may change')
    item=items[0];r=item.get('ResourceChange',{})
    if (item.get('Type')!='Resource' or r.get('LogicalResourceId')!='BuilderFunction' or
            r.get('ResourceType')!='AWS::Lambda::Function' or r.get('Action')!='Modify' or
            r.get('Replacement')!='False'):raise StateError('Unexpected resource change')
    return {'status':'SHARED_POOL_PREVIEW_NOT_EXECUTED','reserved_lambda_limit':None,
        'maximum_provider_calls':1,'reserved_model_micro_usd':250000,'retries':0,
        'new_signature_required':False,'quota_change_required':False}
