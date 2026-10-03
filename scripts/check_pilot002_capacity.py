"""Offline Lambda reservation preflight and disabled-state verification."""
from factory_state.model import StateError


def capacity(account_limit, *, current_reserved, desired_reserved, minimum_unreserved):
    values=(account_limit.get('ConcurrentExecutions'),account_limit.get('UnreservedConcurrentExecutions'),
        current_reserved,desired_reserved,minimum_unreserved)
    if any(type(v) is not int or v<0 for v in values):raise StateError('Exact integer capacity values required')
    total,unreserved,current,desired,floor=values
    if unreserved>total or current>total-unreserved or desired!=1 or floor<1:
        raise StateError('Inconsistent account capacity or Pilot 002 reservation')
    available_after=unreserved+current-desired
    shortage=max(0,floor-available_after)
    return {'status':'CAPACITY_READY' if shortage==0 else 'CAPACITY_BLOCKED',
        'account_concurrency':total,'unreserved_before':unreserved,
        'current_function_reservation':current,'desired_function_reservation':desired,
        'minimum_unreserved':floor,'unreserved_after':available_after,
        'minimum_account_limit_under_observed_floor':total+shortage,
        'requires_fresh_aws_verification':True}


def disabled_snapshot(stack_status, actual_template, expected_template, functions, code_hashes):
    if stack_status not in ('UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE') or actual_template!=expected_template:
        raise StateError('Stack not stably at the exact disabled template')
    roles={'builder','inspector','qa'}
    if set(functions)!=roles or set(code_hashes)!=roles:raise StateError('All three roles required')
    for role in roles:
        function=functions[role];props=expected_template['Resources'][role.title()+'Function']['Properties']
        env=function['Environment']['Variables']
        if (env!=props['Environment']['Variables'] or env.get('FACTORY_PILOT002_EXECUTION_ENABLED')!='false' or
                function['ReservedConcurrentExecutions']!=0 or function['Handler']!=props['Handler'] or
                function['Timeout']!=props['Timeout'] or function['CodeSha256']!=code_hashes[role] or
                function['LastUpdateStatus']!='Successful'):
            raise StateError('Disabled runtime differs')
    return {'status':'DISABLED_RUNTIME_VERIFIED','stack_status':stack_status,'all_roles_disabled':True}


if __name__=='__main__':
    import argparse
    import json
    import boto3
    from botocore.config import Config
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minimum-unreserved',required=True,type=int,
        help='Minimum from reviewed AWS rejection evidence; never guess a lower floor')
    args=parser.parse_args()
    session=boto3.Session(region_name='ca-central-1')
    config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=15)
    assert session.client('sts',config=config).get_caller_identity()['Account']=='666730517561'
    client=session.client('lambda',config=config)
    current=client.get_function_concurrency(FunctionName='tims-factory-pilot-002-builder').get('ReservedConcurrentExecutions')
    result=capacity(client.get_account_settings()['AccountLimit'],current_reserved=current,
        desired_reserved=1,minimum_unreserved=args.minimum_unreserved)
    print(json.dumps(result,indent=2))
    raise SystemExit(0 if result['status']=='CAPACITY_READY' else 2)
