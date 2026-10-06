"""Disabled-by-default cloud controller observation, without dispatch authority."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from factory_state.model import StateError

NAME='tims-factory-handoff-002-observer'
ARN='arn:aws:lambda:ca-central-1:666730517561:function:'+NAME+':'


def run(event, context, *, root, env, observe, clock):
    if env.get('FACTORY_HANDOFF002_OBSERVER_ENABLED')!='true':
        raise StateError('Observer disabled')
    arn=getattr(context,'invoked_function_arn','')
    if (not isinstance(arn,str) or not arn.startswith(ARN) or
            not re.fullmatch('[1-9][0-9]*',arn[len(ARN):]) or
            env.get('AWS_REGION')!='ca-central-1' or env.get('AWS_LAMBDA_FUNCTION_NAME')!=NAME):
        raise StateError('Exact observer version required')
    build=json.loads((root/'BUILD.json').read_bytes())
    if event!={'kind':'handoff002_observe_only','source_commit':build['source_commit']}:
        raise StateError('Observation source binding differs')
    result=observe(clock())
    if (result.get('worker_invocations')!=0 or result.get('execution_authorized') is not False or
            result.get('gate_authority') is not False or result.get('authoritative_task_state_written') is not False):
        raise StateError('Unexpected observation authority')
    return {**result,'observer_source_commit':build['source_commit'],'observer_version_arn':arn}


def handler(event, context):
    root=Path(__file__).resolve().parents[1]
    def observe(now):
        # No AWS client exists until local disable/version/source checks pass.
        sys.path.insert(0,str(root/'scripts'))
        from observe_handoff002_controller import observe as inspect
        import boto3
        from botocore.config import Config
        session=boto3.Session(region_name='ca-central-1')
        cfg=Config(retries={'total_max_attempts':1})
        return inspect(session.client('sts',config=cfg),session.client('dynamodb',config=cfg),now)
    return run(event,context,root=root,env=os.environ,observe=observe,clock=lambda:datetime.now(timezone.utc))
