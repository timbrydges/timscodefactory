"""Deployment-pinned single-stage controller bounds; no authority from ticks."""
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from factory_state.model import StateError
from factory_state.scope import canonical
from .acceptance_jobs import PinnedJobVersion
from .autonomy import AutonomyActivation
from .pilot002_entrypoint import _read, _pairs
from .security_deployment import SecurityDeployment
from .security_provider_scope import VerifiedSecurityAllowance
from .worker import digest


@dataclass(frozen=True)
class SecurityControllerConfig:
    activation: AutonomyActivation
    function_arn: str
    job_version: PinnedJobVersion


def load_controller_config(root, env, *, deployment, grant, now):
    if type(deployment) is not SecurityDeployment or type(grant) is not VerifiedSecurityAllowance:
        raise StateError('Exact deployment and verified security allowance required')
    try:
        raw=_read(root,'SECURITY_CONTROLLER.json',16384)
        if digest(raw)!=env.get('FACTORY_SECURITY_CONTROLLER_DIGEST'):
            raise StateError('Security controller deployment pin differs')
        doc=json.loads(raw,object_pairs_hook=_pairs)
        if (type(doc) is not dict or canonical(doc)!=raw or
                set(doc)!={'activation','function_arn','job_versions'} or
                type(doc['activation']) is not dict or
                set(doc['activation'])!=set(AutonomyActivation.__dataclass_fields__) or
                type(doc['job_versions']) is not dict or set(doc['job_versions'])!={'SECURITY_REVIEW'}):
            raise StateError('Exact security-only controller configuration required')
        a=doc['activation']
        activation=AutonomyActivation(**{**a,'starts_at':datetime.fromisoformat(a['starts_at']),
            'expires_at':datetime.fromisoformat(a['expires_at'])})
        activation.validate(now)
        q=deployment.material.binding.qa
        scope=deployment.material.prepared().scope
        if ((activation.activation_id,activation.factory_id,activation.task_id,
                activation.source_commit,activation.contract_digest)!=
                ('bounded-security-004',q.factory_id,q.task_id,q.source_commit,q.contract_digest) or
                activation.expires_at-activation.starts_at>timedelta(hours=1) or
                activation.expires_at.timestamp()>grant.expires_at or
                grant.scope_digest!=digest(canonical(scope.bindings()))):
            raise StateError('Security activation exceeds exact source or allowance bounds')
        arn=doc['function_arn']
        if type(arn) is not str or not re.fullmatch(
                r'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-review-security:[1-9][0-9]*',arn):
            raise StateError('Exact numeric security role route required')
        version=PinnedJobVersion(**doc['job_versions']['SECURITY_REVIEW'])
        return SecurityControllerConfig(activation,arn,version)
    except (ValueError,TypeError,KeyError,AttributeError,RecursionError):
        raise StateError('Invalid security controller configuration') from None
