"""Task005-only entrypoints. Additional deployment switch defaults to disabled.

Shared dispatchers retain their existing gates, custody checks and permanent
claims. No tick, upload, budget approval or old-task switch activates task005.
"""
import os
from datetime import datetime, timezone
from pathlib import Path
from factory_state.model import StateError
from .remediation_profile import TASK, TEST_COUNT
from . import remediation_deployment as deployment


def dispatch(stage, event, context, *, root, env, clock):
    if env.get('FACTORY_REMEDIATION005_ENABLED') != 'true':
        raise StateError('Task005 deployment disabled')
    if stage == 'review_role':
        from .review_role_lambda import dispatch as run
        return run(event, context, root=root, env=env, clock=clock,
            deployment_loader=deployment.load_review_role)
    if stage == 'review_controller':
        from .review_controller_lambda import dispatch as run
        return run(event, context, root=root, env=env, clock=clock,
            deployment_loader=deployment.load_review_controller, task_id=TASK, test_count=TEST_COUNT)
    if stage in ('security_role', 'security_controller'):
        if stage == 'security_role':
            from .security_role_lambda import dispatch as run
            extra = {}
        else:
            from .security_controller_lambda import dispatch as run
            extra = {'config_loader': deployment.load_security_controller, 'task_id': TASK}
        return run(event, context, root=root, env=env, clock=clock,
            deployment_loader=deployment.load_security, backend_factory=deployment.disabled_backend, **extra)
    raise StateError('Unknown task005 deployment stage')


def _handler(stage, event, context):
    return dispatch(stage, event, context, root=Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task')),
        env=os.environ, clock=lambda: datetime.now(timezone.utc))


def review_role_handler(event, context):
    return _handler('review_role', event, context)


def review_controller_handler(event, context):
    return _handler('review_controller', event, context)


def security_role_handler(event, context):
    return _handler('security_role', event, context)


def security_controller_handler(event, context):
    return _handler('security_controller', event, context)
