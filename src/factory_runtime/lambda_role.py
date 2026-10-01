"""Lambda entrypoint for identity and durable model-free transport canaries.

The canaries prove deployment, authentication, signing, persistence and replay
protection. The full RoleExecutionService is packaged but remains disabled.
"""
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from factory_state.kms_signer import EnrolledKmsReceiptSigner, SIGNERS
from factory_state.model import StateError
from factory_state.scope import canonical

MAX_CANARY_INPUT = 4096
OPERATIONAL_FLAG = 'FACTORY_OPERATIONAL_EXECUTION_ENABLED'
ACTIVATION_CONFIG = 'FACTORY_ACCEPTANCE_ACTIVATION_JSON'
INSPECTOR_AUTHORIZATION_ID = 'acceptance-inspector-sonnet45-fallback-authorization-2026-10-01-006'
INSPECTOR_ACTIVATION_ID = 'inspector-fallback-2026-10-01-006'
INSPECTOR_CONTRACT_DIGEST = 'sha256:7ca5363f88bc43e31436e1c8640bb9516a705aa07dda82519a690a9301a9b9fa'
INSPECTOR_INPUT_DIGEST = 'sha256:e1aefa3eb9e1d4251c15285a353d1b8abbf0076acd515bff13133894a6a48418'


def validate_probe(event, *, role, commit):
    if (role not in {'planner', 'builder', 'inspector'} or
            not isinstance(event, dict) or set(event) != {'kind', 'source_commit', 'nonce'} or
            event['kind'] != 'identity_probe' or event['source_commit'] != commit or
            not isinstance(event['nonce'], str) or not re.fullmatch(r'[a-zA-Z0-9-]{16,64}', event['nonce'])):
        raise StateError('only the bounded deployment identity probe is enabled')


def handle_probe(event, *, role, commit, signer, now):
    validate_probe(event, role=role, commit=commit)
    if signer.identity != SIGNERS[role]:
        raise StateError('deployed role signer mismatch')
    payload = {'kind': 'identity_challenge', 'identity': signer.identity,
        'source_commit': commit, 'nonce': event['nonce'], 'purpose': 'lambda-deployment-verification-only',
        'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
    signature = signer.sign(payload, now=now)
    return {'payload': payload, 'signature_base64': base64.b64encode(signature).decode(),
            'model_calls': 0, 'operational_execution_enabled': False}


def _disabled_builder_backend(root, *, commit, now):
    from .autonomy import AutonomyActivation
    from .autonomy_contract import load_autonomy_operating_allowance
    from .operational_backend import AcceptanceOperationalBackend

    allowance = load_autonomy_operating_allowance(root)
    if (allowance.status == 'ACTIVE' or not allowance.pending_gates or
            allowance.production_release_authorized or
            allowance.acceptance_task_id != 'deterministic-text-fingerprint' or
            allowance.target_alias != 'coding_primary_sol_live' or
            allowance.model_id != 'gpt-5.6-sol' or
            str(allowance.maximum_cost_per_call) != '0.25' or
            allowance.maximum_provider_calls != 3 or
            allowance.maximum_request_bytes_at_cost_cap != 42020):
        raise StateError('disabled Builder operating contract differs')

    class NoOperationalIO:
        def __getattr__(self, name):
            raise StateError('disabled Builder cannot access operational IO')

    activation = AutonomyActivation('disabled-builder-probe', 'tims-software-factory',
        allowance.acceptance_task_id, commit,
        'sha256:' + allowance.acceptance_contract_sha256,
        now, now + timedelta(minutes=1))
    backend = AcceptanceOperationalBackend(root, activation,
        NoOperationalIO(), NoOperationalIO(), enabled=False)
    try:
        backend.check_activation(None, None, now=now)
    except StateError as error:
        if str(error) != 'operational backend is disabled':
            raise
    else:
        raise StateError('Builder operational backend unexpectedly enabled')
    # Compose the same service used by the operational branch with inert clients.
    # Construction must not perform IO; the Lambda kill switch still rejects
    # operational events before this branch can be reached.
    from types import SimpleNamespace

    inert = NoOperationalIO()
    broker_arn = ('arn:aws:lambda:ca-central-1:666730517561:'
                  'function:tims-factory-provider-broker:3')
    client = SimpleNamespace(meta=SimpleNamespace(config=SimpleNamespace(
        retries={'total_max_attempts': 1}),
        endpoint_url='https://lambda.ca-central-1.amazonaws.com'))
    service = _builder_service(root, commit, activation, broker_arn,
                               SimpleNamespace(identity=SIGNERS['builder']), inert, client)
    if (service.execution_table != 'tims-factory-role-executions' or
            service.ledger.table_name != 'tims-software-factory-state' or
            service.backend.budget_store.table_name != 'tims-factory-acceptance-budget' or
            service.backend.executor.function_arn != broker_arn or
            service.backend.activation != activation):
        raise StateError('disabled Builder operational composition differs')
    return allowance


def handle_operational_boundary_probe(event, *, role, commit, signer, now, root=None):
    expected = {'kind', 'source_commit', 'nonce', 'task_id'}
    if (role != 'builder' or not isinstance(event, dict) or set(event) != expected or
            event.get('kind') != 'operational_boundary_probe' or
            event.get('source_commit') != commit or
            event.get('task_id') != 'deterministic-text-fingerprint' or
            not isinstance(event.get('nonce'), str) or
            not re.fullmatch(r'[a-zA-Z0-9-]{16,64}', event['nonce']) or
            signer.identity != SIGNERS['builder']):
        raise StateError('invalid operational boundary probe')
    root = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    allowance = _disabled_builder_backend(root, commit=commit, now=now)
    payload = {'kind': 'operational_boundary_attestation',
        'producer_identity': SIGNERS['builder'], 'source_commit': commit,
        'nonce': event['nonce'], 'task_id': event['task_id'],
        'target_alias': allowance.target_alias, 'model_id': allowance.model_id,
        'maximum_cost_usd_per_call': str(allowance.maximum_cost_per_call),
        'maximum_provider_calls': allowance.maximum_provider_calls,
        'maximum_request_bytes': allowance.maximum_request_bytes_at_cost_cap,
        'provider_credentials_in_role': False,
        'operational_execution_enabled': False,
        'purpose': 'operational-boundary-deployment-verification-only',
        'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
    return {'payload': payload, 'signature_base64': base64.b64encode(
        signer.sign(payload, now=now)).decode(), 'model_calls': 0,
        'operational_execution_enabled': False}


def _disabled_inspector_runtime(root, *, now):
    from types import SimpleNamespace

    from .inspector_budget import InspectorBudgetStore, _price
    from .inspector_runtime import InspectorReviewRuntime

    policy_path = root / 'factory/evidence/acceptance-inspector-sonnet45-budget-policy-2026-09-30.json'
    try:
        policy = json.loads(policy_path.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError) as error:
        raise StateError('Inspector budget policy is unavailable') from error
    reserved = _price(policy, now=now)
    if str(reserved) != '0.24144':
        raise StateError('Inspector conservative reservation differs from reviewed policy')

    class NoOperationalIO:
        def __getattr__(self, name):
            raise StateError('disabled Inspector cannot access operational IO')

    bedrock = SimpleNamespace(
        meta=SimpleNamespace(
            endpoint_url='https://bedrock-runtime.ca-central-1.amazonaws.com',
            config=SimpleNamespace(retries={'total_max_attempts': 1})),
        converse=NoOperationalIO())
    budget = InspectorBudgetStore('tims-factory-acceptance-budget', NoOperationalIO())
    runtime = InspectorReviewRuntime(bedrock, budget)
    if (runtime.client is not bedrock or runtime.budget is not budget or
            runtime.budget.table_name != 'tims-factory-acceptance-budget'):
        raise StateError('disabled Inspector runtime composition differs')
    return policy


def handle_inspector_runtime_boundary_probe(event, *, role, commit, signer, now, root=None):
    expected = {'kind', 'source_commit', 'nonce', 'task_id'}
    if (role != 'inspector' or not isinstance(event, dict) or set(event) != expected or
            event.get('kind') != 'inspector_runtime_boundary_probe' or
            event.get('source_commit') != commit or
            event.get('task_id') != 'deterministic-text-fingerprint' or
            not isinstance(event.get('nonce'), str) or
            not re.fullmatch(r'[a-zA-Z0-9-]{16,64}', event['nonce']) or
            signer.identity != SIGNERS['inspector']):
        raise StateError('invalid Inspector runtime boundary probe')
    root = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    policy = _disabled_inspector_runtime(root, now=now)
    payload = {'kind': 'role_result',
        'producer_identity': SIGNERS['inspector'], 'source_commit': commit,
        'nonce': event['nonce'], 'task_id': event['task_id'],
        'model_id': policy['model_id'],
        'maximum_cost_usd_per_call': policy['maximum_total_cost_usd'],
        'reserved_cost_usd': policy['conservative_maximum_cost_usd'],
        'maximum_provider_calls': policy['maximum_provider_calls'],
        'maximum_request_bytes': policy['maximum_request_bytes'],
        'reviewer_publication_requires_authenticated_decision': True,
        'operational_execution_enabled': False,
        'purpose': 'inspector-runtime-boundary-deployment-verification-only',
        'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
    return {'payload': payload, 'signature_base64': base64.b64encode(
        signer.sign(payload, now=now)).decode(), 'model_calls': 0,
        'operational_execution_enabled': False}


def _load_inspector_live_authorization(root):
    path = root / 'factory/evidence/acceptance-inspector-sonnet45-fallback-authorization-2026-10-01-006.json'
    try:
        document = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError) as error:
        raise StateError('Inspector live authorization is unavailable') from error
    expected = {
        'schema_version': '1.0',
        'event_id': INSPECTOR_AUTHORIZATION_ID,
        'owner_identity': 'tim_brydges',
        'task_id': 'deterministic-text-fingerprint',
        'activation_id': INSPECTOR_ACTIVATION_ID,
        'model_id': 'global.anthropic.claude-sonnet-4-5-20250929-v1:0',
        'currency': 'USD',
        'maximum_cost_usd': '0.25',
        'conservative_reservation_usd': '0.24144',
        'maximum_provider_calls': 1,
        'maximum_retries': 0,
        'maximum_request_bytes': 42020,
        'contract_sha256': INSPECTOR_CONTRACT_DIGEST.removeprefix('sha256:'),
        'input_sha256': INSPECTOR_INPUT_DIGEST.removeprefix('sha256:'),
        'reviewer_identity': SIGNERS['inspector'],
        'reviewer_receipt_publication': 'ONLY_IF_AUTHENTICATED_ACCEPTED_DECISION',
        'production_release_authorized': False,
    }
    if (not isinstance(document, dict) or
            any(document.get(key) != value for key, value in expected.items()) or
            not isinstance(document.get('authorization_text'), str) or
            not document['authorization_text'].strip() or
            not isinstance(document.get('authorized_at'), str)):
        raise StateError('Inspector live authorization differs from owner approval')
    return document


def _decode_inspector_live_plan(document, *, commit, now):
    from factory_runtime.intake import IntakePlan
    from factory_runtime.receipt_transport import receipt_plan_digest
    from factory_state.dispatch import DispatchRequest, DynamoDBDispatchStore
    from factory_state.model import Lease

    fields = {'factory_id', 'task_id', 'state', 'state_version', 'lease',
              'request', 'capability_payload', 'review_payload', 'plan_digest'}
    if (not isinstance(document, dict) or set(document) != fields or
            type(document.get('state_version')) is not int or
            not isinstance(document.get('lease'), dict) or
            not isinstance(document.get('request'), dict) or
            not isinstance(document.get('capability_payload'), dict) or
            not isinstance(document.get('review_payload'), dict)):
        raise StateError('Inspector live plan is malformed')
    try:
        lease = Lease(**{**document['lease'],
            'expires_at': datetime.fromisoformat(document['lease']['expires_at'])})
        request = DispatchRequest(**document['request'])
        plan = IntakePlan(document['factory_id'], document['task_id'], document['state'],
            document['state_version'], lease, request,
            document['capability_payload'], document['review_payload'])
    except (TypeError, ValueError, KeyError) as error:
        raise StateError('Inspector live plan is malformed') from error
    cap, review = plan.capability_payload, plan.review_payload
    expected_review_binding = DynamoDBDispatchStore._binding(request)
    if (document['plan_digest'] != receipt_plan_digest(plan) or
            (plan.factory_id, plan.task_id, plan.state) !=
                ('tims-software-factory', 'deterministic-text-fingerprint', 'IMPLEMENTATION') or
            plan.lease.role_id != 'engineering_agent' or plan.lease.revoked or
            plan.lease.authoritative_identity != SIGNERS['builder'] or
            not now < plan.lease.expires_at or
            request.source_commit != commit or
            request.contract_digest != INSPECTOR_CONTRACT_DIGEST or
            request.input_digest != INSPECTOR_INPUT_DIGEST or
            request.objective_id != 'autonomy' or request.capability_id != 'acceptance' or
            cap.get('kind') != 'capability' or cap.get('owner_identity') != 'tim_brydges' or
            cap.get('contract_digest') != INSPECTOR_CONTRACT_DIGEST or
            review.get('kind') != 'scope_review' or review.get('verdict') != 'ACCEPTED' or
            review.get('reviewer_identity') != SIGNERS['inspector'] or
            review.get('binding') != expected_review_binding):
        raise StateError('Inspector live plan differs from owner-authorized task')
    for payload in (cap, review):
        if (type(payload.get('issued_at')) is not int or
                type(payload.get('expires_at')) is not int or
                not payload['issued_at'] <= now.timestamp() < payload['expires_at'] or
                payload['expires_at'] > plan.lease.expires_at.timestamp()):
            raise StateError('Inspector live plan receipt window is invalid')
    return plan


def _validate_inspector_live_event(event, *, role, commit, now, root):
    fields = {'kind', 'source_commit', 'task_id', 'authorization_id', 'plan', 'request'}
    if (role != 'inspector' or not isinstance(event, dict) or set(event) != fields or
            event.get('kind') != 'inspector_live_review' or
            event.get('source_commit') != commit or
            event.get('task_id') != 'deterministic-text-fingerprint' or
            event.get('authorization_id') != INSPECTOR_AUTHORIZATION_ID or
            not isinstance(event.get('request'), dict)):
        raise StateError('Inspector live review event differs from owner authorization')
    authorization = _load_inspector_live_authorization(root)
    plan = _decode_inspector_live_plan(event['plan'], commit=commit, now=now)
    return authorization, plan


def handle_inspector_live_review(event, *, role, commit, signer, now, root,
                                 session, database, bedrock):
    from .inspector_budget import InspectorBudgetStore
    from .inspector_runtime import InspectorReviewRuntime
    from .receipt_transport import VersionedS3ReceiptPublisher, s3_client

    authorization, plan = _validate_inspector_live_event(
        event, role=role, commit=commit, now=now, root=root)
    policy = json.loads((root/'factory/evidence/acceptance-inspector-sonnet45-budget-policy-2026-09-30.json'
                         ).read_text(encoding='utf-8'))
    if (policy.get('model_id') != authorization['model_id'] or
            policy.get('maximum_total_cost_usd') != authorization['maximum_cost_usd'] or
            policy.get('conservative_maximum_cost_usd') !=
                authorization['conservative_reservation_usd'] or
            policy.get('maximum_provider_calls') != 1 or
            policy.get('maximum_request_bytes') != authorization['maximum_request_bytes']):
        raise StateError('Inspector budget policy differs from owner authorization')
    request_material = InspectorReviewRuntime._material(event['request'])
    if request_material.get('activation_id') != INSPECTOR_ACTIVATION_ID:
        raise StateError('Inspector activation ID differs from owner authorization')
    runtime = InspectorReviewRuntime(
        bedrock, InspectorBudgetStore('tims-factory-acceptance-budget', database))
    decision = runtime.review(
        request=event['request'], plan=plan, policy=policy, now=now)
    result = {
        'status': 'INSPECTOR_REVIEW_REJECTED',
        'plan_digest': decision.plan_digest,
        'verdict': decision.verdict,
        'rationale': decision.rationale,
        'evidence': list(decision.evidence),
        'model_id': decision.model_id,
        'input_tokens': decision.input_tokens,
        'output_tokens': decision.output_tokens,
        'total_tokens': decision.total_tokens,
        'actual_cost_usd': decision.actual_cost_usd,
        'model_calls': 1,
        'provider_calls_remaining': 0,
        'reviewer_receipt_version': None,
        'production_release_authorized': False,
        'operational_execution_enabled': False,
    }
    if decision.verdict == 'ACCEPTED':
        publication = VersionedS3ReceiptPublisher(
            s3_client(session), signer, kind='reviewer').publish(
                plan, now=now, inspector_decision=decision)
        result['status'] = 'INSPECTOR_REVIEW_ACCEPTED_AND_RECEIPT_PUBLISHED'
        result['reviewer_receipt_version'] = publication.version_id
    return result


def _transport_event(event, *, role, commit):
    if (role not in {'planner', 'builder', 'inspector'} or not isinstance(event, dict) or
            set(event) != {'kind', 'source_commit', 'nonce', 'input_base64'} or
            event['kind'] != 'transport_canary' or event['source_commit'] != commit or
            not isinstance(event['nonce'], str) or not re.fullmatch(r'[a-zA-Z0-9-]{16,64}', event['nonce']) or
            not isinstance(event['input_base64'], str) or len(event['input_base64']) > 5500):
        raise StateError('invalid bounded transport canary')
    try:
        raw = base64.b64decode(event['input_base64'], validate=True)
    except (ValueError, TypeError) as error:
        raise StateError('invalid transport canary input') from error
    if len(raw) > MAX_CANARY_INPUT:
        raise StateError('transport canary input exceeds limit')
    return raw


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _builder_activation(root, commit, raw, now):
    """Load deployment-owned activation data, never from the dispatched event."""
    from .autonomy import AutonomyActivation
    from .autonomy_contract import load_autonomy_operating_allowance
    from .acceptance_broker import BROKER_ARN

    if not isinstance(raw, str) or not 0 < len(raw) <= 2048:
        raise StateError('Builder activation deployment is missing')
    try:
        config = json.loads(raw)
        fields = {'activation_id', 'factory_id', 'task_id', 'source_commit',
                  'contract_digest', 'starts_at', 'expires_at', 'broker_version_arn'}
        if not isinstance(config, dict) or set(config) != fields:
            raise ValueError('invalid activation fields')
        activation = AutonomyActivation(config['activation_id'], config['factory_id'],
            config['task_id'], config['source_commit'], config['contract_digest'],
            datetime.fromisoformat(config['starts_at']), datetime.fromisoformat(config['expires_at']))
        broker_arn = config['broker_version_arn']
    except (ValueError, TypeError, KeyError) as error:
        raise StateError('Builder activation deployment is invalid') from error
    allowance = load_autonomy_operating_allowance(root)
    if (not allowance.activation_ready or allowance.production_release_authorized or
            activation.factory_id != 'tims-software-factory' or
            activation.task_id != allowance.acceptance_task_id or
            activation.source_commit != commit or
            activation.contract_digest != 'sha256:' + allowance.acceptance_contract_sha256 or
            not isinstance(broker_arn, str) or not BROKER_ARN.fullmatch(broker_arn)):
        raise StateError('Builder activation differs from owner-approved deployment')
    activation.validate(now)
    if not allowance.pricing_observed_at <= now < allowance.pricing_expires_at:
        raise StateError('Builder acceptance pricing is stale')
    return activation, broker_arn


def _builder_service(root, commit, activation, broker_arn, signer, database, lambda_api):
    """Compose the credential-free role with its independent budget and broker."""
    from .acceptance_broker import AcceptanceBrokerExecutor
    from .acceptance_budget import DynamoDBAcceptanceBudgetStore
    from .cloud_roles import RoleExecutionService
    from .operational_backend import AcceptanceOperationalBackend
    from factory_state.dispatch import DynamoDBDispatchStore
    from factory_state.dynamodb import DynamoDBStateStore
    from factory_state.signers import load_trusted_signers

    clock = lambda: datetime.now(timezone.utc)
    state_table = 'tims-software-factory-state'
    ledger = DynamoDBDispatchStore(state_table, database)
    backend = AcceptanceOperationalBackend(root, activation,
        DynamoDBAcceptanceBudgetStore('tims-factory-acceptance-budget', database),
        AcceptanceBrokerExecutor(lambda_api, broker_arn), enabled=True, clock=clock)
    return RoleExecutionService(DynamoDBStateStore(state_table, database), ledger,
        execution_table='tims-factory-role-executions', deployed_commit=commit,
        identity=SIGNERS['builder'],
        key_loader=lambda now: load_trusted_signers(
            root/'factory/profiles/scope-signers.json', now=now),
        signer=signer, backend=backend, clock=clock)


def handle_transport(event, *, role, commit, signer, now, database, table):
    raw = _transport_event(event, role=role, commit=commit)
    identity = SIGNERS[role]
    if signer.identity != identity or not isinstance(table, str) or not table:
        raise StateError('transport canary deployment mismatch')
    key = {'PK': {'S': f'ROLE#{identity}#FACTORY#tims-software-factory#TASK#cloud-role-canary-{event["nonce"]}'},
           'SK': {'S': 'EXECUTION#transport-canary'}}
    event_digest = _digest(canonical(event))
    item = {**key, 'status': {'S': 'STARTED'}, 'event_digest': {'S': event_digest},
            'identity': {'S': identity}, 'model_calls': {'N': '0'}}
    try:
        database.put_item(TableName=table, Item=item,
            ConditionExpression='attribute_not_exists(PK) AND attribute_not_exists(SK)')
    except Exception as error:
        if getattr(error, 'response', {}).get('Error', {}).get('Code') != 'ConditionalCheckFailedException':
            raise
        prior = database.get_item(TableName=table, Key=key, ConsistentRead=True).get('Item', {})
        if (prior.get('event_digest') != {'S': event_digest} or prior.get('identity') != {'S': identity}):
            raise StateError('transport canary binding conflict') from error
        if prior.get('status') != {'S': 'COMPLETE'} or 'response' not in prior:
            raise StateError('transport canary outcome unknown') from error
        return json.loads(prior['response']['S'])
    output = canonical({'input_digest': _digest(raw), 'role': role, 'status': 'transport_verified'})
    payload = {'kind': 'transport_result', 'producer_identity': identity,
        'source_commit': commit, 'nonce': event['nonce'], 'input_digest': _digest(raw),
        'output_digest': _digest(output), 'purpose': 'lambda-transport-canary-only',
        'issued_at': int(now.timestamp()), 'expires_at': int(now.timestamp()) + 300}
    response = {'payload': payload, 'signature_base64': base64.b64encode(
        signer.sign(payload, now=now)).decode(), 'output_base64': base64.b64encode(output).decode(),
        'model_calls': 0, 'operational_execution_enabled': False}
    database.update_item(TableName=table, Key=key,
        UpdateExpression='SET #s=:done, #r=:response',
        ConditionExpression='#s=:started AND event_digest=:digest AND #i=:identity',
        ExpressionAttributeNames={'#s': 'status', '#r': 'response', '#i': 'identity'},
        ExpressionAttributeValues={':done': {'S': 'COMPLETE'}, ':started': {'S': 'STARTED'},
            ':response': {'S': canonical(response).decode()}, ':digest': {'S': event_digest},
            ':identity': {'S': identity}})
    return response


def handler(event, context):
    root = Path(os.environ.get('LAMBDA_TASK_ROOT', '/var/task'))
    commit = json.loads((root/'BUILD.json').read_text())['source_commit']
    role = os.environ['FACTORY_ROLE']
    if role not in {'planner', 'builder', 'inspector'}:
        raise StateError('invalid deployed role')
    operational = os.environ.get(OPERATIONAL_FLAG)
    if operational == 'true':
        if role != 'builder':
            raise StateError('only Builder can execute the acceptance task')
        activation, broker_arn = _builder_activation(
            root, commit, os.environ.get(ACTIVATION_CONFIG), datetime.now(timezone.utc))
    elif operational == 'false':
        if not isinstance(event, dict) or event.get('kind') not in {
                'identity_probe', 'transport_canary', 'operational_boundary_probe',
                'inspector_runtime_boundary_probe', 'inspector_live_review'}:
            raise StateError('unsupported role invocation')
        if event['kind'] == 'identity_probe':
            validate_probe(event, role=role, commit=commit)
        elif event['kind'] == 'transport_canary':
            _transport_event(event, role=role, commit=commit)
        elif event['kind'] == 'inspector_runtime_boundary_probe':
            if role != 'inspector':
                raise StateError('Inspector runtime boundary probe requires Inspector role')
        elif event['kind'] == 'inspector_live_review':
            _validate_inspector_live_event(
                event, role=role, commit=commit, now=datetime.now(timezone.utc), root=root)
    else:
        raise StateError('operational role kill switch is invalid')
    import boto3
    from botocore.config import Config
    config = Config(connect_timeout=3, read_timeout=5, retries={'total_max_attempts': 1, 'mode': 'standard'})
    # Execution credentials cannot sign or modify controller state. A short-lived
    # role-specific signing session has no state, provider or deployment rights.
    sts = boto3.client('sts', region_name='ca-central-1', config=config)
    response = sts.assume_role(RoleArn=f'arn:aws:iam::666730517561:role/tims-factory-signing-{role}',
        RoleSessionName=f'lambda-{role}-{context.aws_request_id}', DurationSeconds=900)
    creds = response['Credentials']
    session = boto3.Session(aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'],
                            aws_session_token=creds['SessionToken'], region_name='ca-central-1')
    signer = EnrolledKmsReceiptSigner(session.client('kms', config=config), session.client('sts', config=config),
        signer=role, registry_path=root/'factory/profiles/scope-signers.json',
        bindings_path=root/'factory/profiles/kms-signers.json')
    now = datetime.now(timezone.utc)
    if operational == 'true':
        from .cloud_roles import lambda_client
        service = _builder_service(root, commit, activation, broker_arn, signer,
            boto3.client('dynamodb', region_name='ca-central-1', config=config),
            lambda_client(boto3.Session(region_name='ca-central-1')))
        return service.handle(event)
    if event['kind'] == 'identity_probe':
        return handle_probe(event, role=role, commit=commit, signer=signer, now=now)
    if event['kind'] == 'operational_boundary_probe':
        return handle_operational_boundary_probe(
            event, role=role, commit=commit, signer=signer, now=now, root=root)
    if event['kind'] == 'inspector_runtime_boundary_probe':
        return handle_inspector_runtime_boundary_probe(
            event, role=role, commit=commit, signer=signer, now=now, root=root)
    if event['kind'] == 'inspector_live_review':
        review_config = Config(connect_timeout=3, read_timeout=105,
            retries={'total_max_attempts': 1, 'mode': 'standard'})
        return handle_inspector_live_review(
            event, role=role, commit=commit, signer=signer, now=now, root=root,
            session=session,
            database=boto3.client('dynamodb', region_name='ca-central-1', config=config),
            bedrock=boto3.client('bedrock-runtime', region_name='ca-central-1',
                                config=review_config))
    database = boto3.client('dynamodb', region_name='ca-central-1', config=config)
    return handle_transport(event, role=role, commit=commit, signer=signer, now=now,
        database=database, table=os.environ['EXECUTION_TABLE'])
