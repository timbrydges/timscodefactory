"""Trusted one-attempt task composition; no external IO on construction.

Only the operator supplies approval and source pins. No dynamic plugins, commands,
credential lookup names or cloud adapters are accepted from the task queue.
"""
from decimal import Decimal
import json
from .development_profile import TaskExecutionProfile
from factory_state.model import StateError
from .development_approval import compose_approved_host
from .diagnostics import RedactedDiagnosticCapture
from .docker_sandbox import DockerSandboxAdapter, DockerSandboxPolicy
from .openai_provider import OpenAIResponsesProviderInvoker, OpenAIProviderPolicy
from .provider_broker_service import ResolvedProviderTarget
from .provider_credentials import EnvironmentProviderCredentialLeaseSource
from .provider_http_transport import DirectOpenAITransport
from .workload_identity_response import RenewableCredentialBinding


# The repository's own CI gates, run offline against dependencies baked into the
# pinned check image at /deps (scripts/build_bonus_check_image.py), followed by the
# builder's tests and the contract-owned acceptance tests. Paths are fixed here.
RESPONSE_LIMIT = 1024 * 1024


def bonus_repository_checks(builder_test, acceptance_tests):
    return ('sh', '-c',
        'ln -s /deps/node_modules node_modules'
        ' && NEXT_TELEMETRY_DISABLED=1 ./node_modules/.bin/next typegen'
        ' && ./node_modules/.bin/tsc --noEmit'
        ' && ./node_modules/.bin/eslint'
        ' && node --experimental-strip-types --test ' + ' '.join((builder_test, *acceptance_tests)))


BONUS_REPOSITORY_CHECKS = bonus_repository_checks('tests/library-pagination.test.mjs',
    ('tests/factory-acceptance/library-pagination.acceptance.test.mjs',))

# Trusted per-task profiles: required changed paths and the exact sandbox command.
BONUS_TASKS = {
    'bonus-library-pagination': (
        ('src/app/dashboard/page.tsx', 'src/lib/library-pagination.ts',
         'tests/library-pagination.test.mjs'),
        BONUS_REPOSITORY_CHECKS),
    'bonus-library-search': (
        ('src/app/dashboard/page.tsx', 'src/lib/library-search.ts',
         'tests/library-search.test.mjs'),
        bonus_repository_checks('tests/library-search.test.mjs',
            ('tests/factory-acceptance/library-search.acceptance.test.mjs',))),
    'bonus-library-ai-cover-prompt': (
        ('src/lib/ai-cover.ts', 'tests/ai-cover.test.mjs'),
        bonus_repository_checks('tests/ai-cover.test.mjs',
            ('tests/factory-acceptance/ai-cover.acceptance.test.mjs',))),
}


def compose_bonus_host(directory, *, approval, expected_pins, receipt_path,
                       task, contract_bytes, snapshot, pricing_source, clock,
                       owner_authorized=False):
    if owner_authorized is not True:
        raise StateError('explicit human authorization required')
    pins = expected_pins
    if (pins['credential_source'] != 'env:FACTORY_OPENAI_API_KEY'
            or pins['model_id'] != 'gpt-5.6-sol'
            or pins['repository'] != 'timbrydges/bonus-library'
            or task.task_id not in BONUS_TASKS):
        raise StateError('unsupported acceptance composition')
    required, command = BONUS_TASKS[task.task_id]
    spec = json.loads(contract_bytes)
    # The fixed command must run exactly the contract's acceptance tests.
    if any(item['path'] not in command[2] for item in spec.get('acceptance_tests', [])):
        raise StateError('contract acceptance tests differ from the trusted profile')
    return _compose_host(directory, approval=approval, expected_pins=pins,
        receipt_path=receipt_path, task=task, contract_bytes=contract_bytes,
        snapshot=snapshot, pricing_source=pricing_source, clock=clock,
        profile=TaskExecutionProfile('timbrydges/bonus-library', task.task_id, required,
                                     command, timeout_seconds=60),
        bind_profile=False)


def compose_task_host(directory, *, profile, approval, expected_pins, receipt_path,
                      task, contract_bytes, snapshot, pricing_source, clock,
                      owner_authorized=False, credential_binding=None):
    # Profile must be supplied by the trusted operator, never generated task text.
    if owner_authorized is not True or type(profile) is not TaskExecutionProfile:
        raise StateError('explicit human authorization and trusted profile required')
    if expected_pins.get('model_id') != 'gpt-5.6-sol':
        raise StateError('unsupported provider composition')
    credential = None
    if credential_binding is None:
        if expected_pins.get('credential_source') != 'env:FACTORY_OPENAI_API_KEY':
            raise StateError('explicit renewable credential binding required')
    else:
        if (type(credential_binding) is not RenewableCredentialBinding
                or expected_pins.get('credential_source') != credential_binding.source_pin
                or credential_binding.ledger.authorization.target != ResolvedProviderTarget(
                    'openai', expected_pins['model_id'], 'development-pinned-v1')):
            raise StateError('credential binding differs from approved source')
        credential = credential_binding.compose(clock=clock)
    profile.validate_binding(pins=expected_pins, task=task, contract_bytes=contract_bytes)
    return _compose_host(directory, approval=approval, expected_pins=expected_pins,
        receipt_path=receipt_path, task=task, contract_bytes=contract_bytes,
        snapshot=snapshot, pricing_source=pricing_source, clock=clock,
        profile=profile, bind_profile=True, credential=credential)


def _compose_host(directory, *, approval, expected_pins, receipt_path, task,
                  contract_bytes, snapshot, pricing_source, clock, profile, bind_profile,
                  credential=None):
    pins = expected_pins
    policy = DockerSandboxPolicy(image_ref=pins['image_ref'])
    if credential is None:
        credential = EnvironmentProviderCredentialLeaseSource()
    # Response size does not change spend (output tokens are capped); a larger limit
    # keeps an already-billed complete-file proposal parseable and reconcilable.
    transport = DirectOpenAITransport(enabled=True,
        max_request_bytes=pins['max_request_bytes'], max_response_bytes=RESPONSE_LIMIT)
    def adapter(workload):
        return OpenAIResponsesProviderInvoker(credential, pricing_source, transport,
            policy=OpenAIProviderPolicy(live_enabled=True, workload=workload,
                max_request_bytes=pins['max_request_bytes'], max_response_bytes=RESPONSE_LIMIT,
                timeout_seconds=180,
                # Bounded acceptance attempt: reserve more of the unchanged
                # output allowance for the structured decision rather than reasoning.
                # This behavior is bound by the approved source commit.
                reasoning_effort='low',
                # Review returns a verdict/findings, not a full implementation.
                # Its smaller output allowance leaves room for before/after input.
                max_output_tokens=(min(pins['max_output_tokens'], 4096)
                    if workload == 'task_review' else pins['max_output_tokens'])))
    command = profile.test_command
    delivery = profile.delivery
    def request(candidate):
        return candidate.request(request_id='task-tests' if bind_profile else 'pagination-tests', lease_id=task.activation_id,
            role_id='isolated-tests', command=command,
            environment_digest=policy.environment_digest, timeout_seconds=profile.timeout_seconds,
            expected_runner_identity=policy.runner_identity)
    capture = RedactedDiagnosticCapture()
    return compose_approved_host(directory, approval=approval, expected_pins=pins,
        receipt_path=receipt_path, now=clock(), owner_authorized=True,
        task=task, contract_bytes=contract_bytes, snapshot=snapshot,
        builder=adapter('task_implementation'), reviewer=adapter('task_review'),
        target=ResolvedProviderTarget(provider_family='openai', model_id=pins['model_id'],
                                      selector_version='development-pinned-v1'),
        builder_cap=Decimal(pins['builder_cap']), reviewer_cap=Decimal(pins['reviewer_cap']),
        total_cap=Decimal(pins['total_cap']), request_for=request,
        sandbox_for=lambda candidate: DockerSandboxAdapter(candidate.workspace, policy,
                                                           diagnostic_capture=capture),
        diagnostics=capture,
        clock=clock, delivery=delivery,
        **({'execution_profile': profile} if bind_profile else {}))
