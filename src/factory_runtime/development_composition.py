"""Trusted one-attempt Bonus Library composition; no external IO on construction.

Only the operator supplies approval and source pins. No dynamic plugins, commands,
credential lookup names or cloud adapters are accepted from the task queue.
"""
from decimal import Decimal
from factory_state.model import StateError
from .development_approval import compose_approved_host
from .docker_sandbox import DockerSandboxAdapter, DockerSandboxPolicy
from .openai_provider import OpenAIResponsesProviderInvoker, OpenAIProviderPolicy
from .provider_broker_service import ResolvedProviderTarget
from .provider_credentials import EnvironmentProviderCredentialLeaseSource
from .provider_http_transport import DirectOpenAITransport


def compose_bonus_host(directory, *, approval, expected_pins, receipt_path,
                       task, contract_bytes, snapshot, pricing_source, clock,
                       owner_authorized=False):
    if owner_authorized is not True:
        raise StateError('explicit human authorization required')
    pins = expected_pins
    if (pins['credential_source'] != 'env:FACTORY_OPENAI_API_KEY'
            or pins['model_id'] != 'gpt-5.6-sol'
            or pins['repository'] != 'timbrydges/bonus-library'
            or task.task_id != 'bonus-library-pagination'):
        raise StateError('unsupported acceptance composition')
    policy = DockerSandboxPolicy(image_ref=pins['image_ref'])
    credential = EnvironmentProviderCredentialLeaseSource()
    transport = DirectOpenAITransport(enabled=True,
        max_request_bytes=pins['max_request_bytes'])
    def adapter(workload):
        return OpenAIResponsesProviderInvoker(credential, pricing_source, transport,
            policy=OpenAIProviderPolicy(live_enabled=True, workload=workload,
                max_request_bytes=pins['max_request_bytes'],
                timeout_seconds=180,
                max_output_tokens=pins['max_output_tokens']))
    def request(candidate):
        return candidate.request(request_id='pagination-tests', lease_id=task.activation_id,
            role_id='isolated-tests', command=('node', '--experimental-strip-types',
                '--test', 'tests/library-pagination.test.mjs'),
            environment_digest=policy.environment_digest, timeout_seconds=60,
            expected_runner_identity=policy.runner_identity)
    return compose_approved_host(directory, approval=approval, expected_pins=pins,
        receipt_path=receipt_path, now=clock(), owner_authorized=owner_authorized,
        task=task, contract_bytes=contract_bytes, snapshot=snapshot,
        builder=adapter('task_implementation'), reviewer=adapter('task_review'),
        target=ResolvedProviderTarget(provider_family='openai', model_id=pins['model_id'],
                                      selector_version='development-pinned-v1'),
        builder_cap=Decimal(pins['builder_cap']), reviewer_cap=Decimal(pins['reviewer_cap']),
        total_cap=Decimal(pins['total_cap']), request_for=request,
        sandbox_for=lambda candidate: DockerSandboxAdapter(candidate.workspace, policy),
        clock=clock)
