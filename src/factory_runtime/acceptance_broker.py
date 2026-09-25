"""Credential-free Builder client for the exact acceptance provider broker.

The isolated broker Lambda is not deployed here. Its published version and IAM
grant must be reviewed separately; the operational backend remains disabled.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from factory_state.model import COMMIT_SHA, SAFE_IDENTIFIER, SHA256_DIGEST, StateError
from factory_state.scope import canonical


BROKER_ARN = re.compile(
    r'^arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-provider-broker:([1-9][0-9]*)$'
)
MAX_INPUT = 42020
MAX_RESPONSE = 128 * 1024


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StateError('duplicate acceptance broker response field')
        result[key] = value
    return result


@dataclass
class AcceptanceBrokerExecutor:
    """Invoke one pinned, authenticated broker version without implicit retries."""

    client: object
    function_arn: str

    def __post_init__(self):
        match = BROKER_ARN.fullmatch(self.function_arn) if isinstance(self.function_arn, str) else None
        if not match:
            raise StateError('acceptance broker requires a pinned approved Lambda version')
        if (self.client.meta.config.retries.get('total_max_attempts') != 1 or
                self.client.meta.endpoint_url != 'https://lambda.ca-central-1.amazonaws.com'):
            raise StateError('acceptance broker client requires the regional endpoint and no retries')
        self.version = match.group(1)

    def execute(self, *, activation_id: str, dispatch_id: str, source_commit: str,
                contract_digest: str, task_id: str, target_alias: str, model_id: str,
                input_bytes: bytes, maximum_cost_usd: Decimal) -> bytes:
        if (not isinstance(activation_id, str) or not SAFE_IDENTIFIER.fullmatch(activation_id) or
                not isinstance(dispatch_id, str) or not SAFE_IDENTIFIER.fullmatch(dispatch_id) or
                not isinstance(source_commit, str) or not COMMIT_SHA.fullmatch(source_commit) or
                not isinstance(contract_digest, str) or not SHA256_DIGEST.fullmatch(contract_digest) or
                task_id != 'deterministic-text-fingerprint' or
                target_alias != 'coding_primary_sol_live' or model_id != 'gpt-5.6-sol' or
                not isinstance(maximum_cost_usd, Decimal) or maximum_cost_usd != Decimal('0.25') or
                not isinstance(input_bytes, bytes) or len(input_bytes) > MAX_INPUT):
            raise StateError('acceptance broker request differs from owner-approved task and budget')
        digest = 'sha256:' + hashlib.sha256(input_bytes).hexdigest()
        event = {'schema_version': '1.0', 'kind': 'acceptance_provider_call',
                 'activation_id': activation_id, 'dispatch_id': dispatch_id,
                 'source_commit': source_commit, 'contract_digest': contract_digest,
                 'task_id': task_id, 'target_alias': target_alias, 'model_id': model_id,
                 'maximum_cost_usd': '0.25', 'input_digest': digest,
                 'input_base64': base64.b64encode(input_bytes).decode()}
        response = self.client.invoke(FunctionName=self.function_arn,
            InvocationType='RequestResponse', LogType='None', Payload=canonical(event))
        stream = response.get('Payload')
        try:
            if (response.get('StatusCode') != 200 or 'FunctionError' in response or
                    response.get('ExecutedVersion') != self.version or stream is None):
                raise StateError('acceptance broker invocation outcome unknown')
            raw = stream.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise StateError('acceptance broker response exceeds limit')
            try:
                reply = json.loads(raw, object_pairs_hook=_unique)
            except (ValueError, TypeError) as error:
                raise StateError('invalid acceptance broker response') from error
            bindings = ('activation_id', 'dispatch_id', 'source_commit', 'contract_digest',
                        'task_id', 'target_alias', 'model_id', 'input_digest')
            if (not isinstance(reply, dict) or set(reply) != set(bindings) | {
                    'output_base64', 'output_digest', 'cost_usd', 'provider_calls'} or
                    any(reply.get(key) != event[key] for key in bindings) or
                    type(reply.get('provider_calls')) is not int or reply['provider_calls'] != 1):
                raise StateError('acceptance broker response binding differs')
            try:
                cost = Decimal(reply['cost_usd']) if isinstance(reply['cost_usd'], str) else None
            except InvalidOperation as error:
                raise StateError('acceptance broker cost is invalid') from error
            if cost is None or not cost.is_finite() or not 0 <= cost <= maximum_cost_usd:
                raise StateError('acceptance broker cost exceeds approved allowance')
            encoded = reply['output_base64']
            if not isinstance(encoded, str) or len(encoded) > ((65536 + 2) // 3) * 4:
                raise StateError('acceptance broker output exceeds limit')
            try:
                output = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as error:
                raise StateError('invalid acceptance broker output') from error
            if (len(output) > 65536 or reply['output_digest'] !=
                    'sha256:' + hashlib.sha256(output).hexdigest()):
                raise StateError('acceptance broker output digest differs')
            return output
        finally:
            if stream is not None:
                stream.close()
