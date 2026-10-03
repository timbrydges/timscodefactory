"""Validate persisted unsigned Google results without inventing a raw response."""
import json

from factory_state.model import StateError
from factory_state.scope import canonical
from .google_qa import MODEL, MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS, request_body
from .review_preparation import BINDING, parse_assessment


def parse_record(raw, packet, *, root):
    request_body(packet, root=root)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise StateError('duplicate stored Google response field')
            result[key] = value
        return result
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 20000:
        raise StateError('stored Google response size invalid')
    try:
        value = json.loads(raw, object_pairs_hook=unique)
        expected = {'assessment', 'provider_family', 'model_id', 'input_tokens',
                    'output_tokens_including_thinking', 'status', 'gate_authority'}
        if (not isinstance(value, dict) or set(value) != expected or
                value['provider_family'] != 'google' or value['model_id'] != MODEL or
                value['status'] != 'UNAUTHENTICATED_PROVIDER_RESPONSE' or value['gate_authority'] is not False or
                type(value['input_tokens']) is not int or not 0 <= value['input_tokens'] <= MAX_INPUT_TOKENS or
                type(value['output_tokens_including_thinking']) is not int or
                not 0 <= value['output_tokens_including_thinking'] <= MAX_OUTPUT_TOKENS):
            raise StateError('stored Google response binding differs')
        assessment = value['assessment']
        fields = (*BINDING, 'verdict', 'rationale', 'findings')
        parsed = parse_assessment(canonical({k: assessment[k] for k in fields}), packet, root=root)
        if canonical(parsed) != canonical(assessment):
            raise StateError('stored Google assessment differs')
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise StateError('stored Google response malformed') from None
