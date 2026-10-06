"""Offline codecs for the fresh contract; no transport or credential access."""
from factory_state.model import StateError
from . import handoff001_packets as packets
from .pilot002_protocols import serialize_packet, _decode, _openai, _bedrock, _google


def packet(root, *, role, builder_response=None, candidate_commit=None):
    if role == 'builder':
        if builder_response is not None or candidate_commit is not None:
            raise StateError('Builder cannot substitute review material')
        return packets.builder_packet(root)
    return packets.review_packet(root, role=role, builder_response=builder_response,
                                 candidate_commit=candidate_commit)


def request_bytes(root, **context):
    value = packet(root, **context)
    return serialize_packet(value, role=value['role'])


def parse_response(raw, root, *, role, builder_response=None, candidate_commit=None):
    value = packet(root, role=role, builder_response=builder_response, candidate_commit=candidate_commit)
    try:
        response = _decode(raw)
        text, usage = (_openai(response, value['model_id']) if role == 'builder' else
            _bedrock(response) if role == 'inspector' else _google(response, value['model_id']))
        if not isinstance(text, str): raise ValueError('text required')
        output = text.encode('utf-8')
        parsed = (packets.parse_builder(output, root=root) if role == 'builder' else
            packets.parse_review(output, root=root, role=role, builder_response=builder_response,
                                 candidate_commit=candidate_commit))
    except (StateError, ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError):
        raise StateError('Handoff provider envelope, usage or task output rejected') from None
    return {'status': 'UNAUTHENTICATED_PROVIDER_RESPONSE', 'role': role,
        'requested_model_id': value['model_id'], 'provider_identity_verified': False,
        'usage': usage, 'output_bytes': output, 'parsed_output': parsed,
        'gate_authority': False, 'production_release_authorized': False}
