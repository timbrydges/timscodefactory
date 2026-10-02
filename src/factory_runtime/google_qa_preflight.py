"""Non-generating Google qualification. Preparation never grants permission."""
import hashlib
import json
import ssl
import urllib.error
import urllib.request

from factory_state.model import StateError
from factory_state.scope import canonical
from .google_qa import MODEL, MAX_INPUT_TOKENS, MAX_OUTPUT_TOKENS, NoRedirect, request_body
from .review_preparation import prepare

MODEL_URL = 'https://generativelanguage.googleapis.com/v1beta/models/' + MODEL
COUNT_URL = MODEL_URL + ':countTokens'
LIMIT = 65536


def build(root):
    packet = prepare(root, role='qa')
    generation = request_body(packet, root=root)
    count = canonical({'generateContentRequest': {
        'model': 'models/' + MODEL, **json.loads(generation)}})
    return {'status': 'PREPARED_NOT_AUTHORIZED', 'model_id': MODEL,
        'metadata_endpoint': MODEL_URL, 'count_endpoint': COUNT_URL,
        'packet_digest': packet['packet_digest'],
        'generation_request_sha256': hashlib.sha256(generation).hexdigest(),
        'count_request_sha256': hashlib.sha256(count).hexdigest(),
        'count_request_bytes': len(count), 'count_request': json.loads(count),
        'maximum_http_requests': 2, 'retries': 0, 'generation_calls': 0,
        'disclosure': 'Candidate source, tests, contract, review instructions and schema to Google Gemini API',
        'google_project': 'gen-lang-client-0247455615', 'observed_tier': 'Free tier',
        'approval_required': True, 'gate_authority': False}


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise StateError('duplicate Google preflight response field')
            value[key] = item
        return value
    if not isinstance(raw, bytes) or not 0 < len(raw) <= LIMIT:
        raise StateError('Google preflight response size invalid')
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise StateError('Google preflight response malformed') from None
    if not isinstance(value, dict):
        raise StateError('Google preflight response must be an object')
    return value


def validate_model(raw):
    value = decode(raw)
    methods = value.get('supportedGenerationMethods')
    if (value.get('name') != 'models/' + MODEL or
            not isinstance(methods, list) or 'generateContent' not in methods or
            type(value.get('inputTokenLimit')) is not int or
            type(value.get('outputTokenLimit')) is not int or
            value['inputTokenLimit'] < MAX_INPUT_TOKENS or
            value['outputTokenLimit'] < MAX_OUTPUT_TOKENS):
        raise StateError('Google model identity, method or token limits differ')
    return {k: value[k] for k in ('name', 'inputTokenLimit', 'outputTokenLimit')}


def validate_count(raw):
    value = decode(raw)
    count = value.get('totalTokens')
    if (type(count) is not int or not 0 < count <= MAX_INPUT_TOKENS or
            type(value.get('cachedContentTokenCount', 0)) is not int or
            value.get('cachedContentTokenCount', 0) != 0):
        raise StateError('Google input tokens outside limit or cached')
    return count


class PreflightTransport:
    """One GET then one token-count POST; no generation endpoint or retries."""
    def __init__(self, *, opener=None):
        self.attempted = False
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

    def run_once(self, *, root, api_key):
        plan = build(root)
        if (not isinstance(api_key, str) or not 16 <= len(api_key) <= 256 or
                any(ord(c) < 33 or ord(c) > 126 for c in api_key)):
            raise StateError('Google credential invalid')
        if self.attempted:
            raise StateError('Preflight attempted; reconcile without retry')
        self.attempted = True

        def call(url, body=None):
            request = urllib.request.Request(url, data=body,
                method='GET' if body is None else 'POST',
                headers={'x-goog-api-key': api_key, 'Content-Type': 'application/json',
                         'Accept': 'application/json'})
            try:
                with self.opener.open(request, timeout=30) as response:
                    if response.status != 200:
                        raise StateError('Google preflight returned non-success')
                    return response.read(LIMIT + 1)
            except (urllib.error.URLError, TimeoutError, OSError):
                raise StateError('Google preflight failed; do not retry') from None

        model = validate_model(call(MODEL_URL))
        tokens = validate_count(call(COUNT_URL, canonical(plan['count_request'])))
        return {'status': 'PREFLIGHT_OBSERVED_NOT_GENERATION_AUTHORIZED',
            'model': model, 'input_tokens': tokens,
            'count_request_sha256': plan['count_request_sha256'],
            'generation_request_sha256': plan['generation_request_sha256'],
            'http_requests': 2, 'generation_calls': 0, 'retries': 0,
            'output_thinking_cap_qualified': False, 'budget_reserved': False,
            'gate_authority': False}
