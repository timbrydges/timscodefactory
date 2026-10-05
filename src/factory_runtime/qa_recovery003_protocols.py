"""Exact, offline Gemini 3.7 QA codec. No transport or automatic model fallback."""
from factory_state.model import StateError
from factory_state.scope import canonical
from .qa_recovery003_packets import review_packet,parse_review
from .pilot002_protocols import _decode,_google,MAX_INPUT_TOKENS,MAX_OUTPUT_TOKENS,MAX_RESPONSE_BYTES


def _packet(root,role,builder_response,candidate_commit):
    return review_packet(root,role=role,builder_response=builder_response,candidate_commit=candidate_commit)


def request_bytes(root,*,role,builder_response=None,candidate_commit=None):
    packet=_packet(root,role,builder_response,candidate_commit)
    body={'systemInstruction':{'parts':[{'text':packet['instructions']}]},
        'contents':[{'role':'user','parts':[{'text':canonical(packet).decode('utf-8')}]}],
        'generationConfig':{'candidateCount':1,'maxOutputTokens':MAX_OUTPUT_TOKENS,
            'responseMimeType':'application/json','thinkingConfig':{'thinkingLevel':'LOW','includeThoughts':False}}}
    raw=canonical(body)
    if len(raw)>65536:raise StateError('Recovery 003 request exceeds bound')
    return raw


def parse_response(raw,root,*,role,builder_response=None,candidate_commit=None):
    packet=_packet(root,role,builder_response,candidate_commit)
    try:
        text,usage=_google(_decode(raw),packet['model_id'])
        if not isinstance(text,str):raise ValueError('text required')
        output=text.encode('utf-8')
        parsed=parse_review(output,root=root,role=role,builder_response=builder_response,candidate_commit=candidate_commit)
    except (StateError,ValueError,TypeError,KeyError,AttributeError,RecursionError,UnicodeError):
        raise StateError('Recovery 003 provider envelope, usage or task output rejected') from None
    return {'status':'UNAUTHENTICATED_PROVIDER_RESPONSE','role':role,'requested_model_id':packet['model_id'],
        'provider_identity_verified':False,'usage':usage,'output_bytes':output,'parsed_output':parsed,
        'gate_authority':False,'production_release_authorized':False}
