"""Offline provider codecs, not transports or authenticated billing evidence."""
import json

from factory_state.model import StateError
from factory_state.scope import canonical
from .pilot002_packets import builder_packet, review_packet, parse_builder, parse_review

MAX_INPUT_TOKENS = 32768
MAX_OUTPUT_TOKENS = 4096
MAX_RESPONSE_BYTES = 262144


def _packet(root, role, builder_response, candidate_commit):
    if role == 'builder':
        if builder_response is not None or candidate_commit is not None:
            raise StateError('Builder cannot accept review context')
        return builder_packet(root)
    return review_packet(root, role=role, builder_response=builder_response, candidate_commit=candidate_commit)


def request_bytes(root, *, role, builder_response=None, candidate_commit=None):
    """Complete JSON body (OpenAI/Google) or canonical Converse SDK arguments.

The reviewed transport must bind the fixed endpoint/model, exact bytes and
one-attempt allowance. This function has no credentials or network operations.
"""
    packet = _packet(root, role, builder_response, candidate_commit)
    return serialize_packet(packet, role=role)


def serialize_packet(packet, *, role):
    """Pure serialization of a deployment-built packet; no authorization."""
    if role not in ('builder', 'inspector', 'qa') or packet.get('role') != role:
        raise StateError('Provider packet role differs')
    material = canonical(packet).decode('utf-8')
    instruction = packet['instructions']
    if role == 'builder':
        body = {'model':packet['model_id'], 'store':False, 'background':False,
            'stream':False, 'tools':[], 'service_tier':'default', 'truncation':'disabled',
            'prompt_cache_options':{'mode':'explicit'},
            'instructions':instruction, 'input':material, 'max_output_tokens':MAX_OUTPUT_TOKENS,
            'reasoning':{'effort':'low'}, 'text':{'format':{'type':'json_object'}}}
    elif role == 'inspector':
        body = {'modelId':packet['model_id'], 'system':[{'text':instruction}],
            'messages':[{'role':'user','content':[{'text':material}]}],
            'inferenceConfig':{'maxTokens':MAX_OUTPUT_TOKENS,'temperature':0}}
    else:
        body = {'systemInstruction':{'parts':[{'text':instruction}]},
            'contents':[{'role':'user','parts':[{'text':material}]}],
            'generationConfig':{'candidateCount':1,'maxOutputTokens':MAX_OUTPUT_TOKENS,
                'responseMimeType':'application/json',
                'thinkingConfig':{'thinkingLevel':'LOW','includeThoughts':False}}}
    raw = canonical(body)
    if len(raw)>65536:raise StateError('Pilot 002 complete provider request exceeds byte bound')
    return raw


def _decode(raw):
    if not isinstance(raw,bytes) or not 0<len(raw)<=MAX_RESPONSE_BYTES:
        raise StateError('Pilot 002 provider response size invalid')
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate')
            value[key]=item
        return value
    def invalid(_):raise ValueError('nonfinite')
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=unique,parse_constant=invalid)
    canonical(value)
    if not isinstance(value,dict):raise ValueError('object required')
    return value


def _count(value, maximum):
    if type(value) is not int or not 0<=value<=maximum:raise ValueError('invalid token count')
    return value


def _usage(input_tokens, output_tokens, total):
    i=_count(input_tokens,MAX_INPUT_TOKENS);o=_count(output_tokens,MAX_OUTPUT_TOKENS)
    if _count(total,MAX_INPUT_TOKENS+MAX_OUTPUT_TOKENS)!=i+o:raise ValueError('inconsistent usage')
    return {'input_tokens':i,'output_tokens_including_reasoning':o,'total_tokens':i+o}


def _fields(value, allowed):
    if not isinstance(value,dict) or set(value)-set(allowed):raise ValueError('unqualified usage fields')


def _openai(response, model):
    if (response.get('model')!=model or response.get('status')!='completed' or
            response.get('error') is not None or response.get('incomplete_details') is not None or
            response.get('service_tier')!='default'):
        raise ValueError('model, completion or service tier differs')
    output=response['output']
    if not isinstance(output,list) or not output:raise ValueError('missing output')
    messages=[]
    for item in output:
        if item['type']=='message':messages.append(item)
        elif item['type']!='reasoning':raise ValueError('unexpected tool or output')
    if len(messages)!=1:raise ValueError('ambiguous message')
    message=messages[0];content=message['content']
    if (message.get('role')!='assistant' or message.get('status')!='completed' or
            not isinstance(content,list) or len(content)!=1 or content[0].get('type')!='output_text'):
        raise ValueError('non-text or unfinished output')
    usage=response['usage']
    _fields(usage,('input_tokens','output_tokens','total_tokens','input_tokens_details','output_tokens_details'))
    result=_usage(usage['input_tokens'],usage['output_tokens'],usage['total_tokens'])
    details=usage['input_tokens_details']
    _fields(details,('cached_tokens','cache_write_tokens'))
    _fields(usage['output_tokens_details'],('reasoning_tokens',))
    if (_count(details['cached_tokens'],MAX_INPUT_TOKENS)!=0 or
            _count(details.get('cache_write_tokens',0),MAX_INPUT_TOKENS)!=0):
        raise ValueError('unqualified cache billing')
    _count(usage['output_tokens_details']['reasoning_tokens'],result['output_tokens_including_reasoning'])
    return content[0]['text'],result


def _bedrock(response):
    if response.get('stopReason')!='end_turn':raise ValueError('unfinished or tool output')
    message=response['output']['message'];content=message['content']
    if (message.get('role')!='assistant' or not isinstance(content,list) or len(content)!=1 or
            not isinstance(content[0],dict) or set(content[0])!={'text'}):
        raise ValueError('non-text response')
    usage=response['usage']
    cache_fields=('cacheReadInputTokens','cacheWriteInputTokens','cacheReadInputTokenCount','cacheWriteInputTokenCount')
    _fields(usage,('inputTokens','outputTokens','totalTokens',*cache_fields,'serverToolUsage'))
    result=_usage(usage['inputTokens'],usage['outputTokens'],usage['totalTokens'])
    for field in cache_fields:
        if _count(usage.get(field,0),MAX_INPUT_TOKENS)!=0:raise ValueError('unqualified cache billing')
    if type(usage.get('serverToolUsage',{})) is not dict or usage.get('serverToolUsage',{}):
        raise ValueError('unqualified server tool usage')
    if response.get('performanceConfig',{}).get('latency','standard')!='standard':
        raise ValueError('unqualified performance tier')
    if response.get('serviceTier',{}).get('type','default')!='default':
        raise ValueError('unqualified service tier')
    text=content[0]['text']
    # Only unwrap one complete JSON fence; the strict task parser still validates
    # the entire enclosed object, duplicate keys and every candidate binding.
    if isinstance(text,str) and text.startswith('```json\n') and text.endswith('\n```'):
        text=text[8:-4]
    return text,result


def _google(response, model):
    if response.get('modelVersion')!=model or response.get('promptFeedback',{}).get('blockReason'):
        raise ValueError('model or safety differs')
    candidates=response['candidates']
    if not isinstance(candidates,list) or len(candidates)!=1:raise ValueError('ambiguous candidates')
    candidate=candidates[0];content=candidate['content'];parts=content['parts']
    if (candidate.get('finishReason')!='STOP' or content.get('role')!='model' or
            not isinstance(parts,list) or len(parts)!=1 or not isinstance(parts[0],dict) or
            set(parts[0])-{'text','thoughtSignature'} or
            candidate.get('groundingMetadata') or candidate.get('urlContextMetadata')):
        raise ValueError('unfinished, tool or non-text result')
    usage=response['usageMetadata']
    _fields(usage,('promptTokenCount','candidatesTokenCount','thoughtsTokenCount','totalTokenCount',
        'cachedContentTokenCount','toolUsePromptTokenCount','promptTokensDetails','candidatesTokensDetails','serviceTier'))
    if usage.get('serviceTier','standard')!='standard':
        raise ValueError('unqualified Google service tier')
    for field in ('promptTokensDetails','candidatesTokensDetails'):
        if field in usage:
            if not isinstance(usage[field],list):raise ValueError('invalid modality usage')
            for detail in usage[field]:
                if set(detail)!={'modality','tokenCount'} or detail['modality']!='TEXT':
                    raise ValueError('unqualified modality')
                _count(detail['tokenCount'],MAX_INPUT_TOKENS+MAX_OUTPUT_TOKENS)
    visible=_count(usage['candidatesTokenCount'],MAX_OUTPUT_TOKENS)
    thoughts=_count(usage.get('thoughtsTokenCount',0),MAX_OUTPUT_TOKENS)
    result=_usage(usage['promptTokenCount'],visible+thoughts,usage['totalTokenCount'])
    for field in ('cachedContentTokenCount','toolUsePromptTokenCount'):
        if _count(usage.get(field,0),MAX_INPUT_TOKENS)!=0:raise ValueError('unqualified cache or tool usage')
    return parts[0]['text'],result


def parse_response(raw, root, *, role, builder_response=None, candidate_commit=None):
    """Validate envelope, complete text, usage and exact task output bindings.

No authenticated model claim or dollar cost is produced. Converse does not echo
model identity: the future transport must prove the requested inference profile.
"""
    packet=_packet(root,role,builder_response,candidate_commit)
    try:
        response=_decode(raw)
        text,usage=(_openai(response,packet['model_id']) if role=='builder' else
            _bedrock(response) if role=='inspector' else _google(response,packet['model_id']))
        if not isinstance(text,str):raise ValueError('text required')
        output=text.encode('utf-8')
        parsed=(parse_builder(output,root=root) if role=='builder' else
            parse_review(output,root=root,role=role,builder_response=builder_response,candidate_commit=candidate_commit))
    except (StateError,ValueError,TypeError,KeyError,AttributeError,RecursionError,UnicodeError):
        raise StateError('Pilot 002 provider envelope, usage or task output rejected') from None
    return {'status':'UNAUTHENTICATED_PROVIDER_RESPONSE','role':role,
        'requested_model_id':packet['model_id'],'provider_identity_verified':False,
        'usage':usage,'output_bytes':output,'parsed_output':parsed,
        'gate_authority':False,'production_release_authorized':False}
