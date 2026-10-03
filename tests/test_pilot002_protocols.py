import copy
import json
import unittest
from pathlib import Path

from factory_runtime import pilot002_protocols as p
from factory_runtime.pilot002_packets import builder_packet,review_packet,REVIEW_BINDINGS
from factory_state.model import StateError
from factory_state.scope import canonical

ROOT=Path(__file__).resolve().parents[1]


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        packet=builder_packet(ROOT)
        self.builder={'task_id':packet['task_id'],'packet_digest':packet['packet_digest'],
            'files':{'fingerprint.py':'# candidate\n','tests/test_fingerprint.py':'# tests\n'}}
        self.raw=canonical(self.builder);self.commit='a'*40

    def context(self,role):
        return {'role':role,**({} if role=='builder' else {'builder_response':self.raw,'candidate_commit':self.commit})}

    def response(self,role):
        if role=='builder':
            return {'model':'gpt-5.6-sol','status':'completed','service_tier':'default',
                'output':[{'type':'reasoning','summary':[]},{'type':'message','role':'assistant','status':'completed',
                    'content':[{'type':'output_text','text':self.raw.decode()}]}],
                'usage':{'input_tokens':100,'output_tokens':30,'total_tokens':130,
                    'input_tokens_details':{'cached_tokens':0,'cache_write_tokens':0},
                    'output_tokens_details':{'reasoning_tokens':10}}}
        packet=review_packet(ROOT,**self.context(role))
        text=canonical({**{key:packet[key] for key in REVIEW_BINDINGS},
            'verdict':'ACCEPTED','rationale':'Offline fixture assessment.','findings':[]}).decode()
        if role=='inspector':
            return {'stopReason':'end_turn','output':{'message':{'role':'assistant','content':[{'text':text}]}},
                'usage':{'inputTokens':100,'outputTokens':30,'totalTokens':130}}
        return {'modelVersion':'gemini-3.8-flash','candidates':[{'finishReason':'STOP',
            'content':{'role':'model','parts':[{'text':text}]}}],
            'usageMetadata':{'promptTokenCount':100,'candidatesTokenCount':20,'thoughtsTokenCount':10,'totalTokenCount':130}}

    def parse(self,role,value):return p.parse_response(canonical(value),ROOT,**self.context(role))

    def test_requests_are_deterministic_and_contain_exact_packets(self):
        for role in ('builder','inspector','qa'):
            with self.subTest(role=role):
                raw=p.request_bytes(ROOT,**self.context(role))
                self.assertEqual(raw,p.request_bytes(ROOT,**self.context(role)))
                body=json.loads(raw)
                material=(body['input'] if role=='builder' else body['messages'][0]['content'][0]['text']
                    if role=='inspector' else body['contents'][0]['parts'][0]['text'])
                packet=json.loads(material)
                self.assertEqual(packet['role'],role)
                self.assertEqual(packet['untrusted_files'],self.builder['files'] if role!='builder' else builder_packet(ROOT)['untrusted_files'])
                self.assertNotIn('tools',body if role!='builder' else {})
                self.assertLessEqual(len(raw),65536)
        builder=json.loads(p.request_bytes(ROOT,role='builder'))
        self.assertFalse(builder['store']);self.assertFalse(builder['stream'])
        self.assertEqual(builder['tools'],[])
        self.assertEqual(builder['prompt_cache_options'],{'mode':'explicit'})

    def test_role_and_context_cannot_be_substituted(self):
        for ctx in ({'role':'unknown'},{'role':'builder','candidate_commit':self.commit},
                    {'role':'builder','builder_response':self.raw},{'role':'qa'}):
            with self.subTest(ctx=ctx),self.assertRaises(StateError):p.request_bytes(ROOT,**ctx)

    def test_three_valid_responses_include_reasoning_once(self):
        for role in ('builder','inspector','qa'):
            with self.subTest(role=role):
                result=self.parse(role,self.response(role))
                self.assertEqual(result['usage'],{'input_tokens':100,'output_tokens_including_reasoning':30,'total_tokens':130})
                self.assertFalse(result['provider_identity_verified'])
                self.assertFalse(result['gate_authority'])
                self.assertNotIn('actual_micro_usd',result)

    def test_openai_incomplete_wrong_model_and_wrong_tier_rejected(self):
        for key,value in (('status','incomplete'),('model','other'),('service_tier','priority'),
                          ('error',{'message':'SECRET'}),('incomplete_details',{'reason':'max_output_tokens'})):
            response=self.response('builder');response[key]=value
            with self.subTest(key=key),self.assertRaisesRegex(StateError,'rejected'):self.parse('builder',response)

    def test_openai_refusals_tools_and_multiple_messages_rejected(self):
        for item in ({'type':'function_call'},{'type':'web_search_call'},
            {'type':'message','role':'assistant','status':'completed','content':[{'type':'refusal','refusal':'no'}]}):
            response=self.response('builder');response['output'].append(item)
            with self.subTest(item=item),self.assertRaises(StateError):self.parse('builder',response)
        response=self.response('builder');response['output'][1]['content'][0]={'type':'refusal','refusal':'no'}
        with self.assertRaises(StateError):self.parse('builder',response)

    def test_usage_requires_integers_consistent_totals_and_bounds(self):
        for role,field,key in (('builder','usage','input_tokens'),('inspector','usage','inputTokens'),('qa','usageMetadata','promptTokenCount')):
            for value in (True,-1,1.0,'100',32769,None):
                response=self.response(role);response[field][key]=value
                with self.subTest(role=role,value=value),self.assertRaises(StateError):self.parse(role,response)
            response=self.response(role);response[field][key]=99
            with self.assertRaises(StateError):self.parse(role,response)

    def test_reasoning_cannot_exceed_total_output_cap(self):
        response=self.response('builder');response['usage']['output_tokens_details']['reasoning_tokens']=31
        with self.assertRaises(StateError):self.parse('builder',response)
        response=self.response('qa');response['usageMetadata'].update(thoughtsTokenCount=4090,totalTokenCount=4210)
        with self.assertRaises(StateError):self.parse('qa',response)

    def test_cache_usage_requires_separate_qualification(self):
        for role in ('builder','inspector','qa'):
            response=self.response(role)
            if role=='builder':response['usage']['input_tokens_details']['cache_write_tokens']=1
            elif role=='inspector':response['usage']['cacheWriteInputTokens']=1
            else:response['usageMetadata']['cachedContentTokenCount']=1
            with self.subTest(role=role),self.assertRaises(StateError):self.parse(role,response)

    def test_new_billing_fields_and_nontext_modalities_fail_closed(self):
        for role in ('builder','inspector','qa'):
            response=self.response(role)
            response['usageMetadata' if role=='qa' else 'usage']['newPaidTokens']=1
            with self.subTest(role=role),self.assertRaises(StateError):self.parse(role,response)
        response=self.response('qa')
        response['usageMetadata']['promptTokensDetails']=[{'modality':'AUDIO','tokenCount':100}]
        with self.assertRaises(StateError):self.parse('qa',response)
        response['usageMetadata']['promptTokensDetails']=[{'modality':'TEXT','tokenCount':100}]
        self.parse('qa',response)

    def test_bedrock_truncation_tools_and_wrong_role_rejected(self):
        for reason in ('max_tokens','tool_use','guardrail_intervened','content_filtered'):
            response=self.response('inspector');response['stopReason']=reason
            with self.subTest(reason=reason),self.assertRaises(StateError):self.parse('inspector',response)
        response=self.response('inspector');response['output']['message']['content']=[{'toolUse':{}}]
        with self.assertRaises(StateError):self.parse('inspector',response)
        response=self.response('inspector');response['output']['message']['role']='user'
        with self.assertRaises(StateError):self.parse('inspector',response)

    def test_google_safety_model_tools_and_ambiguous_output_rejected(self):
        base=self.response('qa')
        variations=[]
        for key,value in (('modelVersion','other'),('promptFeedback',{'blockReason':'SAFETY'}),('candidates',base['candidates']*2)):
            response=copy.deepcopy(base);response[key]=value;variations.append(response)
        for key,value in (('finishReason','MAX_TOKENS'),('groundingMetadata',{'source':'unexpected'})):
            response=copy.deepcopy(base);response['candidates'][0][key]=value;variations.append(response)
        response=copy.deepcopy(base);response['candidates'][0]['content']['parts']=[{'functionCall':{}}];variations.append(response)
        for response in variations:
            with self.subTest(response=response),self.assertRaises(StateError):self.parse('qa',response)

    def test_task_bindings_still_checked_inside_provider_text(self):
        for role in ('builder','inspector','qa'):
            response=self.response(role)
            if role=='builder':part=response['output'][1]['content'][0]
            elif role=='inspector':part=response['output']['message']['content'][0]
            else:part=response['candidates'][0]['content']['parts'][0]
            text=json.loads(part['text']);text['task_id']='wrong-task';part['text']=json.dumps(text)
            with self.subTest(role=role),self.assertRaises(StateError):self.parse(role,response)

    def test_duplicate_nonfinite_deep_and_oversized_envelopes_rejected(self):
        for raw in (b'{"status":0,"status":1}',b'{"x":NaN}',b'['*2000+b']'*2000,
                    b'{"x":"\\ud800"}',b'x'*262145,b'[]',b'null',b'\xff'):
            with self.subTest(raw=raw[:30]),self.assertRaises(StateError):p.parse_response(raw,ROOT,role='builder')

    def test_malformed_nested_values_raise_sanitized_errors(self):
        for role,key in (('builder','usage'),('builder','output'),('inspector','output'),('qa','candidates')):
            response=self.response(role);response[key]=None
            with self.assertRaisesRegex(StateError,'^Pilot 002 provider envelope, usage or task output rejected$'):
                self.parse(role,response)


if __name__=='__main__':unittest.main()
