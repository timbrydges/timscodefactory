"""No paid calls: real signatures and claims with a synthetic HTTPS peer."""
import base64
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock,patch
from factory_state.dispatch import DispatchRequest,DynamoDBDispatchStore
from factory_state.dynamodb import DynamoDBStateStore
from factory_state.model import CONTROLLER_IDENTITY,TaskState,Lease,StateError
from factory_state.scope import SignedScopeStore,canonical
from factory_runtime import pilot002_transport as wire
from factory_runtime.review_provider_protocol import job_input,prepare,parse_response,ResponseValidationFailure
from factory_runtime.review_provider_transport import ReviewProviderTransport
from factory_runtime.review_provider_backend import ReviewProviderBackend, BoundedProviderFailure
from factory_runtime.review_provider_claims import ReviewProviderClaims,TABLE
from factory_runtime.review_provider_scope import FACTORY,TASK
from factory_runtime.review_verdict import ReviewBinding,PinnedPythonTestEvidence
from factory_runtime.worker import digest
from scripts.scope_dispatch_canary import fixture_keys,sign
from test_autonomous_scheduler import NOW
from test_review_provider_scope import fixture as scope_fixture
from test_pilot002_transport import Connection,Response,KEY,AWS
try:
    import boto3
    from botocore.config import Config
    from moto import mock_aws
except ImportError:
    mock_aws=None

FILES={'fingerprint.py':'# synthetic candidate\n','tests/test_fingerprint.py':'# synthetic tests\n'}


def material(role='builder'):
    proof=canonical({'source_commit':'a'*40,'candidate_commit':'b'*40,'observed_at':NOW.isoformat(),
        'runtime':'python3.12-linux','python_version':'3.12.15',
        'files':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in FILES.items()},'exit_code':0,
        'credentials_in_environment':False,'stdout':'','stderr':'test_fixture ... ok\n\nRan 1 tests in 0.001s\n\nOK\n'})
    raw=job_input(role=role,source_commit='a'*40,contract_digest=digest(b'contract'),candidate_commit='b'*40,
                  files=FILES,test_evidence_digest=digest(proof))
    request=DispatchRequest('lease-'+role,TASK,'bounded-review','a'*40,digest(b'contract'),digest(raw))
    return prepare(role=role,request=request,candidate_commit='b'*40,files=FILES,
                   test_evidence_digest=digest(proof),input_bytes=raw),proof


def output_for(prepared,verdict='ACCEPTED'):
    output=json.loads(prepared.expected_output);output['rationale']='Synthetic fixture only.'
    if prepared.scope.role=='builder':output['files']=FILES.copy()
    else:output.update(verdict=verdict,findings=[])
    return output


def response_for(prepared,output=None):
    text=canonical(output or output_for(prepared)).decode();role=prepared.scope.role
    if role=='builder':
        result={'model':'gpt-5.6-sol','status':'completed','service_tier':'default',
            'output':[{'type':'message','role':'assistant','status':'completed',
                       'content':[{'type':'output_text','text':text}]}],
            'usage':{'input_tokens':100,'output_tokens':50,'total_tokens':150,
                     'input_tokens_details':{'cached_tokens':0},'output_tokens_details':{'reasoning_tokens':0}}}
    elif role=='inspector':
        result={'stopReason':'end_turn','output':{'message':{'role':'assistant','content':[{'text':text}]}},
                'usage':{'inputTokens':100,'outputTokens':50,'totalTokens':150}}
    else:
        result={'modelVersion':'gemini-3.7-flash','candidates':[{'finishReason':'STOP',
            'content':{'role':'model','parts':[{'text':text}]}}],
            'usageMetadata':{'promptTokenCount':100,'candidatesTokenCount':50,'totalTokenCount':150}}
    return canonical(result)


class ProtocolTests(unittest.TestCase):
    def test_response_rejection_codes_do_not_expose_provider_values(self):
        prepared,_=material();good=json.loads(response_for(prepared))
        cases=[(b'secret','envelope-json'),
            (canonical({**good,'model':'secret'}),'provider-model'),
            (canonical({**good,'status':'incomplete','incomplete_details':{'reason':'secret'}}),'provider-completion'),
            (canonical({**good,'service_tier':'secret'}),'provider-tier'),
            (canonical({**good,'usage':{**good['usage'],'total_tokens':999}}),'provider-usage'),
            (canonical({**good,'output':[]}),'provider-output'),
            (response_for(prepared,{**output_for(prepared),'rationale':'','extra':'secret'}),'output-fields'),
            (response_for(prepared,{**output_for(prepared),'files':{**FILES,'fingerprint.py':'secret'}}),'candidate-files')]
        bad=json.loads(response_for(prepared));bad['output'][0]['content'][0]['text']='secret'
        cases.append((canonical(bad),'output-json'))
        for raw,code in cases:
            with self.subTest(code=code),self.assertRaises(ResponseValidationFailure) as error:
                parse_response(raw,prepared)
            self.assertEqual(error.exception.code,code)
            self.assertNotIn('secret',str(error.exception))
        failure=ResponseValidationFailure('secret');failure.code='secret';failure.args=('secret',)
        self.assertNotIn('secret',str(BoundedProviderFailure('response validation',failure)))

    def test_exact_fields_and_bindings_rejected_without_provider_text(self):
        for role in ('builder','inspector','qa'):
            prepared,_=material(role);good=output_for(prepared)
            cases=[({k:v for k,v in good.items() if k!='rationale'},'output-fields'),
                   ({'wrapper':good},'output-fields'),
                   ({**good,'rationale':' '},'output-rationale'),
                   ({**good,'rationale':42},'output-rationale'),
                   ({**good,'rationale':'x'*2001},'output-rationale')]
            cases += [({**good,key:'secret'},'binding-'+key.replace('_','-'))
                      for key in json.loads(prepared.expected_output)]
            for output,code in cases:
                with self.subTest(role=role,code=code),self.assertRaises(ResponseValidationFailure) as error:
                    parse_response(response_for(prepared,output),prepared)
                self.assertEqual(error.exception.code,code)
                self.assertNotIn('secret',str(error.exception))
                self.assertNotIn('secret',str(BoundedProviderFailure('response validation',error.exception)))

    def test_builder_strict_schema_matches_local_acceptance_boundary(self):
        from jsonschema import Draft202012Validator
        prepared,_=material();body=json.loads(prepared.scope.request_bytes)
        fmt=body['text']['format'];self.assertEqual(fmt['type'],'json_schema');self.assertTrue(fmt['strict'])
        schema=fmt['schema'];Draft202012Validator.check_schema(schema);validator=Draft202012Validator(schema)
        valid=output_for(prepared);validator.validate(valid)
        self.assertEqual(set(schema['required']),set(valid))
        self.assertFalse(schema['additionalProperties'])
        for bad in ({k:v for k,v in valid.items() if k!='files'},
                    {**valid,'candidate_commit':'c'*40},{**valid,'extra':True},
                    {**valid,'files':{'unapproved.py':'secret'}}):
            self.assertFalse(validator.is_valid(bad))
        # A shape-valid changed candidate still cannot pass the local gate.
        changed={**valid,'files':{**FILES,'fingerprint.py':'changed'}}
        validator.validate(changed)
        with self.assertRaisesRegex(ResponseValidationFailure,'candidate-files'):
            parse_response(response_for(prepared,changed),prepared)
        changed=replace(prepared,scope=replace(prepared.scope,request_bytes=canonical({**body,'text':{}})))
        with self.assertRaises(StateError):changed.validate()

    def test_failure_metadata_rejects_untrusted_text_and_status(self):
        for status in ('secret', True, 200, 600, None):
            failure=BoundedProviderFailure('provider transport',wire.ProviderHTTPStatusError(status))
            self.assertIsNone(failure.http_status)
            self.assertNotIn('secret',str(failure))
        failure=BoundedProviderFailure('secret',RuntimeError('secret'))
        self.assertEqual(failure.phase,'unknown')
        self.assertNotIn('secret',str(failure))

    def test_all_fixed_routes_and_parsed_outputs(self):
        hosts=set()
        for role in ('builder','inspector','qa'):
            prepared,_=material(role);raw=response_for(prepared);connection=Connection(Response(raw))
            with patch.object(wire.http.client,'HTTPSConnection',return_value=connection) as connect:
                transport=ReviewProviderTransport(prepared,enabled=True)
                result=transport.send_once(request_bytes=prepared.scope.request_bytes,
                    credential=AWS if role=='inspector' else KEY,
                    expected_request_digest=prepared.scope.bindings()['request_digest'])
                hosts.add(connect.call_args.args[0])
                output,usage=parse_response(result,prepared)
                self.assertEqual(json.loads(output),output_for(prepared));self.assertEqual(usage['total_tokens'],150)
                with self.assertRaises(StateError):transport.send_once(request_bytes=prepared.scope.request_bytes,
                    credential=KEY,expected_request_digest=prepared.scope.bindings()['request_digest'])
                self.assertEqual(connect.call_count,1)
                if role=='qa':self.assertIn('gemini-3.7-flash',connection.calls[0][0][1])
        self.assertEqual(hosts,{'api.openai.com','bedrock-runtime.ca-central-1.amazonaws.com','generativelanguage.googleapis.com'})

    def test_modified_job_request_candidate_or_output_rejected(self):
        prepared,_=material()
        changed=replace(prepared,scope=replace(prepared.scope,request_bytes=b'{}'))
        with self.assertRaises(StateError):ReviewProviderTransport(changed,enabled=True)
        changed=replace(prepared,input_bytes=prepared.input_bytes+b' ')
        with self.assertRaises(StateError):changed.validate()
        for changes in ({'candidate_commit':'c'*40},{'files':{**FILES,'fingerprint.py':'changed'}},
                        {'tests_passed':True}):
            with self.assertRaises(StateError):parse_response(response_for(prepared,{**output_for(prepared),**changes}),prepared)

    def test_rejected_review_retained_and_extra_authority_claim_rejected(self):
        prepared,_=material('qa')
        output,_=parse_response(response_for(prepared,output_for(prepared,'REJECTED')),prepared)
        self.assertEqual(json.loads(output)['verdict'],'REJECTED')
        value=output_for(prepared);value['gate_authority']=True
        with self.assertRaises(StateError):parse_response(response_for(prepared,value),prepared)

    def test_default_transport_never_connects(self):
        prepared,_=material()
        with patch.object(wire.http.client,'HTTPSConnection') as connect:
            with self.assertRaises(StateError):ReviewProviderTransport(prepared).send_once(
                request_bytes=prepared.scope.request_bytes,credential=KEY,
                expected_request_digest=prepared.scope.bindings()['request_digest'])
            connect.assert_not_called()


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class BackendTests(unittest.TestCase):
    def setUp(self):
        aws=mock_aws();aws.start();self.addCleanup(aws.stop)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.keys,self.private=fixture_keys(self.tmp.name,('tim_brydges','product_spec_reviewer_service'))
        self.db=boto3.client('dynamodb',region_name='ca-central-1',config=Config(retries={'total_max_attempts':1}))
        for table,keys in (('state',('PK','SK')),(TABLE,('PK',))):
            self.db.create_table(TableName=table,KeySchema=[{'AttributeName':k,'KeyType':'HASH' if i==0 else 'RANGE'} for i,k in enumerate(keys)],
                AttributeDefinitions=[{'AttributeName':k,'AttributeType':'S'} for k in keys],BillingMode='PAY_PER_REQUEST')
        self.prepared,proof=material();self.request=self.prepared.scope.request
        self.states=DynamoDBStateStore('state',self.db);self.ledger=DynamoDBDispatchStore('state',self.db)
        self.state=TaskState(FACTORY,TASK,'IMPLEMENTATION',0,NOW,CONTROLLER_IDENTITY,
            (Lease(self.request.lease_id,'engineering_agent','engineering_agent_service',NOW+timedelta(minutes=15)),))
        row=self.states._serialize_state(self.state);row['SK']={'S':'STATE'}
        self.db.put_item(TableName='state',Item=row)
        scopes=SignedScopeStore('state',self.db,self.keys)
        times={'issued_at':int(NOW.timestamp())-1,'expires_at':int(NOW.timestamp())+600}
        cap={'kind':'capability','factory_id':FACTORY,'objective_id':TASK,'capability_id':'bounded-review',
            'contract_digest':self.request.contract_digest,'owner_identity':'tim_brydges',
            'required_evidence':'Synthetic fixture','stop_condition':'End fixture',**times}
        scopes.approve_capability(self.state,self.request,cap,sign(cap,self.private['tim_brydges'],self.tmp.name),now=NOW)
        review={'kind':'scope_review','factory_id':FACTORY,'task_id':TASK,'binding':self.ledger._binding(self.request),
            'reviewer_identity':'product_spec_reviewer_service','verdict':'ACCEPTED','rationale':'Synthetic fixture',**times}
        scopes.approve_task(self.state,self.request,review,sign(review,self.private['product_spec_reviewer_service'],self.tmp.name),now=NOW)
        self.dispatch=self.ledger.enqueue(self.state,self.request,caller_identity=CONTROLLER_IDENTITY,now=NOW)
        self.ledger.claim(self.state,self.request,worker_id='bounded-review-controller',caller_identity=CONTROLLER_IDENTITY,now=NOW)
        _,price,ready,payload=scope_fixture();bindings=self.prepared.scope.bindings()
        price.update(bindings);ready.update(bindings);payload.update(bindings)
        payload.update(pricing_digest=digest(canonical(price)),readiness_digest=digest(canonical(ready)))
        self.envelope={'payload':payload,'signature_base64':base64.b64encode(sign(payload,self.private['tim_brydges'],self.tmp.name)).decode()}
        b=ReviewBinding(FACTORY,TASK,'independent_inspector','a'*40,self.request.contract_digest,self.request.input_digest,
            'b'*40,bindings['candidate_digest'],digest(proof),tuple(FILES))
        self.now=NOW;self.loader=Mock(return_value=KEY)
        self.config=dict(prepared=self.prepared,envelope=self.envelope,pricing=price,readiness=ready,
            states=self.states,ledger=self.ledger,claims=ReviewProviderClaims(self.db),key_loader=lambda _:self.keys,
            test_evidence=PinnedPythonTestEvidence(b,proof,FILES,test_count=1,clock=lambda:self.now),
            clock=lambda:self.now,load_credential=self.loader,enabled=True)
        self.backend=ReviewProviderBackend(**self.config)

    def hold(self):self.backend.reserve(self.state,self.request,dispatch_id=self.dispatch,now=self.now)
    def execute(self):return self.backend.execute(self.state,self.request,dispatch_id=self.dispatch,input_bytes=self.prepared.input_bytes)
    def row(self):return self.db.get_item(TableName=TABLE,Key={'PK':{'S':'BOUNDED_REVIEW#003#ROLE#builder'}}).get('Item')

    def test_real_signed_scope_shared_hold_send_once_and_retained_completion(self):
        self.hold();self.hold();connection=Connection(Response(response_for(self.prepared)))
        with patch.object(wire.http.client,'HTTPSConnection',return_value=connection) as connect:
            self.assertEqual(json.loads(self.execute()),output_for(self.prepared))
            with self.assertRaises(StateError):self.execute()
            self.assertEqual(connect.call_count,1);self.loader.assert_called_once()
        self.assertEqual(self.row()['status'],{'S':'COMPLETE'});self.assertEqual(self.row()['reservation_status'],{'S':'HELD'})

    def test_uncertain_transport_and_new_backend_cannot_repeat(self):
        self.hold();connection=Connection(error=TimeoutError('synthetic secret'))
        with patch.object(wire.http.client,'HTTPSConnection',return_value=connection) as connect:
            with self.assertRaisesRegex(StateError,'provider transport'):self.execute()
            self.backend=ReviewProviderBackend(**self.config)
            with self.assertRaisesRegex(StateError,'send claim'):self.execute()
            self.assertEqual(connect.call_count,1);self.loader.assert_called_once()
        self.assertEqual(self.row()['status'],{'S':'STARTED'})

    def test_http_failure_keeps_safe_status_and_permanent_hold(self):
        self.hold()
        with patch.object(ReviewProviderTransport,'send_once',side_effect=wire.ProviderHTTPStatusError(429)) as send:
            with self.assertRaises(BoundedProviderFailure) as error:self.execute()
            self.assertEqual(error.exception.http_status,429)
            self.assertIn('provider transport (http 429)',str(error.exception))
            with self.assertRaisesRegex(BoundedProviderFailure,'send claim'):self.execute()
            send.assert_called_once()
        self.assertEqual(self.row()['status'],{'S':'STARTED'})
        self.assertEqual(self.row()['reservation_status'],{'S':'HELD'})

    def test_pause_during_credential_load_burns_claim_without_connection(self):
        self.hold()
        def pause():
            paused=replace(self.state,state='PAUSED',version=1)
            row=self.states._serialize_state(paused);row['SK']={'S':'STATE'};self.db.put_item(TableName='state',Item=row)
            return KEY
        self.backend.load_credential=pause
        with patch.object(wire.http.client,'HTTPSConnection') as connect:
            with self.assertRaises(StateError):self.execute()
            connect.assert_not_called()
        self.assertEqual(self.row()['status'],{'S':'STARTED'})

    def test_bad_output_retains_started_and_stale_scope_never_sends(self):
        self.hold();bad={**output_for(self.prepared),'candidate_commit':'c'*40}
        connection=Connection(Response(response_for(self.prepared,bad)))
        with patch.object(wire.http.client,'HTTPSConnection',return_value=connection) as connect:
            with self.assertRaisesRegex(StateError,'response validation \\(binding-candidate-commit\\)'):self.execute()
            self.now+=timedelta(minutes=11)
            with self.assertRaises(StateError):self.execute()
            self.assertEqual(connect.call_count,1)
        self.assertEqual(self.row()['status'],{'S':'STARTED'})

    def test_disabled_controller_only_and_revoked_owner_do_not_load_credentials(self):
        with self.assertRaises(StateError):ReviewProviderBackend(**{**self.config,'enabled':False}).check_activation(self.state,self.request,now=NOW)
        with self.assertRaises(StateError):ReviewProviderBackend(**{**self.config,'load_credential':None}).execute(
            self.state,self.request,dispatch_id=self.dispatch,input_bytes=self.prepared.input_bytes)
        self.hold();self.keys.pop('tim_brydges')
        with patch.object(wire.http.client,'HTTPSConnection') as connect:
            with self.assertRaises(StateError):self.execute()
            connect.assert_not_called();self.loader.assert_not_called()
        self.assertEqual(self.row()['status'],{'S':'RESERVED'})
