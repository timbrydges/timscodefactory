import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from factory_runtime.handoff002_observer import run,NAME,ARN
from factory_state.model import StateError
from prepare_handoff002_observer import render,validate_changes,STACK


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'BUILD.json').write_text(json.dumps({'source_commit':'a'*40}))
        self.env={'FACTORY_HANDOFF002_OBSERVER_ENABLED':'true','AWS_REGION':'ca-central-1','AWS_LAMBDA_FUNCTION_NAME':NAME}
        self.event={'kind':'handoff002_observe_only','source_commit':'a'*40}
        self.observe=Mock(return_value={'status':'COMPLETED_NO_DISPATCH','worker_invocations':0,
            'execution_authorized':False,'gate_authority':False,'authoritative_task_state_written':False})
    def call(self,**kw):
        return run(**{**dict(event=self.event,context=SimpleNamespace(invoked_function_arn=ARN+'1'),
            root=self.root,env=self.env,observe=self.observe,clock=lambda:1),**kw})
    def test_valid_observer_cannot_gain_authority(self):
        self.assertEqual(self.call()['status'],'COMPLETED_NO_DISPATCH')
        self.observe.return_value['gate_authority']=True
        with self.assertRaises(StateError):self.call()
    def test_disabled_alias_and_wrong_source_never_read_aws(self):
        for kw in ({'env':{}},{'context':SimpleNamespace(invoked_function_arn=ARN+'latest')},
                   {'event':{**self.event,'source_commit':'b'*40}}):
            with self.assertRaises(StateError):self.call(**kw)
        self.observe.assert_not_called()

    def test_infrastructure_has_only_exact_read_and_logs_permissions(self):
        args={'source_commit':'a'*40,'code':{'S3Bucket':'fixed','S3Key':'observer.zip','S3ObjectVersion':'v1'}}
        template=render(**args);resources=template['Resources']
        policy=resources['Role']['Properties']['Policies'][0]['PolicyDocument']['Statement']
        self.assertEqual(policy[0]['Action'],'dynamodb:GetItem')
        self.assertEqual(len(policy[0]['Condition']['ForAllValues:StringEquals']['dynamodb:LeadingKeys']),3)
        self.assertEqual(policy[1]['Action'],['logs:CreateLogStream','logs:PutLogEvents'])
        self.assertEqual(len(policy),2)
        self.assertEqual(resources['Function']['Properties']['ReservedConcurrentExecutions'],0)
        preview={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+STACK+'/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':n,'ResourceType':v['Type'],'Action':'Add'}}
                       for n,v in resources.items()]}
        self.assertEqual(validate_changes(template,preview,**args)['worker_invoke_permissions'],0)
        policy[0]['Action']='dynamodb:PutItem'
        with self.assertRaises(StateError):validate_changes(template,preview,**args)
