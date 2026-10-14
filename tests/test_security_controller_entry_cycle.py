"""Actual entrypoints and versioned job parser; simulated cloud transport only.

Intake is already durably authorized by the fixture, so receipt S3 is not read.
The controller, not the fixture, claims dispatch and reserves provider spend.
"""
import base64
import hashlib
import io
import json
from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_security_entry_cycle as fixtures
from test_security_provider_claims import mock_aws
from test_pilot002_transport import Connection, Response
from factory_runtime import security_controller_lambda as controller, security_role_lambda as role
from factory_runtime import pilot002_transport as wire
from factory_runtime.acceptance_jobs import encode_job
from factory_runtime.autonomy import ScheduledAutonomyJob
from factory_runtime.receipt_transport import ReceiptVersions
from factory_runtime.worker import digest
from factory_state.model import StateError
from factory_state.scope import canonical


@unittest.skipIf(mock_aws is None,'Requires moto[dynamodb]')
class ControllerEntryCycleTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.EntryCycleTests();f.preclaim=False;f.setUp();self.addCleanup(f.doCleanups)
        self.f=f;self.invocations=0;self.reads=[];self.bad_checksum=False
        q=f.material.binding.qa
        job=ScheduledAutonomyJob(f.t.policy.plan,ReceiptVersions('owner-v1','review-v1'),
            f.material.prepared().input_bytes,f.material.contract_bytes)
        self.job=encode_job(job,'bounded-security-004')
        config={'activation':{'activation_id':'bounded-security-004','factory_id':q.factory_id,
            'task_id':q.task_id,'source_commit':q.source_commit,'contract_digest':q.contract_digest,
            'starts_at':f.now.isoformat(),'expires_at':(f.now+timedelta(minutes=5)).isoformat()},
            'function_arn':f.context.invoked_function_arn,
            'job_versions':{'SECURITY_REVIEW':{'version_id':'job-v1','sha256':digest(self.job)}}}
        raw=canonical(config);(f.root/'SECURITY_CONTROLLER.json').write_bytes(raw)
        self.env={**f.env,'FACTORY_SECURITY_CONTROLLER_ENABLED':'true',
            'FACTORY_SECURITY_CONTROLLER_DIGEST':digest(raw),'AWS_LAMBDA_FUNCTION_NAME':controller.NAME}
        self.context=SimpleNamespace(invoked_function_arn=
            'arn:aws:lambda:ca-central-1:666730517561:function:'+controller.NAME+':1',
            get_remaining_time_in_millis=lambda:300000)
        def meta(service):return SimpleNamespace(endpoint_url=f'https://{service}.ca-central-1.amazonaws.com',
            config=SimpleNamespace(retries={'total_max_attempts':1}))
        sts=SimpleNamespace(meta=meta('sts'),get_caller_identity=lambda:{'Account':'666730517561',
            'Arn':'arn:aws:sts::666730517561:assumed-role/'+controller.EXECUTION_ROLE+'/fixture'})
        self.clients={'sts':sts,'dynamodb':f.t.db,
            's3':SimpleNamespace(meta=meta('s3'),get_object=self.get_object),
            'lambda':SimpleNamespace(meta=meta('lambda'),invoke=self.invoke)}
        # No credential accessor exists on the controller session.
        self.session=SimpleNamespace(client=lambda name,**kw:self.clients[name])

    def get_object(self,**kwargs):
        self.reads.append(kwargs)
        self.assertEqual(kwargs['VersionId'],'job-v1')
        self.assertEqual(kwargs['Key'],'factory-autonomy-jobs/bounded-security-004/SECURITY_REVIEW.json')
        checksum=base64.b64encode(hashlib.sha256(self.job).digest()).decode()
        return {'VersionId':'job-v1','ContentLength':len(self.job),'Body':io.BytesIO(self.job),
            'ChecksumSHA256':'changed' if self.bad_checksum else checksum}

    def invoke(self,**kwargs):
        self.invocations+=1
        self.assertEqual(kwargs['FunctionName'],self.f.context.invoked_function_arn)
        result=role.dispatch(json.loads(kwargs['Payload']),self.f.context,
            root=self.f.root,env=self.f.env,clock=lambda:self.f.now)
        return {'StatusCode':200,'ExecutedVersion':'1','Payload':io.BytesIO(canonical(result))}

    def tick(self):
        return controller.dispatch(controller.EVENT,self.context,root=self.f.root,env=self.env,clock=lambda:self.f.now)

    def test_controller_reads_pinned_job_runs_role_once_and_stops(self):
        with patch.object(controller,'_aws_session',return_value=self.session), \
                patch.object(role,'_aws_session',return_value=self.f.session), \
                patch.object(wire.http.client,'HTTPSConnection',return_value=Connection(Response(self.f.response))) as network:
            result=self.tick();again=self.tick()
        self.assertEqual(result['status'],'ADVANCED')
        self.assertEqual(result['progression']['state'],'RELEASE_READY')
        self.assertEqual(again['status'],'STOPPED');self.assertFalse(again['release_dispatched'])
        self.assertEqual((self.invocations,network.call_count,len(self.reads)),(1,1,1))

    def test_wrong_s3_checksum_blocks_role_and_provider(self):
        self.bad_checksum=True
        with patch.object(controller,'_aws_session',return_value=self.session), \
                patch.object(wire.http.client,'HTTPSConnection') as network:
            with self.assertRaises(StateError):self.tick()
            network.assert_not_called()
        self.assertEqual(self.invocations,0)


if __name__ == '__main__':unittest.main()
