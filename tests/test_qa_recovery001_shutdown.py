import copy
import json
import sys
import unittest
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
import prepare_qa_recovery001_shutdown as p


class RecoveryShutdownTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,10,4,20,tzinfo=timezone.utc);self.deadline=int(self.now.timestamp())+1200

    def test_only_concurrency_permission_and_disabled_by_default(self):
        self.assertEqual(p.FUNCTION_ARN,'arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-qa-recovery-001')
        self.assertEqual(p.GROUP,'tims-factory-qa-recovery-001-shutdown')
        self.assertEqual(p.NAME,'qa-recovery001-concurrency-zero')
        import prepare_inspector_recovery001_shutdown as inspector
        self.assertNotEqual(p.NAME,inspector.NAME)
        template=p.render(self.deadline,now=self.now)
        role=template['Resources']['ShutdownRole']['Properties']
        statement=role['Policies'][0]['PolicyDocument']['Statement']
        self.assertEqual(statement,[{'Effect':'Allow','Action':'lambda:PutFunctionConcurrency','Resource':p.FUNCTION_ARN}])
        self.assertEqual(role['AssumeRolePolicyDocument']['Statement'][0]['Condition']['StringEquals'],
            {'aws:SourceAccount':'666730517561','aws:SourceArn':p.GROUP_ARN})
        schedule=template['Resources']['ShutdownSchedule']['Properties']
        self.assertEqual(schedule['State'],'DISABLED')
        self.assertNotIn('ActionAfterCompletion',schedule)
        for field in ('StartDate','EndDate'):
            self.assertRegex(schedule[field],r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$')
        self.assertEqual(p.properties(self.deadline,now=self.now)['ActionAfterCompletion'],'NONE')
        self.assertEqual(json.loads(schedule['Target']['Input']),{'FunctionName':p.FUNCTION_ARN,'ReservedConcurrentExecutions':0})
        self.assertEqual(schedule['Target']['Arn'],p.TARGET)

    def test_exact_armed_schedule_and_timestamp_normalization(self):
        schedule=p.properties(self.deadline,now=self.now,armed=True)
        for field in ('StartDate','EndDate'):schedule[field]=datetime.fromisoformat(schedule[field])
        self.assertEqual(p.validate_armed(schedule,self.deadline,now=self.now)['deadline'],self.deadline)
        for change in ({'State':'DISABLED'},{'ScheduleExpression':'rate(1 hour)'},{'EndDate':self.now},
                       {'Target':{**schedule['Target'],'Input':'{"ReservedConcurrentExecutions":1}'}}):
            with self.assertRaises(Exception):p.validate_armed({**schedule,**change},self.deadline,now=self.now)

    def test_stale_far_future_and_naive_times_rejected(self):
        for value in (True,int(self.now.timestamp())+59,int(self.now.timestamp())+1801):
            with self.assertRaises(Exception):p.render(value,now=self.now)
        with self.assertRaises(Exception):p.render(self.deadline,now=self.now.replace(tzinfo=None))

    def test_preview_rejects_permissions_or_resource_expansion(self):
        template=p.render(self.deadline,now=self.now)
        changes={'Status':'CREATE_COMPLETE','ExecutionStatus':'AVAILABLE',
            'StackId':'arn:aws:cloudformation:ca-central-1:666730517561:stack/'+p.STACK+'/fixture',
            'Changes':[{'Type':'Resource','ResourceChange':{'LogicalResourceId':name,'ResourceType':r['Type'],'Action':'Add'}} for name,r in template['Resources'].items()]}
        self.assertFalse(p.validate_preview(template,changes,self.deadline,now=self.now)['armed'])
        bad=copy.deepcopy(template);bad['Resources']['ShutdownRole']['Properties']['Policies'][0]['PolicyDocument']['Statement'][0]['Action']='lambda:*'
        with self.assertRaises(Exception):p.validate_preview(bad,changes,self.deadline,now=self.now)
        changes['Changes'][0]['ResourceChange']['Action']='Modify'
        with self.assertRaises(Exception):p.validate_preview(template,changes,self.deadline,now=self.now)

    def test_live_window_fits_free_tier_without_extending_expiry(self):
        epoch = int(self.now.timestamp())
        deadline = epoch + 180
        schedule = p.properties(deadline, now=self.now, armed=True)
        result = p.validate_live_window(schedule, deadline, allowance_expires_at=epoch + 300, now=self.now)
        self.assertFalse(result['execution_authorized'])
        self.assertEqual(result['latest_nominal_first_execution'], epoch + 240)
        for expiry in (True, epoch, epoch + 239, epoch + 301):
            with self.assertRaises(Exception):
                p.validate_live_window(schedule, deadline, allowance_expires_at=expiry, now=self.now)
        for delay in (59, 1801):
            with self.assertRaises(Exception):
                p.properties(epoch + delay, now=self.now, armed=True)
        schedule['State'] = 'DISABLED'
        with self.assertRaises(Exception):
            p.validate_live_window(schedule, deadline, allowance_expires_at=epoch + 300, now=self.now)


if __name__=='__main__':unittest.main()
