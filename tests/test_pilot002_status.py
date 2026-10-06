import copy
import json
import unittest
from datetime import datetime,timezone
from types import SimpleNamespace
from unittest.mock import Mock,patch

from factory_runtime import pilot002_status as p
from factory_state.model import StateError


class OperatorStatusTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,10,5,tzinfo=timezone.utc)
        self.sts=SimpleNamespace(get_caller_identity=Mock(return_value={'Account':p.ACCOUNT}))
        self.configs={function:{'FunctionArn':f'arn:aws:lambda:{p.REGION}:{p.ACCOUNT}:function:{function}',
            'Environment':{'Variables':{flag:'false','SECRET':'never-print-this'}}}
            for function,flag in p.WORKERS.values()}
        self.lam=SimpleNamespace(
            get_function_configuration=Mock(side_effect=lambda **kw:self.configs[kw['FunctionName']]),
            get_function_concurrency=Mock(return_value={'ReservedConcurrentExecutions':0}))
        self.rows={table+key['PK']['S']:{**copy.deepcopy(key),'status':{'S':'STARTED'},
            'reservation_status':{'S':'HELD'},'reserved_micro_usd':{'N':'250000'},
            'private_field':{'S':'never-print-this'}} for table,key in p.ATTEMPTS.values()}
        self.db=SimpleNamespace(get_item=Mock(side_effect=lambda **kw:{'Item':self.rows.get(kw['TableName']+kw['Key']['PK']['S'])}))

    def observe(self):
        with patch.object(p.DynamoDBStateStore,'load_state',return_value=SimpleNamespace(state='PAUSED',version=0,leases=[])):
            return p.observe(sts=self.sts,lam=self.lam,db=self.db,clock=lambda:self.now)

    def test_thirteen_consumed_holds_without_secrets_or_write_clients(self):
        report=self.observe()
        self.assertEqual(report['status'],'OBSERVED')
        self.assertEqual(report['known_reserved_micro_usd'],3250000)
        self.assertTrue(report['reservation_total_complete'])
        self.assertTrue(report['all_workers_disabled_observed'])
        self.assertNotIn('never-print-this',json.dumps(report))
        self.assertFalse(report['gate_authority']);self.assertFalse(report['execution_authorized'])
        self.assertEqual(self.db.get_item.call_count,13)
        self.assertTrue(all(c.kwargs['ConsistentRead'] for c in self.db.get_item.call_args_list))

    def test_missing_and_failed_reads_never_mean_authorized_or_disabled(self):
        self.rows.clear()
        self.lam.get_function_concurrency.side_effect=RuntimeError('never-print-this')
        report=self.observe()
        self.assertEqual(report['status'],'INCOMPLETE')
        self.assertFalse(report['all_workers_disabled_observed'])
        self.assertTrue(all(a['status']=='ABSENT' and not a['attempt_reusable'] for a in report['attempts'].values()))
        self.assertNotIn('never-print-this',json.dumps(report))

    def test_wrong_account_stops_before_resource_reads(self):
        self.sts.get_caller_identity.return_value={'Account':'000000000000'}
        with self.assertRaises(StateError):self.observe()
        self.db.get_item.assert_not_called();self.lam.get_function_configuration.assert_not_called()

    def test_bad_money_is_unknown_not_zero_complete_total(self):
        next(iter(self.rows.values()))['reserved_micro_usd']={'N':'NaN'}
        report=self.observe()
        self.assertFalse(report['reservation_total_complete'])
        self.assertEqual(report['status'],'INCOMPLETE')

    def test_unreserved_capacity_or_enabled_flag_never_reports_disabled(self):
        self.lam.get_function_concurrency.return_value={}
        self.assertFalse(self.observe()['all_workers_disabled_observed'])
        self.lam.get_function_concurrency.return_value={'ReservedConcurrentExecutions':0}
        function,flag=p.WORKERS['builder']
        self.configs[function]['Environment']['Variables'][flag]='true'
        self.assertFalse(self.observe()['all_workers_disabled_observed'])

    def test_wrong_worker_arn_or_missing_flag_is_unknown(self):
        function,flag=p.WORKERS['builder']
        self.configs[function]['FunctionArn']='wrong'
        report=self.observe()
        self.assertEqual(report['workers']['builder']['status'],'UNKNOWN')

    def test_reported_actual_is_not_invoice_or_total_spend(self):
        next(iter(self.rows.values()))['actual_micro_usd']={'N':'87664'}
        report=self.observe()
        self.assertEqual(report['known_reported_actual_micro_usd'],87664)
        self.assertFalse(report['invoice_verified'])

    def test_observer_has_no_provider_budget_but_enabled_flag_prevents_all_disabled(self):
        self.assertNotIn('handoff002_observer',p.ATTEMPTS)
        function,flag=p.WORKERS['handoff002_observer']
        self.configs[function]['Environment']['Variables'][flag]='true'
        report=self.observe()
        self.assertFalse(report['all_workers_disabled_observed'])
        self.assertEqual(len(report['attempts']),13)

    def test_handoff_attempts_use_separate_fixed_tables_and_keys(self):
        for number in ('001', '002'):
            for role in ('builder', 'inspector', 'qa'):
                name = 'handoff'+number+'_'+role
                table, key = p.ATTEMPTS[name]
                self.assertEqual(table, f'tims-factory-handoff-{number}-attempts')
                self.assertEqual(key, {'PK': {'S': f'HANDOFF#{number}#TASK#authenticated-handoff-{number}#ROLE#{role}'}})
        table, key = p.ATTEMPTS['handoff001_qa']
        del self.rows[table+key['PK']['S']]
        report = self.observe()
        self.assertEqual(report['attempts']['handoff001_qa']['status'], 'ABSENT')
        self.assertEqual(report['known_reserved_micro_usd'], 3000000)
        self.assertFalse(report['attempts']['handoff001_qa']['attempt_reusable'])
        self.assertIn('authoritative task is Pilot 002 only', report['scope'])
