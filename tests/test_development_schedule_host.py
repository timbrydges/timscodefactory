import asyncio
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import AsyncMock,Mock,patch
import sys

from factory_runtime.development_schedule import DevelopmentSchedule
from factory_runtime.development_schedule_host import ScheduledPacketHost,decode_packet,poll_schedule
from factory_state.model import StateError


class HostTests(TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        for name in ('packets','attempts','repo'): (self.base/name).mkdir()
        self.schedule=DevelopmentSchedule(self.base/'schedule.db')
        self.now=datetime(2026,1,1,tzinfo=timezone.utc)
        contract='{"task_id":"offline-fake"}'
        pins={'attempt_id':'job-1','contract_digest':'sha256:'+hashlib.sha256(contract.encode()).hexdigest()}
        self.packet={'pins':pins,'approval':{'pins':pins,'expires_at':(self.now+timedelta(hours=1)).isoformat()},
            'pricing':{},'contract':contract,'execution_profile':{}}
        self.raw=json.dumps(self.packet).encode()
        self.execute=AsyncMock(return_value={'status':'TICK_COMPLETED'})
        self.host=ScheduledPacketHost(packet_directory=self.base/'packets',
            attempt_directory=self.base/'attempts',repository_path=self.base/'repo',
            execute=self.execute,owner_authorized=True)

    def poll(self,**changes):
        options=dict(clock=lambda:self.now,enabled=True,max_ticks=2,sleep=AsyncMock())
        options.update(changes)
        return asyncio.run(poll_schedule(self.schedule,self.host,**options))

    def test_admission_then_fixed_dispatch_retains_exact_contract_and_no_replay(self):
        self.host.admit(self.schedule,self.raw,due_at=self.now)
        self.schedule.pause(False)
        self.assertEqual(self.poll()['ticks'],2)
        self.execute.assert_awaited_once()
        args=self.execute.call_args.args[0]
        self.assertEqual(args.contract.read_bytes(),self.packet['contract'].encode())
        self.assertEqual(json.loads(args.pins.read_bytes()),self.packet['pins'])
        self.assertEqual(args.repository_path,self.base/'repo')
        self.assertEqual(args.attempt_directory,self.base/'attempts/job-1')
        self.assertTrue(args.owner_authorized)

    def test_disabled_does_not_touch_schedule_or_host(self):
        schedule=Mock();host=Mock()
        result=asyncio.run(poll_schedule(schedule,host,clock=Mock(),enabled=False))
        self.assertEqual(result['ticks'],0)
        self.assertEqual(schedule.mock_calls,[])
        self.assertEqual(host.mock_calls,[])

    def test_owner_required_and_packet_changes_stop_before_execute(self):
        self.host.owner_authorized=False
        with self.assertRaises(StateError): self.host.admit(self.schedule,self.raw,due_at=self.now)
        self.host.owner_authorized=True
        self.host.admit(self.schedule,self.raw,due_at=self.now)
        (self.base/'packets/job-1.json').write_bytes(self.raw+b' ')
        self.schedule.pause(False)
        result=self.poll()
        self.assertEqual(result['last_result']['status'],'IDLE_OR_PAUSED')
        self.assertEqual(result['outcomes']['REJECTED'],1)
        self.assertEqual(self.schedule.status('job-1'),'REJECTED')
        self.execute.assert_not_awaited()

    def test_uncertain_dispatch_stops_polling(self):
        self.host.admit(self.schedule,self.raw,due_at=self.now)
        self.schedule.pause(False)
        self.execute.side_effect=RuntimeError('private failure')
        sleep=AsyncMock()
        result=self.poll(sleep=sleep,max_ticks=20)
        self.assertEqual(result['ticks'],1)
        self.assertEqual(result['last_result']['status'],'NEEDS_RECONCILIATION')
        sleep.assert_not_awaited()

    def test_existing_inputs_never_overwritten_or_replayed(self):
        self.host.admit(self.schedule,self.raw,due_at=self.now)
        (self.base/'attempts/job-1-inputs').mkdir()
        self.schedule.pause(False)
        self.assertEqual(self.poll()['last_result']['status'],'NEEDS_RECONCILIATION')
        self.execute.assert_not_awaited()

    def test_packet_rejects_unsafe_paths_duplicate_keys_and_changed_contract(self):
        for name in ('../escape','CON','nul','a/b','a.'):
            value=json.loads(self.raw);value['pins']['attempt_id']=name
            value['approval']['pins']=value['pins']
            with self.assertRaises(StateError): decode_packet(json.dumps(value).encode())
        value=json.loads(self.raw);value['contract']='changed'
        with self.assertRaises(StateError): decode_packet(json.dumps(value).encode())
        with self.assertRaises(StateError): decode_packet(b'{"pins":{},"pins":{}}')
        with self.assertRaises(StateError): decode_packet(b' '*262145)

    def test_paused_polling_sleeps_bounded_count_without_dispatch(self):
        self.host.admit(self.schedule,self.raw,due_at=self.now)
        sleep=AsyncMock()
        self.assertEqual(self.poll(sleep=sleep,max_ticks=3,interval_seconds=5)['ticks'],3)
        self.assertEqual(sleep.await_count,2)
        self.execute.assert_not_awaited()

    def test_schedule_cli_default_does_not_create_files_or_execute(self):
        scripts=Path(__file__).resolve().parents[1]/'scripts'
        with patch.object(sys,'path',[str(scripts)]+sys.path):
            spec=importlib.util.spec_from_file_location('schedule_cli',scripts/'development_schedule.py')
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        with patch.object(module,'DevelopmentSchedule') as db,patch.object(module,'execute') as execute:
            self.assertEqual(module.main([]),0)
            db.assert_not_called()
            execute.assert_not_called()

    def test_schedule_cli_preserves_operator_binding_in_fixed_dispatch(self):
        scripts=Path(__file__).resolve().parents[1]/'scripts'
        with patch.object(sys,'path',[str(scripts)]+sys.path):
            spec=importlib.util.spec_from_file_location('schedule_binding_cli',scripts/'development_schedule.py')
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        binding=object()
        with patch.object(module,'execute',new_callable=AsyncMock) as execute, \
                patch.object(module,'poll_schedule',new_callable=AsyncMock,
                             return_value={'outcomes':{}}) as poll:
            self.assertEqual(module.main(['--enable','--owner-authorized','--action','run',
                '--host-directory',str(self.base),'--repository-path',str(self.base/'repo')],
                credential_binding=binding),0)
            host=poll.call_args.args[1]
            self.assertIs(host.execute.func,execute)
            self.assertIs(host.execute.keywords['credential_binding'],binding)
            execute.assert_not_awaited()

    def test_schedule_cli_bootstrap_requires_enabled_owner_run(self):
        scripts=Path(__file__).resolve().parents[1]/'scripts'
        with patch.object(sys,'path',[str(scripts)]+sys.path):
            spec=importlib.util.spec_from_file_location('schedule_config_cli',scripts/'development_schedule.py')
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        with patch.object(module,'binding_from_configuration',return_value=object()) as bind, \
                patch.object(module,'poll_schedule',new_callable=AsyncMock,
                             return_value={'outcomes':{}}) as poll:
            identity=['--identity-config','operator.json','--identity-config-sha256','sha256:fake']
            self.assertEqual(module.main(identity),0)
            bind.assert_not_called()
            self.assertEqual(module.main(['--enable','--owner-authorized','--action','run',
                '--host-directory',str(self.base),'--repository-path',str(self.base/'repo')]+identity),0)
            bind.assert_called_once()
            self.assertIs(poll.call_args.args[1].execute.keywords['credential_binding'],bind.return_value)
