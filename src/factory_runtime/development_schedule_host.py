"""Fixed-entrypoint scheduled host. No dynamic executable or credential routing."""
import asyncio
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

from factory_state.model import StateError
from .development_schedule import scheduled_tick


def decode_packet(raw):
    if type(raw) is not bytes or len(raw) > 262144:
        raise StateError('bounded scheduled packet required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate packet key')
            result[key] = value
        return result
    try:
        packet = json.loads(raw, object_pairs_hook=unique)
        if (type(packet) is not dict or set(packet) != {
                'pins','approval','pricing','contract','execution_profile'}
                or any(type(packet[k]) is not dict for k in
                       ('pins','approval','pricing','execution_profile'))
                or type(packet['contract']) is not str):
            raise ValueError()
        pins = packet['pins']
        job = pins['attempt_id']
        if (type(job) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}',job)
                or re.fullmatch(r'(con|prn|aux|nul|com[0-9]|lpt[0-9])',job)
                or packet['approval'].get('pins') != pins
                or hashlib.sha256(packet['contract'].encode('utf-8')).hexdigest()
                    != pins['contract_digest'].removeprefix('sha256:')):
            raise ValueError()
        expiry = datetime.fromisoformat(packet['approval']['expires_at'])
        if expiry.tzinfo is None or expiry.utcoffset() is None:
            raise ValueError()
        return packet
    except (KeyError, ValueError, TypeError, AttributeError):
        raise StateError('invalid scheduled packet binding') from None


class ScheduledPacketHost:
    def __init__(self, *, packet_directory, attempt_directory, repository_path,
                 execute, owner_authorized=False):
        # Operator-owned directories and fixed execute function, never packet fields.
        self.packets = Path(packet_directory)
        self.attempts = Path(attempt_directory)
        self.repository = Path(repository_path)
        if any(not p.is_dir() or p.is_symlink() for p in (self.packets,self.attempts,self.repository)):
            raise StateError('existing regular host directories required')
        self.execute = execute
        self.owner_authorized = owner_authorized

    def admit(self, schedule, raw, *, due_at):
        if self.owner_authorized is not True:
            raise StateError('explicit host owner authorization required')
        packet = decode_packet(raw)
        job = packet['pins']['attempt_id']
        path = self.packets/(job+'.json')
        # Never replace or repair an existing input after uncertain admission.
        with path.open('xb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        schedule.admit(job,'sha256:'+hashlib.sha256(raw).hexdigest(),due_at=due_at,
            expires_at=datetime.fromisoformat(packet['approval']['expires_at']),
            operator_authorized=True)

    def load_packet(self, job):
        if type(job) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}',job):
            raise StateError('invalid scheduled job path')
        path = self.packets/(job+'.json')
        if path.is_symlink():
            raise StateError('symlinked schedule packet prohibited')
        with path.open('rb') as handle:
            raw = handle.read(262145)
        if decode_packet(raw)['pins']['attempt_id'] != job:
            raise StateError('schedule packet identity differs')
        return raw

    async def dispatch(self, raw):
        if self.owner_authorized is not True:
            raise StateError('explicit host owner authorization required')
        packet = decode_packet(raw)
        job = packet['pins']['attempt_id']
        inputs = self.attempts/(job+'-inputs')
        inputs.mkdir(exist_ok=False)
        for name,value in packet.items():
            data = value.encode('utf-8') if name=='contract' else json.dumps(value,sort_keys=True).encode('utf-8')
            with (inputs/(name+'.json')).open('xb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        args = SimpleNamespace(owner_authorized=True,
            pins=inputs/'pins.json',approval=inputs/'approval.json',
            pricing=inputs/'pricing.json',contract=inputs/'contract.json',
            execution_profile=inputs/'execution_profile.json',
            repository_path=self.repository,attempt_directory=self.attempts/job)
        # execute rechecks clean source, exact approval, pricing, profile and receipt.
        result = await self.execute(args)
        return result.get('status') if type(result) is dict else 'NEEDS_RECONCILIATION'


async def poll_schedule(schedule, host, *, clock, enabled=False, max_ticks=1,
                        interval_seconds=60, sleep=asyncio.sleep):
    if type(enabled) is not bool:
        raise StateError('explicit scheduler enable flag required')
    if not enabled:
        return {'status':'DISABLED','ticks':0}
    if (host.owner_authorized is not True or type(max_ticks) is not int
            or not 1 <= max_ticks <= 28800 or type(interval_seconds) is not int
            or not 1 <= interval_seconds <= 3600):
        raise StateError('bounded owner-authorized polling required')
    result = None
    outcomes = {}
    for index in range(max_ticks):
        result = await scheduled_tick(schedule,load_packet=host.load_packet,
            dispatch=host.dispatch,clock=clock,enabled=True)
        outcomes[result['status']] = outcomes.get(result['status'], 0) + 1
        # Stop the host on uncertainty; never proceed to another costly job.
        if result['status']=='NEEDS_RECONCILIATION':
            break
        if index+1 < max_ticks:
            await sleep(interval_seconds)
    return {'status':'POLLING_FINISHED','ticks':index+1,'last_result':result,'outcomes':outcomes}
