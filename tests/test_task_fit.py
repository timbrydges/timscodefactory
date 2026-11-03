"""Every Bonus Library task fits the Factory limits before any money is spent.

Uses the source sizes recorded in each task contract (source_file_bytes), the
reviewed lessons, the trusted delivery block and a worst-case second repair
(maximum findings and summary), so CI catches a task that would stop at
BINDING or exceed the provider request cap.
"""
import importlib.util
import json
from pathlib import Path
import unittest

from factory_runtime.development_composition import BONUS_TASKS
from factory_runtime import openai_provider as op
from factory_runtime.task_provider import TaskImplementationProtocol
from factory_runtime.task_queue import QueuedTask
from factory_runtime.worker import digest

ROOT = Path(__file__).resolve().parents[1]
spec_ = importlib.util.spec_from_file_location('prepare_fit', ROOT/'scripts'/'prepare_development_attempt.py')
prep = importlib.util.module_from_spec(spec_); spec_.loader.exec_module(prep)

# Real source text needs JSON escaping that placeholder text does not. Calibrated on
# the ai-cover-wiring, search and backend sources: at most 4.3% of file bytes in the
# turn and 10% in the provider request; these margins add headroom.
TURN_ESCAPING, REQUEST_ESCAPING = 0.06, 0.13
TURN_LIMIT, REPAIR_LIMIT, REQUEST_LIMIT = 32000, 40000, 42020


def request_bytes(turn):
    payload = {"model": "gpt-5.6-sol", "store": False, "service_tier": "default",
        "prompt_cache_options": {"mode": "explicit"}, "instructions": op._instructions('task_implementation'),
        "input": json.dumps(turn, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        "max_output_tokens": 16384, "reasoning": {"effort": "low"},
        "text": {"format": {"type": "json_schema", "name": "factory_repair_decision", "strict": True,
                            "schema": op._decision_schema('task_implementation')}}}
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


class TaskFitTests(unittest.TestCase):
    def test_every_task_fits_turn_and_request_limits(self):
        for task_id, (required, command) in BONUS_TASKS.items():
            with self.subTest(task=task_id):
                raw = prep.contract_with_lessons((ROOT/'factory/projects'/task_id/'task.json').read_bytes())
                spec = json.loads(raw)
                sizes = spec.get('source_file_bytes')
                self.assertIsInstance(sizes, dict, 'record source_file_bytes for allowed paths present at target')
                self.assertLessEqual(set(sizes), set(spec['allowed_paths']))
                files = {p: 'x' * n for p, n in sizes.items()}
                task = QueuedTask('fit-001', 'development-local', task_id, 'fit-001', 'a'*40,
                                  digest(raw), 'IMPLEMENTATION')
                proto = TaskImplementationProtocol(task, repository=spec['repository'],
                    target_commit=spec['target_commit'], contract_bytes=raw, files=files,
                    missing_paths=[p for p in spec['allowed_paths'] if p not in sizes],
                    delivery={'mode': 'complete_task_single_proposal',
                              'required_changed_paths': list(required), 'test_command': list(command)})
                total = sum(sizes.values())
                self.assertLessEqual(len(proto._raw) + total * TURN_ESCAPING, TURN_LIMIT, 'implementation turn')
                repair = proto.repair_turn(rejected_decision={'type': 'apply_edits', 'summary': 's' * 1000, 'edits': []},
                                           findings=['f' * 1990] * 4, round_number=2, rounds=2)
                repair_raw = len(json.dumps(repair, sort_keys=True, separators=(',', ':')).encode())
                self.assertLessEqual(repair_raw + total * TURN_ESCAPING, REPAIR_LIMIT, 'repair turn')
                self.assertLessEqual(request_bytes(repair) + total * REQUEST_ESCAPING, REQUEST_LIMIT,
                                     'worst-case repair provider request')


if __name__ == '__main__':
    unittest.main()
