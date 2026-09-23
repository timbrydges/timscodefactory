from __future__ import annotations

import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from factory_runtime.autonomy import AutonomyActivation
from factory_runtime.operational_backend import AcceptanceOperationalBackend
from factory_state.dispatch import DispatchRequest
from factory_state.model import CONTROLLER_IDENTITY, StateError, TaskState


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 23, 2, tzinfo=timezone.utc)
COMMIT = "a" * 40
CONTRACT = "sha256:" + "b" * 64


class Budget:
    def __init__(self):
        self.calls = []

    def reserve(self, **kwargs):
        self.calls.append(kwargs)


class Executor:
    def __init__(self, output=b"accepted"):
        self.output = output
        self.calls = []

    def execute(self, **kwargs):
        self.calls.append(kwargs)
        return self.output


class OperationalBackendTests(unittest.TestCase):
    def active_root(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        shutil.copytree(ROOT / "factory", root / "factory")
        shutil.copytree(ROOT / "docs", root / "docs")
        path = root / "factory/autonomy/operating-contract.yaml"
        contract = yaml.safe_load(path.read_text(encoding="utf-8"))
        contract["status"] = "ACTIVE"
        contract["activation"]["pending_gates"] = []
        path.write_text(yaml.safe_dump(contract, sort_keys=False), encoding="utf-8")
        return root

    def backend(self, root, *, enabled):
        activation = AutonomyActivation(
            "factory-autonomy-001",
            "factory",
            "deterministic-text-fingerprint",
            COMMIT,
            CONTRACT,
            NOW - timedelta(minutes=1),
            NOW + timedelta(hours=1),
        )
        budget, executor = Budget(), Executor()
        return AcceptanceOperationalBackend(root, activation, budget, executor, enabled), budget, executor

    def state_request(self):
        state = TaskState(
            "factory", "deterministic-text-fingerprint", "IMPLEMENTATION", 1, NOW, CONTROLLER_IDENTITY
        )
        request = DispatchRequest("lease-123", "autonomy", "acceptance", COMMIT, CONTRACT, "sha256:" + "c" * 64)
        return state, request

    def test_checked_in_contract_and_default_backend_both_deny(self):
        state, request = self.state_request()
        for root, enabled, message in ((ROOT, True, "pending"), (self.active_root(), False, "disabled")):
            backend, _, _ = self.backend(root, enabled=enabled)
            with self.subTest(message=message):
                with self.assertRaisesRegex(StateError, message):
                    backend.check_activation(state, request, now=NOW)

    def test_active_exact_binding_reserves_and_executes_only_approved_target(self):
        backend, budget, executor = self.backend(self.active_root(), enabled=True)
        state, request = self.state_request()
        backend.check_activation(state, request, now=NOW)
        backend.reserve(state, request, dispatch_id="dispatch-1", now=NOW)
        self.assertEqual(backend.execute(state, request, dispatch_id="dispatch-1", input_bytes=b"input"), b"accepted")
        self.assertEqual(budget.calls[0]["maximum_provider_calls"], 3)
        self.assertEqual(str(budget.calls[0]["maximum_cost_usd"]), "0.25")
        self.assertEqual(executor.calls[0]["target_alias"], "coding_primary_sol_live")
        self.assertEqual(executor.calls[0]["model_id"], "gpt-5.6-sol")

    def test_wrong_task_commit_contract_and_oversized_input_fail_closed(self):
        backend, _, executor = self.backend(self.active_root(), enabled=True)
        state, request = self.state_request()
        wrong_state = TaskState("factory", "other", "IMPLEMENTATION", 1, NOW, CONTROLLER_IDENTITY)
        with self.assertRaisesRegex(StateError, "binding"):
            backend.check_activation(wrong_state, request, now=NOW)
        with self.assertRaisesRegex(StateError, "cost bound"):
            backend.execute(state, request, dispatch_id="dispatch-1", input_bytes=b"x" * 42021)
        self.assertEqual(executor.calls, [])


if __name__ == "__main__":
    unittest.main()
