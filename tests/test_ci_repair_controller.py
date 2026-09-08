from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.detector import DetectionResult  # noqa: E402
from factory_runtime.docker_sandbox import workspace_tree_digest  # noqa: E402
from factory_runtime.environment import (  # noqa: E402
    EnvironmentSpec,
    ProvisioningReceipt,
    ProvisioningRequest,
    validate_provisioning_receipt,
)
from factory_runtime.pipeline import RuntimeInvocation, RuntimeObservation  # noqa: E402
from factory_runtime.repair import (  # noqa: E402
    BoundedCIRepairController,
    RepairAction,
    RepairEscalation,
    RepairEscalationReason,
    RepairPolicy,
    RepairRequest,
    VerifiedRepairCandidate,
)
from factory_runtime.sandbox import SandboxReceipt, SandboxRequest, bind_sandbox_receipt  # noqa: E402


BASE_IMAGE = "python@sha256:" + "a" * 64
RESULT_IMAGE = "sha256:" + "b" * 64
ENV_DIGEST = "sha256:" + "c" * 64
LOG_DIGEST = "sha256:" + "d" * 64
OUT_DIGEST = "sha256:" + "e" * 64
ERR_DIGEST = "sha256:" + "f" * 64
COMMIT = "1" * 40


def write_workspace(root: Path, status: str = "broken") -> None:
    (root / "status.txt").write_text(status + "\n", encoding="utf-8")


def request(max_seconds: int = 120) -> RepairRequest:
    return RepairRequest(
        repair_id="repair-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        command=("python", "-m", "pytest", "-q"),
        expected_provisioner_identity="fake_provisioner_v1",
        expected_runner_identity="fake_verifier_v1",
        provisioning_timeout_seconds=max_seconds,
        verification_timeout_seconds=max_seconds,
    )


def make_observation(workspace: Path, invocation: RuntimeInvocation, *, exit_code: int | None, timed_out: bool) -> RuntimeObservation:
    now = datetime.now(timezone.utc)
    digest = workspace_tree_digest(workspace)
    spec = EnvironmentSpec(
        stack="python",
        base_image_ref=BASE_IMAGE,
        inputs=(),
        steps=(),
        network_policy_id=None,
    )
    provision_request = ProvisioningRequest(
        request_id=f"{invocation.run_id}.provision",
        task_id=invocation.task_id,
        lease_id=invocation.lease_id,
        role_id=invocation.role_id,
        source_commit=invocation.source_commit,
        workspace_digest=digest,
        environment_spec_digest=spec.digest,
        max_seconds=invocation.provisioning_timeout_seconds,
        expected_provisioner_identity=invocation.expected_provisioner_identity,
    )
    provision_receipt = ProvisioningReceipt(
        request_id=provision_request.request_id,
        task_id=provision_request.task_id,
        lease_id=provision_request.lease_id,
        role_id=provision_request.role_id,
        source_commit=provision_request.source_commit,
        workspace_digest=provision_request.workspace_digest,
        environment_spec_digest=provision_request.environment_spec_digest,
        provisioner_identity=provision_request.expected_provisioner_identity,
        result_image_ref=RESULT_IMAGE,
        started_at=now - timedelta(seconds=3),
        finished_at=now - timedelta(seconds=2),
        exit_code=0,
        timed_out=False,
        build_log_digest=LOG_DIGEST,
    )
    validated_provisioning = validate_provisioning_receipt(
        provision_request,
        spec,
        provision_receipt,
        now=now,
    )
    verify_request = SandboxRequest(
        request_id=f"{invocation.run_id}.verify",
        task_id=invocation.task_id,
        lease_id=invocation.lease_id,
        role_id=invocation.role_id,
        source_commit=invocation.source_commit,
        workspace_digest=digest,
        command=invocation.command,
        environment_digest=ENV_DIGEST,
        timeout_seconds=invocation.verification_timeout_seconds,
        expected_runner_identity=invocation.expected_runner_identity,
    )
    verify_receipt = SandboxReceipt(
        request_id=verify_request.request_id,
        task_id=verify_request.task_id,
        lease_id=verify_request.lease_id,
        role_id=verify_request.role_id,
        source_commit=verify_request.source_commit,
        workspace_digest=verify_request.workspace_digest,
        command_digest=verify_request.command_digest,
        environment_digest=verify_request.environment_digest,
        runner_identity=verify_request.expected_runner_identity,
        sandbox_id="sandbox-repair-1",
        started_at=now - timedelta(seconds=2),
        finished_at=now - timedelta(seconds=1),
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_digest=OUT_DIGEST,
        stderr_digest=ERR_DIGEST,
    )
    return RuntimeObservation(
        detection=DetectionResult(spec=spec, stack="python", runtime_version="3.12"),
        provisioning=validated_provisioning,
        verification_request=verify_request,
        verification=bind_sandbox_receipt(verify_request, verify_receipt, now=now),
        workspace_digest=digest,
    )


class FakePipeline:
    def __init__(self, workspace: Path, owner: "FakePipelineFactory") -> None:
        self.workspace = workspace
        self.owner = owner

    async def observe(self, invocation: RuntimeInvocation) -> RuntimeObservation:
        self.owner.invocations.append(invocation)
        if self.owner.raise_initial and invocation.run_id.endswith(".initial"):
            raise RuntimeError("synthetic initial runtime failure")
        status = (self.workspace / "status.txt").read_text(encoding="utf-8").strip()
        if status == "runtime-error":
            raise RuntimeError("synthetic candidate runtime failure")
        if status == "timeout":
            return make_observation(self.workspace, invocation, exit_code=None, timed_out=True)
        return make_observation(
            self.workspace,
            invocation,
            exit_code=0 if status == "fixed" else 1,
            timed_out=False,
        )


class FakePipelineFactory:
    def __init__(self, *, raise_initial: bool = False) -> None:
        self.raise_initial = raise_initial
        self.invocations: list[RuntimeInvocation] = []

    def create(self, workspace: Path) -> FakePipeline:
        return FakePipeline(workspace, self)


class FixFirstStrategy:
    def __init__(self) -> None:
        self.calls = 0

    async def apply(self, workspace: Path, context) -> RepairAction:
        self.calls += 1
        (workspace / "status.txt").write_text("fixed\n", encoding="utf-8")
        return RepairAction("fix candidate")


class TwoStepStrategy:
    async def apply(self, workspace: Path, context) -> RepairAction:
        status = "still-broken" if context.attempt_number == 1 else "fixed"
        (workspace / "status.txt").write_text(status + "\n", encoding="utf-8")
        return RepairAction(f"attempt {context.attempt_number}")


class AlwaysChangingBrokenStrategy:
    async def apply(self, workspace: Path, context) -> RepairAction:
        (workspace / "status.txt").write_text(
            f"broken-{context.attempt_number}\n",
            encoding="utf-8",
        )
        return RepairAction(f"still broken {context.attempt_number}")


class NoChangeStrategy:
    async def apply(self, workspace: Path, context) -> RepairAction:
        return RepairAction("claimed change without changing files")


class TimeoutStrategy:
    async def apply(self, workspace: Path, context) -> RepairAction:
        (workspace / "status.txt").write_text("timeout\n", encoding="utf-8")
        return RepairAction("candidate times out")


class RuntimeErrorStrategy:
    async def apply(self, workspace: Path, context) -> RepairAction:
        (workspace / "status.txt").write_text("runtime-error\n", encoding="utf-8")
        return RepairAction("candidate cannot execute")


class RaisingStrategy:
    async def apply(self, workspace: Path, context) -> RepairAction:
        raise RuntimeError("strategy failed")


class MutateAuthoritativeStrategy:
    def __init__(self, authoritative: Path) -> None:
        self.authoritative = authoritative

    async def apply(self, workspace: Path, context) -> RepairAction:
        (workspace / "status.txt").write_text("fixed\n", encoding="utf-8")
        (self.authoritative / "status.txt").write_text("tampered\n", encoding="utf-8")
        return RepairAction("unsafe strategy")


class CIRepairControllerTests(unittest.TestCase):
    def _controller(self, root: Path, strategy, *, attempts: int = 3, factory=None):
        return BoundedCIRepairController(
            root,
            factory or FakePipelineFactory(),
            strategy,
            RepairPolicy(max_attempts=attempts),
        )

    def test_verified_candidate_requires_exact_original_command_to_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            factory = FakePipelineFactory()
            strategy = FixFirstStrategy()
            outcome = asyncio.run(self._controller(root, strategy, factory=factory).repair(request()))
            self.assertIsInstance(outcome, VerifiedRepairCandidate)
            assert isinstance(outcome, VerifiedRepairCandidate)
            self.assertEqual(outcome.attempt_number, 1)
            self.assertEqual(outcome.verification.receipt.exit_code, 0)
            self.assertEqual((root / "status.txt").read_text().strip(), "broken")
            self.assertEqual((outcome.workspace / "status.txt").read_text().strip(), "fixed")
            self.assertTrue(all(item.command == request().command for item in factory.invocations))
            self.assertEqual(
                [item.run_id for item in factory.invocations],
                ["repair-1.initial", "repair-1.attempt-1"],
            )
            candidate = outcome.workspace
            outcome.cleanup()
            self.assertFalse(candidate.exists())

    def test_strategy_cannot_claim_success_without_candidate_file_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            outcome = asyncio.run(self._controller(root, NoChangeStrategy()).repair(request()))
            self.assertIsInstance(outcome, RepairEscalation)
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(outcome.reason, RepairEscalationReason.NO_CANDIDATE_CHANGE)

    def test_initial_command_must_reproduce_failure_before_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root, "fixed")
            strategy = FixFirstStrategy()
            outcome = asyncio.run(self._controller(root, strategy).repair(request()))
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(outcome.reason, RepairEscalationReason.INITIAL_COMMAND_PASSED)
            self.assertEqual(strategy.calls, 0)

    def test_initial_timeout_escalates_without_strategy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root, "timeout")
            strategy = FixFirstStrategy()
            outcome = asyncio.run(self._controller(root, strategy).repair(request()))
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(outcome.reason, RepairEscalationReason.INITIAL_TIMEOUT)
            self.assertEqual(strategy.calls, 0)

    def test_initial_runtime_failure_escalates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            outcome = asyncio.run(
                self._controller(
                    root,
                    FixFirstStrategy(),
                    factory=FakePipelineFactory(raise_initial=True),
                ).repair(request())
            )
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(outcome.reason, RepairEscalationReason.INITIAL_RUNTIME_FAILURE)

    def test_two_attempts_may_succeed_but_never_change_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            factory = FakePipelineFactory()
            outcome = asyncio.run(
                self._controller(root, TwoStepStrategy(), attempts=2, factory=factory).repair(request())
            )
            assert isinstance(outcome, VerifiedRepairCandidate)
            self.assertEqual(outcome.attempt_number, 2)
            self.assertEqual(len(outcome.actions), 2)
            self.assertTrue(all(item.command == request().command for item in factory.invocations))
            outcome.cleanup()

    def test_attempt_cap_escalates_instead_of_unbounded_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            factory = FakePipelineFactory()
            outcome = asyncio.run(
                self._controller(
                    root,
                    AlwaysChangingBrokenStrategy(),
                    attempts=2,
                    factory=factory,
                ).repair(request())
            )
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(outcome.reason, RepairEscalationReason.ATTEMPT_LIMIT_REACHED)
            self.assertEqual(outcome.attempts, 2)
            self.assertEqual(len(factory.invocations), 3)  # initial + exactly two attempts

    def test_candidate_verification_timeout_escalates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            outcome = asyncio.run(self._controller(root, TimeoutStrategy()).repair(request()))
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(outcome.reason, RepairEscalationReason.VERIFICATION_TIMEOUT)

    def test_candidate_runtime_failure_escalates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            outcome = asyncio.run(self._controller(root, RuntimeErrorStrategy()).repair(request()))
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(outcome.reason, RepairEscalationReason.CANDIDATE_RUNTIME_FAILURE)

    def test_strategy_failure_escalates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            outcome = asyncio.run(self._controller(root, RaisingStrategy()).repair(request()))
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(outcome.reason, RepairEscalationReason.STRATEGY_FAILURE)

    def test_authoritative_workspace_mutation_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_workspace(root)
            outcome = asyncio.run(
                self._controller(root, MutateAuthoritativeStrategy(root)).repair(request())
            )
            assert isinstance(outcome, RepairEscalation)
            self.assertEqual(
                outcome.reason,
                RepairEscalationReason.AUTHORITATIVE_WORKSPACE_CHANGED,
            )

    def test_repair_policy_is_hard_bounded(self):
        with self.assertRaises(Exception):
            RepairPolicy(max_attempts=0)
        with self.assertRaises(Exception):
            RepairPolicy(max_attempts=9)


if __name__ == "__main__":
    unittest.main()
