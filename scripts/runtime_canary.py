#!/usr/bin/env python3
"""Run the Factory Docker runtime against a real isolated canary fixture.

This is deliberately non-authoritative. It proves the concrete detector,
provisioner handoff and hardened verification sandbox work on a real Docker
engine. It creates no Factory Evidence and mutates no Factory state.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from factory_runtime.detector import BaseImagePolicy  # noqa: E402
from factory_runtime.docker_provisioner import DockerProvisioningPolicy  # noqa: E402
from factory_runtime.docker_sandbox import workspace_tree_digest  # noqa: E402
from factory_runtime.pipeline import RuntimeInvocation, build_docker_runtime_pipeline  # noqa: E402


PINNED_PYTHON_IMAGE = re.compile(r"^python@sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--source-commit", required=True)
    return parser.parse_args()


async def run_canary(workspace: Path, image_ref: str, source_commit: str) -> dict[str, object]:
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise RuntimeError("canary workspace does not exist")
    if not PINNED_PYTHON_IMAGE.fullmatch(image_ref):
        raise RuntimeError("canary base image must be a resolved immutable python@sha256 reference")
    if not COMMIT.fullmatch(source_commit):
        raise RuntimeError("source commit must be an exact 40-character SHA")

    before_digest = workspace_tree_digest(workspace)
    image_policy = BaseImagePolicy(images=(("python:3.12", image_ref),))
    provisioning_policy = DockerProvisioningPolicy()
    pipeline = build_docker_runtime_pipeline(
        workspace,
        image_policy,
        provisioning_policy,
    )
    invocation = RuntimeInvocation(
        run_id="runtime-canary-v1",
        task_id="runtime-canary-task",
        lease_id="runtime-canary-lease",
        role_id="engineering_agent",
        source_commit=source_commit,
        command=("python", "-m", "unittest", "discover", "-s", "tests", "-v"),
        expected_provisioner_identity="factory_docker_provisioner_v1",
        expected_runner_identity="factory_docker_sandbox_v1",
        provisioning_timeout_seconds=300,
        verification_timeout_seconds=180,
    )

    result = await pipeline.run(invocation)
    after_digest = workspace_tree_digest(workspace)
    if after_digest != before_digest:
        raise RuntimeError("authoritative canary workspace changed during runtime execution")
    if result.detection.stack != "python" or result.detection.runtime_version != "3.12":
        raise RuntimeError("canary detector resolved an unexpected runtime")
    if result.detection.spec.steps:
        raise RuntimeError("canary v1 unexpectedly requested networked dependency provisioning")
    if result.detection.spec.network_policy_id is not None:
        raise RuntimeError("canary v1 unexpectedly requested a network policy")
    if result.provisioning.receipt.result_image_ref != image_ref:
        raise RuntimeError("provisioner did not preserve the immutable no-dependency image handoff")
    if result.verification.receipt.exit_code != 0 or result.verification.receipt.timed_out:
        raise RuntimeError("hardened verification sandbox did not complete successfully")

    return {
        "status": "PASS",
        "stack": result.detection.stack,
        "runtime_version": result.detection.runtime_version,
        "workspace_digest": result.workspace_digest,
        "environment_spec_digest": result.detection.spec.digest,
        "provisioned_image_ref": result.provisioning.receipt.result_image_ref,
        "verification_environment_digest": result.verification.receipt.environment_digest,
        "verification_stdout_digest": result.verification.receipt.stdout_digest,
        "verification_stderr_digest": result.verification.receipt.stderr_digest,
        "verification_exit_code": result.verification.receipt.exit_code,
        "networked_provisioning": False,
        "authoritative_state_mutation": False,
    }


def main() -> int:
    args = parse_args()
    summary = asyncio.run(run_canary(args.workspace, args.image_ref, args.source_commit))
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
