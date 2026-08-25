#!/usr/bin/env python3
"""Static supply-chain checks for Factory GitHub Actions workflows."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml


PINNED_ACTION = re.compile(r"^\s*-\s+uses:\s+[^\s@]+@([0-9a-f]{40})\s*$", re.MULTILINE)
ANY_ACTION = re.compile(r"^\s*-\s+uses:\s+([^\s]+)\s*$", re.MULTILINE)


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    workflow_dir = root / ".github/workflows"
    workflows = sorted(workflow_dir.glob("*.yml"))
    if not workflows:
        return ["no GitHub Actions workflows found"]
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        try:
            yaml.safe_load(text)
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: invalid YAML: {exc}")
        for action in ANY_ACTION.findall(text):
            if not re.search(r"@[0-9a-f]{40}$", action):
                errors.append(f"{path.name}: action is not pinned by full commit SHA: {action}")
        if "permissions:" not in text:
            errors.append(f"{path.name}: explicit permissions block is required")
        if re.search(r"secrets\.(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)", text):
            errors.append(f"{path.name}: long-lived AWS credential secret is prohibited")

    release_path = workflow_dir / "release-oidc.yml"
    rollback_path = workflow_dir / "rollback-oidc.yml"
    if not release_path.is_file():
        errors.append("release-oidc.yml: workflow is missing")
        return errors
    if not rollback_path.is_file():
        errors.append("rollback-oidc.yml: deterministic rollback workflow is missing")
        return errors

    release = release_path.read_text(encoding="utf-8")
    required_release_fragments = [
        "id-token: write",
        "environment: production",
        "group: factory-production-release",
        "cancel-in-progress: false",
        'test "$GITHUB_REF" = "refs/heads/main"',
        "rollback_source_commit",
        "OWNER_OVERRIDE",
        "verify-build-run",
        "verify-authority",
        "gh attestation verify",
        "INITIAL_RELEASE",
        "AWS_RELEASE_ROLE_ARN",
        "GH_TOKEN: ${{ github.token }}",
        "--checksum-sha256",
        "object-version",
        "--version-id",
        "--checksum-mode ENABLED",
        "prepare-release",
        "transact-write-items",
        "verify-current",
        "FACTORY#tims-software-factory#RELEASE",
    ]
    for fragment in required_release_fragments:
        if fragment not in release:
            errors.append(f"release-oidc.yml: missing fail-closed control: {fragment}")
    if "pull_request:" in release or "push:" in release:
        errors.append("release-oidc.yml: production release must be explicitly dispatched")
    if "rollback_object_version" in release:
        errors.append("release-oidc.yml: caller-supplied S3 rollback versions are prohibited")

    rollback = rollback_path.read_text(encoding="utf-8")
    required_rollback_fragments = [
        "id-token: write",
        "environment: production",
        "group: factory-production-release",
        "cancel-in-progress: false",
        'test "$GITHUB_REF" = "refs/heads/main"',
        'test "$ACTOR_ID" = "214414801"',
        "target_source_commit",
        "expected_current_source_commit",
        "deployment-location",
        "--version-id",
        "--checksum-mode ENABLED",
        "prepare-rollback",
        "transact-write-items",
        "verify-current",
        "FACTORY#tims-software-factory#RELEASE",
    ]
    for fragment in required_rollback_fragments:
        if fragment not in rollback:
            errors.append(f"rollback-oidc.yml: missing deterministic control: {fragment}")
    if "pull_request:" in rollback or "push:" in rollback:
        errors.append("rollback-oidc.yml: production rollback must be explicitly dispatched")
    if re.search(r"\b(openai|anthropic|bedrock|model|prompt|agent)\b", rollback, re.IGNORECASE):
        errors.append("rollback-oidc.yml: rollback path must remain AI-independent")

    build_attest = (workflow_dir / "build-attest.yml").read_text(encoding="utf-8")
    if "sha256sum factory-control-plane.tar.gz > factory-control-plane.tar.gz.sha256" not in build_attest:
        errors.append("build-attest.yml: checksum must use a portable relative artifact path")
    if 'sha256sum "$RUNNER_TEMP/factory-control-plane.tar.gz"' in build_attest:
        errors.append("build-attest.yml: absolute checksum paths are prohibited")
    required_archive_fragments = [
        'line.split("  ", 1)',
        'paths.append("MANIFEST.sha256")',
        '--use-compress-program="gzip -n"',
        "--null",
        "--verbatim-files-from",
        "--no-recursion",
        '--files-from "$FILE_LIST"',
        "--sort=name",
        "--mtime=@0",
        "--owner=0",
        "--group=0",
        "sha256sum --check MANIFEST.sha256",
    ]
    for fragment in required_archive_fragments:
        if fragment not in build_attest:
            errors.append(f"build-attest.yml: missing deterministic archive control: {fragment}")
    if "tar --exclude=.git" in build_attest:
        errors.append("build-attest.yml: broad workspace archives are prohibited")

    preflight = (workflow_dir / "preflight.yml").read_text(encoding="utf-8")
    required_preflight_fragments = [
        "push:",
        "branches: [main]",
        "github.event_name == 'push'",
        "python scripts/preflight.py --mode live",
    ]
    for fragment in required_preflight_fragments:
        if fragment not in preflight:
            errors.append(f"preflight.yml: missing automatic live control: {fragment}")

    aws_versions = (root / "infra/aws/versions.tf").read_text(encoding="utf-8")
    if 'backend "s3" {}' not in aws_versions:
        errors.append("infra/aws/versions.tf: encrypted remote state backend is required")
    if 'required_version = ">= 1.10.0"' not in aws_versions:
        errors.append("infra/aws/versions.tf: Terraform 1.10+ is required for native S3 state locking")

    bootstrap = (root / "scripts/aws-bootstrap-cloudshell.sh").read_text(encoding="utf-8")
    required_bootstrap_fragments = [
        "put-bucket-versioning",
        "put-bucket-encryption",
        "put-public-access-block",
        'use_lockfile=true',
        "existing_github_oidc_provider_arn",
    ]
    for fragment in required_bootstrap_fragments:
        if fragment not in bootstrap:
            errors.append(f"aws-bootstrap-cloudshell.sh: missing bootstrap control: {fragment}")
    if re.search(r"AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)", bootstrap):
        errors.append("aws-bootstrap-cloudshell.sh: long-lived AWS credentials are prohibited")

    aws_main = (root / "infra/aws/main.tf").read_text(encoding="utf-8")
    required_aws_fragments = [
        "github_repository_owner_id",
        "github_repository_id",
        'variable = "token.actions.githubusercontent.com:sub"',
        "FACTORY#tims-software-factory#TASK#*",
        "FACTORY#tims-software-factory#RELEASE",
        '"dynamodb:TransactWriteItems"',
        '"s3:GetObjectVersion"',
        'check "existing_github_oidc_provider"',
    ]
    for fragment in required_aws_fragments:
        if fragment not in aws_main:
            errors.append(f"infra/aws/main.tf: missing release boundary: {fragment}")

    release_control = (root / "scripts/release_control.py").read_text(encoding="utf-8")
    required_control_fragments = [
        'OWNER_GITHUB_LOGIN = "timbrydges"',
        'RELEASE_IDENTITY = "github_actions_production_environment"',
        "AUTHORIZE_RELEASE:",
        "ConditionExpression",
        "validate_s3_head",
        "prepare_release_transaction",
        "prepare_rollback_transaction",
    ]
    for fragment in required_control_fragments:
        if fragment not in release_control:
            errors.append(f"release_control.py: missing fail-closed implementation: {fragment}")

    github_bootstrap = (root / "scripts/apply_github_controls.py").read_text(encoding="utf-8")
    for fragment in ("actions/oidc/customization/sub", "oidc-subject.json", "2026-03-10"):
        if fragment not in github_bootstrap:
            errors.append(f"apply_github_controls.py: missing immutable OIDC setup: {fragment}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("GitHub Actions supply-chain validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
