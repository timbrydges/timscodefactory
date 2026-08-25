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

    release = (workflow_dir / "release-oidc.yml").read_text(encoding="utf-8")
    required_release_fragments = [
        "id-token: write",
        "environment: production",
        "cancel-in-progress: false",
        "gh attestation verify",
        "rollback_object_version",
        "INITIAL_RELEASE",
        "AWS_RELEASE_ROLE_ARN",
        "GH_TOKEN: ${{ github.token }}",
    ]
    for fragment in required_release_fragments:
        if fragment not in release:
            errors.append(f"release-oidc.yml: missing fail-closed control: {fragment}")
    if "pull_request:" in release or "push:" in release:
        errors.append("release-oidc.yml: production release must be explicitly dispatched")

    build_attest = (workflow_dir / "build-attest.yml").read_text(encoding="utf-8")
    if "sha256sum factory-control-plane.tar.gz > factory-control-plane.tar.gz.sha256" not in build_attest:
        errors.append("build-attest.yml: checksum must use a portable relative artifact path")
    if 'sha256sum "$RUNNER_TEMP/factory-control-plane.tar.gz"' in build_attest:
        errors.append("build-attest.yml: absolute checksum paths are prohibited")

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
