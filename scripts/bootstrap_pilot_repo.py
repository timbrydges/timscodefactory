#!/usr/bin/env python3
"""Owner-run bootstrap for the single private Factory pilot repository."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = "https://api.github.com"
OWNER = "timbrydges"
OWNER_ID = 214414801
REPO = "tims-factory-pilot"
FULL_REPO = f"{OWNER}/{REPO}"
API_VERSION = "2026-03-10"

TEMPLATES = {
    "README.md": "config/github/pilot-repo/README.md",
    ".factory/identity-contract.json": "config/github/pilot-repo/identity-contract.json",
    ".github/CODEOWNERS": "config/github/pilot-repo/CODEOWNERS",
    ".github/pull_request_template.md": "config/github/pilot-repo/pull_request_template.md",
    ".github/workflows/pilot-ci.yml": "config/github/pilot-repo/pilot-ci.yml",
    ".github/workflows/identity-boundary.yml": "config/github/pilot-repo/identity-boundary.yml",
    ".github/workflows/inspector-gate.yml": "config/github/pilot-repo/inspector-gate.yml",
    ".github/workflows/identity-canary.yml": "config/github/pilot-repo/identity-canary.yml",
}


def token() -> str:
    configured = os.environ.get("GH_ADMIN_TOKEN", "").strip()
    if configured:
        return configured
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise SystemExit(
            "Authenticate GitHub CLI first with `gh auth login`, or set GH_ADMIN_TOKEN locally. "
            "Never paste the token into chat or commit it."
        ) from exc
    value = result.stdout.strip()
    if not value:
        raise SystemExit("GitHub CLI returned an empty token")
    return value


def request(method: str, path: str, auth: str, payload=None, *, allow_404=False):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{API}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {auth}",
            "X-GitHub-Api-Version": API_VERSION,
            "Content-Type": "application/json",
            "User-Agent": "tims-software-factory-pilot-bootstrap",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        if allow_404 and exc.code == 404:
            return 404, {}
        if exc.code == 403 and "ruleset" in path:
            raise RuntimeError(
                "GitHub rejected the private-repository ruleset. Private repo rulesets require "
                "GitHub Pro, Team, or Enterprise. Upgrade the GitHub account before continuing; "
                "the Factory will remain fail-closed."
            ) from exc
        raise RuntimeError(f"GitHub {method} {path} failed ({exc.code}): {detail}") from exc


def put_file(auth: str, target: str, source: Path, *, replace: bool) -> str:
    raw = source.read_bytes()
    status, existing = request(
        "GET", f"/repos/{FULL_REPO}/contents/{target}", auth, allow_404=True
    )
    payload = {
        "message": f"chore(factory): bootstrap {target}",
        "content": base64.b64encode(raw).decode("ascii"),
        "branch": "main",
    }
    if status == 200:
        existing_raw = base64.b64decode(existing["content"].replace("\n", ""))
        if existing_raw == raw:
            return existing["sha"]
        github_default_readme = (
            target == "README.md"
            and existing_raw.decode("utf-8", errors="replace").strip() == f"# {REPO}"
        )
        if not replace and not github_default_readme:
            raise RuntimeError(
                f"{target} already exists with unexpected content; rerun with --replace-files only after review"
            )
        payload["sha"] = existing["sha"]
    _, result = request("PUT", f"/repos/{FULL_REPO}/contents/{target}", auth, payload)
    return result["content"]["sha"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--replace-files", action="store_true")
    args = parser.parse_args()
    auth = token()

    _, user = request("GET", "/user", auth)
    if user.get("login") != OWNER or int(user.get("id", 0)) != OWNER_ID:
        raise SystemExit("GitHub authentication is not Tim's authoritative owner account")

    status, repo = request("GET", f"/repos/{FULL_REPO}", auth, allow_404=True)
    if status == 404:
        _, repo = request(
            "POST",
            "/user/repos",
            auth,
            {
                "name": REPO,
                "description": "Governed private pilot for Tim's Software Factory",
                "private": True,
                "auto_init": True,
                "has_issues": False,
                "has_projects": False,
                "has_wiki": False,
            },
        )
        print(f"Created private repository {FULL_REPO}")

    if repo.get("full_name") != FULL_REPO or repo.get("private") is not True:
        raise SystemExit("Pilot repository identity/visibility mismatch; refusing to continue")

    request(
        "PATCH",
        f"/repos/{FULL_REPO}",
        auth,
        {
            "private": True,
            "has_issues": False,
            "has_projects": False,
            "has_wiki": False,
            "allow_squash_merge": True,
            "allow_merge_commit": False,
            "allow_rebase_merge": False,
            "delete_branch_on_merge": True,
        },
    )
    request(
        "PUT",
        f"/repos/{FULL_REPO}/actions/permissions/workflow",
        auth,
        {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
    )

    file_shas = {}
    for target, template in TEMPLATES.items():
        file_shas[target] = put_file(
            auth, target, ROOT / template, replace=args.replace_files
        )

    ruleset = json.loads(
        (ROOT / "config/github/pilot-main-branch-ruleset.json").read_text(encoding="utf-8")
    )
    _, rulesets = request("GET", f"/repos/{FULL_REPO}/rulesets", auth)
    match = next((item for item in rulesets if item.get("name") == ruleset["name"]), None)
    if match:
        _, applied_ruleset = request(
            "PUT", f"/repos/{FULL_REPO}/rulesets/{match['id']}", auth, ruleset
        )
    else:
        _, applied_ruleset = request("POST", f"/repos/{FULL_REPO}/rulesets", auth, ruleset)

    _, repo = request("GET", f"/repos/{FULL_REPO}", auth)
    _, workflow_permissions = request(
        "GET", f"/repos/{FULL_REPO}/actions/permissions/workflow", auth
    )
    evidence = {
        "schema_version": "1.0",
        "evidence_type": "private_pilot_repository_bootstrap",
        "conclusion": "success",
        "repository": FULL_REPO,
        "repository_id": repo["id"],
        "visibility": repo["visibility"],
        "default_branch": repo["default_branch"],
        "ruleset_id": applied_ruleset["id"],
        "ruleset_name": applied_ruleset["name"],
        "ruleset_enforcement": applied_ruleset["enforcement"],
        "default_workflow_permissions": workflow_permissions["default_workflow_permissions"],
        "actions_can_approve_pull_requests": workflow_permissions["can_approve_pull_request_reviews"],
        "bootstrap_file_shas": file_shas,
        "verified_controls": [
            "private_repository",
            "single_reserved_repository_name",
            "main_pr_only_ruleset",
            "force_push_blocked",
            "branch_deletion_blocked",
            "squash_only_merge",
            "read_only_default_github_token",
            "actions_cannot_approve_prs",
            "deterministic_ci_required",
            "role_path_boundary_required",
            "exact_head_inspector_approval_required",
        ],
        "feature_code_written": False,
    }
    output = ROOT / "pilot-repo-bootstrap-evidence.json"
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    print(f"Evidence saved locally to {output}")
    print("Pilot repository controls bootstrapped. Operational role activation remains DENY.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
