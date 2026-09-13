#!/usr/bin/env python3
"""Owner-only deployment of the governed live-pilot runtime into the private pilot repo."""

from __future__ import annotations

import base64
import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API = "https://api.github.com"
API_VERSION = "2026-03-10"
OWNER = "timbrydges"
OWNER_ID = 214414801
REPOSITORY = "timbrydges/tims-factory-pilot"
REPOSITORY_ID = 1368587958
ENVIRONMENT = "production"

TEMPLATES = {
    ".factory/pilot-task.json": "config/github/pilot-repo/pilot-task.json",
    ".factory/provider-policy.json": "config/github/pilot-repo/provider-policy.json",
    ".factory/pilot_runtime.py": "config/github/pilot-repo/pilot_runtime.py",
    ".github/workflows/pilot-live.yml": "config/github/pilot-repo/pilot-live.yml",
}


def gh_token() -> str:
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True, timeout=15
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SystemExit("Authenticate GitHub CLI as Tim before configuring the pilot runtime.") from exc
    token = result.stdout.strip()
    if not token:
        raise SystemExit("GitHub CLI returned an empty token")
    return token


def request(method: str, path: str, token: str, payload=None, *, allow_404: bool = False):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{API}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "Content-Type": "application/json",
            "User-Agent": "tims-software-factory-pilot-runtime-config",
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
        raise RuntimeError(f"GitHub {method} {path} failed ({exc.code}): {detail}") from exc


def put_file(token: str, target: str, source: Path) -> str:
    raw = source.read_bytes()
    status, existing = request(
        "GET", f"/repos/{REPOSITORY}/contents/{target}", token, allow_404=True
    )
    payload = {
        "message": f"chore(factory): configure live pilot {target}",
        "content": base64.b64encode(raw).decode("ascii"),
        "branch": "main",
    }
    if status == 200:
        current = base64.b64decode(existing["content"].replace("\n", ""))
        if current == raw:
            return existing["sha"]
        payload["sha"] = existing["sha"]
    _, result = request("PUT", f"/repos/{REPOSITORY}/contents/{target}", token, payload)
    return result["content"]["sha"]


def main() -> int:
    token = gh_token()
    _, user = request("GET", "/user", token)
    if user.get("login") != OWNER or int(user.get("id", 0)) != OWNER_ID:
        raise SystemExit("GitHub authentication is not Tim's authoritative owner account")

    _, repo = request("GET", f"/repos/{REPOSITORY}", token)
    if (
        repo.get("full_name") != REPOSITORY
        or int(repo.get("id", 0)) != REPOSITORY_ID
        or repo.get("private") is not True
        or repo.get("default_branch") != "main"
    ):
        raise SystemExit("Pilot repository identity, visibility, or default branch drifted")

    request(
        "PUT",
        f"/repos/{REPOSITORY}/actions/oidc/customization/sub",
        token,
        {"use_default": True, "use_immutable_subject": True},
    )
    # GitHub Pro permits the private-repository environment itself, but private
    # repository deployment branch protection rules are not available here.
    # Main-only execution is independently enforced by the pilot workflow,
    # immutable OIDC subject, and active default-branch ruleset.
    request(
        "PUT",
        f"/repos/{REPOSITORY}/environments/{ENVIRONMENT}",
        token,
        {},
    )

    shas = {}
    for target, source in TEMPLATES.items():
        shas[target] = put_file(token, target, ROOT / source)

    evidence = {
        "schema_version": "1.0",
        "evidence_type": "pilot_live_runtime_configuration",
        "conclusion": "success",
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "environment": ENVIRONMENT,
        "immutable_oidc_subject": True,
        "deployment_branch_policy": "enforced_by_workflow_oidc_and_repository_ruleset",
        "runtime_file_shas": shas,
        "openai_secret_configured": False,
        "aws_runtime_variables_configured": False,
    }
    output = ROOT.parent / "pilot-live-runtime-setup-evidence.json"
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    print(f"Evidence saved locally to {output}")
    print("Live pilot runtime files and GitHub trust controls are configured.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
