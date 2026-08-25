#!/usr/bin/env python3
"""One-time, owner-run application of GitHub ruleset and environment controls."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "timbrydges/timscodefactory"


def request(method: str, path: str, token: str, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}/{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "tims-software-factory-bootstrap",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.load(response) if response.length != 0 else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub {method} {path} failed ({exc.code}): {detail}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--replace-ruleset", action="store_true", help="Update an existing ruleset with the same name")
    args = parser.parse_args()
    token = os.environ.get("GH_ADMIN_TOKEN")
    if not token:
        print("GH_ADMIN_TOKEN is required and must have repository administration permission", file=sys.stderr)
        return 2
    ruleset = json.loads((ROOT / "config/github/main-branch-ruleset.json").read_text(encoding="utf-8"))
    environment = json.loads((ROOT / "config/github/production-environment.json").read_text(encoding="utf-8"))
    _, existing = request("GET", "rulesets", token)
    match = next((item for item in existing if item.get("name") == ruleset["name"]), None)
    if match:
        if not args.replace_ruleset:
            print("Ruleset already exists; use --replace-ruleset for an intentional replacement", file=sys.stderr)
            return 2
        request("PUT", f"rulesets/{match['id']}", token, ruleset)
    else:
        request("POST", "rulesets", token, ruleset)
    request("PUT", "environments/production", token, environment)
    print("GitHub main ruleset and production environment applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

