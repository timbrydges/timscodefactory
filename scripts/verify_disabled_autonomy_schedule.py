#!/usr/bin/env python3
"""Read-only canary for the disabled autonomy acceptance schedule."""
from __future__ import annotations

import json
import subprocess


NAME = "tims-software-factory-autonomy-acceptance"
TARGET = (
    "arn:aws:lambda:ca-central-1:666730517561:function:"
    "tims-software-factory-autonomy-controller:acceptance"
)
ROLE = "arn:aws:iam::666730517561:role/tims-software-factory-autonomy-scheduler"
INPUT = {
    "factory_id": "factory",
    "task_id": "deterministic-text-fingerprint",
    "mode": "acceptance",
}


def main() -> None:
    completed = subprocess.run(
        [
            "aws", "scheduler", "get-schedule",
            "--name", NAME,
            "--region", "ca-central-1",
            "--output", "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    schedule = json.loads(completed.stdout)
    target = schedule.get("Target", {})
    retry = target.get("RetryPolicy", {})
    checks = {
        "name": schedule.get("Name") == NAME,
        "state_disabled": schedule.get("State") == "DISABLED",
        "expression": schedule.get("ScheduleExpression") == "rate(15 minutes)",
        "timezone": schedule.get("ScheduleExpressionTimezone") == "UTC",
        "window_off": schedule.get("FlexibleTimeWindow") == {"Mode": "OFF"},
        "target": target.get("Arn") == TARGET,
        "role": target.get("RoleArn") == ROLE,
        "input": json.loads(target.get("Input", "null")) == INPUT,
        "no_retries": retry.get("MaximumRetryAttempts") == 0,
        "one_minute_event_age": retry.get("MaximumEventAgeInSeconds") == 60,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise SystemExit("disabled schedule canary failed: " + ", ".join(failed))
    print(json.dumps({"schedule": NAME, "state": "DISABLED", "canary": "PASS"}))


if __name__ == "__main__":
    main()
