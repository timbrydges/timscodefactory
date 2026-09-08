from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.telemetry import (  # noqa: E402
    RuntimeTelemetryPayloadError,
    RuntimeTraceBinding,
    RuntimeTraceEventType,
    RuntimeTraceIntegrityError,
    RuntimeTraceLifecycleError,
    RuntimeTraceRecorder,
    parse_runtime_trace_jsonl,
    replay_runtime_trace,
    serialize_runtime_trace,
    validate_runtime_trace,
)


ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 9, 8, 23, 30, tzinfo=timezone.utc)
COMMIT = "a" * 40
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
D4 = "sha256:" + "4" * 64
D5 = "sha256:" + "5" * 64
D6 = "sha256:" + "6" * 64


def binding() -> RuntimeTraceBinding:
    return RuntimeTraceBinding(
        trace_id="trace-1",
        runtime_session_id="session-1",
        task_id="task-1",
        lease_id="lease-1",
        role_id="engineering_agent",
        source_commit=COMMIT,
        started_at=START,
    )


def complete_trace():
    recorder = RuntimeTraceRecorder(binding())
    recorder.emit(
        RuntimeTraceEventType.SESSION_STARTED,
        {"component": "ci_repair_runtime"},
        occurred_at=START,
    )
    recorder.emit(
        RuntimeTraceEventType.DETECTION_COMPLETED,
        {
            "stack": "python",
            "runtime_version": "3.12",
            "environment_spec_digest": D1,
            "workspace_digest": D2,
        },
        occurred_at=START + timedelta(seconds=1),
    )
    recorder.emit(
        RuntimeTraceEventType.PROVISIONING_COMPLETED,
        {
            "request_id": "provision-1",
            "receipt_digest": D3,
            "build_log_digest": D4,
            "exit_code": 0,
            "timed_out": False,
        },
        occurred_at=START + timedelta(seconds=2),
    )
    recorder.emit(
        RuntimeTraceEventType.VERIFICATION_OBSERVED,
        {
            "request_id": "verify-1",
            "workspace_digest": D2,
            "command_digest": D3,
            "environment_digest": D1,
            "stdout_digest": D4,
            "stderr_digest": D5,
            "exit_code": 1,
            "timed_out": False,
        },
        occurred_at=START + timedelta(seconds=3),
    )
    recorder.emit(
        RuntimeTraceEventType.DIAGNOSTIC_REDACTED,
        {"diagnostic_digest": D6, "redaction_count": 2, "truncated": False},
        occurred_at=START + timedelta(seconds=4),
    )
    recorder.emit(
        RuntimeTraceEventType.REPAIR_MODEL_CALL,
        {
            "request_id": "broker-request-1",
            "provider_profile": "coding_primary",
            "model_selector": "FACTORY_CODING_MODEL",
            "input_tokens": 100,
            "output_tokens": 20,
            "cost_usd": "0.0125",
        },
        occurred_at=START + timedelta(seconds=5),
    )
    recorder.emit(
        RuntimeTraceEventType.REPAIR_ACTION,
        {"attempt_number": 1, "action_digest": D1, "workspace_digest": D6},
        occurred_at=START + timedelta(seconds=6),
    )
    recorder.emit(
        RuntimeTraceEventType.REPAIR_MODEL_CALL,
        {
            "request_id": "broker-request-2",
            "provider_profile": "coding_primary",
            "model_selector": "FACTORY_CODING_MODEL",
            "input_tokens": 50,
            "output_tokens": 10,
            "cost_usd": "0.0075",
        },
        occurred_at=START + timedelta(seconds=7),
    )
    recorder.emit(
        RuntimeTraceEventType.VERIFICATION_OBSERVED,
        {
            "request_id": "verify-2",
            "workspace_digest": D6,
            "command_digest": D3,
            "environment_digest": D1,
            "stdout_digest": D4,
            "stderr_digest": D5,
            "exit_code": 0,
            "timed_out": False,
        },
        occurred_at=START + timedelta(seconds=8),
    )
    recorder.emit(
        RuntimeTraceEventType.SESSION_FINISHED,
        {"outcome": "VERIFIED_REPAIR", "result_digest": D2},
        occurred_at=START + timedelta(seconds=9),
    )
    return recorder.events


class RuntimeTelemetryTests(unittest.TestCase):
    def test_event_document_matches_json_schema(self):
        events = complete_trace()
        schema = json.loads(
            (ROOT / "factory/schemas/runtime-trace-event.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for event in events:
            validator.validate(event.to_dict())

    def test_hash_chain_and_jsonl_round_trip(self):
        events = complete_trace()
        checked = validate_runtime_trace(events)
        self.assertEqual(checked, events)
        raw = serialize_runtime_trace(events)
        parsed = parse_runtime_trace_jsonl(raw)
        self.assertEqual([item.to_dict() for item in parsed], [item.to_dict() for item in events])

    def test_replay_reconstructs_counts_cost_and_success_without_side_effects(self):
        result = replay_runtime_trace(complete_trace())
        self.assertEqual(result.terminal_status, "SUCCEEDED")
        self.assertEqual(result.terminal_reason, "VERIFIED_REPAIR")
        self.assertEqual(result.verification_observations, 2)
        self.assertEqual(result.repair_actions, 1)
        self.assertEqual(result.model_calls, 2)
        self.assertEqual(result.total_provider_cost_usd, Decimal("0.0200"))
        self.assertEqual(result.liveness_evaluations, 0)
        self.assertEqual(result.terminations, 0)

    def test_changed_event_attribute_breaks_digest(self):
        events = list(complete_trace())
        target = events[5]
        changed = dict(target.attributes)
        changed["input_tokens"] = 101
        events[5] = replace(target, attributes=changed)
        with self.assertRaises(RuntimeTraceIntegrityError):
            validate_runtime_trace(events)

    def test_deleted_event_breaks_indexes_and_chain(self):
        events = list(complete_trace())
        del events[4]
        with self.assertRaises(RuntimeTraceIntegrityError):
            validate_runtime_trace(events)

    def test_reordered_events_break_chain(self):
        events = list(complete_trace())
        events[3], events[4] = events[4], events[3]
        with self.assertRaises(RuntimeTraceIntegrityError):
            validate_runtime_trace(events)

    def test_binding_drift_is_detected_even_if_event_object_is_replaced(self):
        events = list(complete_trace())
        events[2] = replace(events[2], task_id="other-task")
        with self.assertRaises(RuntimeTraceIntegrityError):
            validate_runtime_trace(events)

    def test_raw_stdout_stderr_prompt_and_credentials_are_forbidden(self):
        forbidden = [
            {"stdout": "raw log"},
            {"stderr": "raw log"},
            {"prompt": "fix this"},
            {"authorization": "Bearer secret"},
            {"api_key": "secret"},
            {"source_content": "code"},
            {"response_body": "raw response"},
        ]
        for attributes in forbidden:
            recorder = RuntimeTraceRecorder(binding())
            with self.subTest(attributes=attributes):
                with self.assertRaises(RuntimeTelemetryPayloadError):
                    recorder.emit(
                        RuntimeTraceEventType.SESSION_STARTED,
                        {"component": "runtime", **attributes},
                        occurred_at=START,
                    )

    def test_digest_metadata_is_allowed_for_logs_but_must_be_valid_digest(self):
        recorder = RuntimeTraceRecorder(binding())
        recorder.emit(RuntimeTraceEventType.SESSION_STARTED, {"component": "runtime"}, occurred_at=START)
        with self.assertRaises(RuntimeTelemetryPayloadError):
            recorder.emit(
                RuntimeTraceEventType.VERIFICATION_OBSERVED,
                {
                    "request_id": "v1",
                    "workspace_digest": D1,
                    "command_digest": D2,
                    "environment_digest": D3,
                    "stdout_digest": "not-a-digest",
                    "stderr_digest": D4,
                    "exit_code": 1,
                    "timed_out": False,
                },
                occurred_at=START + timedelta(seconds=1),
            )

    def test_nested_float_and_control_character_attributes_are_rejected(self):
        invalid_values = [
            {"component": {"nested": True}},
            {"component": 1.5},
            {"component": "line1\nline2"},
        ]
        for attributes in invalid_values:
            recorder = RuntimeTraceRecorder(binding())
            with self.subTest(attributes=attributes):
                with self.assertRaises(RuntimeTelemetryPayloadError):
                    recorder.emit(
                        RuntimeTraceEventType.SESSION_STARTED,
                        attributes,
                        occurred_at=START,
                    )

    def test_event_specific_scalar_types_fail_closed(self):
        recorder = RuntimeTraceRecorder(binding())
        recorder.emit(RuntimeTraceEventType.SESSION_STARTED, {"component": "runtime"}, occurred_at=START)
        invalid_model_calls = [
            {
                "request_id": "r1",
                "provider_profile": "coding_primary",
                "model_selector": "FACTORY_CODING_MODEL",
                "input_tokens": True,
                "output_tokens": 2,
                "cost_usd": "0.01",
            },
            {
                "request_id": "r1",
                "provider_profile": "coding_primary",
                "model_selector": "FACTORY_CODING_MODEL",
                "input_tokens": 1,
                "output_tokens": -1,
                "cost_usd": "0.01",
            },
            {
                "request_id": "r1",
                "provider_profile": "coding_primary",
                "model_selector": "FACTORY_CODING_MODEL",
                "input_tokens": 1,
                "output_tokens": 2,
                "cost_usd": "01.0",
            },
        ]
        for attributes in invalid_model_calls:
            with self.subTest(attributes=attributes):
                with self.assertRaises(RuntimeTelemetryPayloadError):
                    recorder.emit(
                        RuntimeTraceEventType.REPAIR_MODEL_CALL,
                        attributes,
                        occurred_at=START + timedelta(seconds=1),
                    )

    def test_first_event_must_be_session_started(self):
        recorder = RuntimeTraceRecorder(binding())
        with self.assertRaises(RuntimeTraceLifecycleError):
            recorder.emit(
                RuntimeTraceEventType.ESCALATED,
                {"reason_code": "FAIL", "attempts": 1},
                occurred_at=START,
            )

    def test_session_started_cannot_repeat(self):
        recorder = RuntimeTraceRecorder(binding())
        recorder.emit(RuntimeTraceEventType.SESSION_STARTED, {"component": "runtime"}, occurred_at=START)
        with self.assertRaises(RuntimeTraceLifecycleError):
            recorder.emit(
                RuntimeTraceEventType.SESSION_STARTED,
                {"component": "runtime"},
                occurred_at=START + timedelta(seconds=1),
            )

    def test_no_events_after_terminal_event(self):
        recorder = RuntimeTraceRecorder(binding())
        recorder.emit(RuntimeTraceEventType.SESSION_STARTED, {"component": "runtime"}, occurred_at=START)
        recorder.emit(
            RuntimeTraceEventType.ESCALATED,
            {"reason_code": "STRATEGY_FAILURE", "attempts": 1},
            occurred_at=START + timedelta(seconds=1),
        )
        with self.assertRaises(RuntimeTraceLifecycleError):
            recorder.emit(
                RuntimeTraceEventType.LIVENESS_EVALUATED,
                {
                    "status": "DEAD",
                    "reason_code": "RUNTIME_HEARTBEAT_DEAD",
                    "controller_request": "REQUEST_CONTROLLER_STALL",
                    "runtime_action": "TERMINATE_SESSION",
                },
                occurred_at=START + timedelta(seconds=2),
            )

    def test_event_time_regression_fails_closed(self):
        recorder = RuntimeTraceRecorder(binding())
        recorder.emit(
            RuntimeTraceEventType.SESSION_STARTED,
            {"component": "runtime"},
            occurred_at=START + timedelta(seconds=1),
        )
        with self.assertRaises(RuntimeTraceIntegrityError):
            recorder.emit(
                RuntimeTraceEventType.ESCALATED,
                {"reason_code": "FAIL", "attempts": 1},
                occurred_at=START,
            )

    def test_termination_requires_matching_prior_liveness_decision(self):
        recorder = RuntimeTraceRecorder(binding())
        recorder.emit(RuntimeTraceEventType.SESSION_STARTED, {"component": "runtime"}, occurred_at=START)
        recorder.emit(
            RuntimeTraceEventType.LIVENESS_EVALUATED,
            {
                "status": "DEAD",
                "reason_code": "RUNTIME_HEARTBEAT_DEAD",
                "controller_request": "REQUEST_CONTROLLER_STALL",
                "runtime_action": "TERMINATE_SESSION",
            },
            occurred_at=START + timedelta(seconds=1),
        )
        recorder.emit(
            RuntimeTraceEventType.TERMINATION_COMPLETED,
            {
                "resource_id_digest": D1,
                "reason_code": "RUNTIME_HEARTBEAT_DEAD",
                "receipt_digest": D2,
            },
            occurred_at=START + timedelta(seconds=2),
        )
        recorder.emit(
            RuntimeTraceEventType.ESCALATED,
            {"reason_code": "RUNTIME_HEARTBEAT_DEAD", "attempts": 2},
            occurred_at=START + timedelta(seconds=3),
        )
        result = replay_runtime_trace(recorder.events)
        self.assertEqual(result.liveness_evaluations, 1)
        self.assertEqual(result.terminations, 1)
        self.assertEqual(result.terminal_status, "ESCALATED")

    def test_termination_reason_mismatch_fails_trace_validation(self):
        recorder = RuntimeTraceRecorder(binding())
        recorder.emit(RuntimeTraceEventType.SESSION_STARTED, {"component": "runtime"}, occurred_at=START)
        recorder.emit(
            RuntimeTraceEventType.LIVENESS_EVALUATED,
            {
                "status": "DEAD",
                "reason_code": "RUNTIME_HEARTBEAT_DEAD",
                "controller_request": "REQUEST_CONTROLLER_STALL",
                "runtime_action": "TERMINATE_SESSION",
            },
            occurred_at=START + timedelta(seconds=1),
        )
        recorder.emit(
            RuntimeTraceEventType.TERMINATION_COMPLETED,
            {
                "resource_id_digest": D1,
                "reason_code": "OTHER_REASON",
                "receipt_digest": D2,
            },
            occurred_at=START + timedelta(seconds=2),
        )
        with self.assertRaises(RuntimeTraceLifecycleError):
            validate_runtime_trace(recorder.events)

    def test_jsonl_requires_trailing_newline(self):
        raw = serialize_runtime_trace(complete_trace()).rstrip(b"\n")
        with self.assertRaises(RuntimeTraceIntegrityError):
            parse_runtime_trace_jsonl(raw)

    def test_jsonl_tampering_is_detected(self):
        raw = serialize_runtime_trace(complete_trace())
        lines = raw.splitlines()
        value = json.loads(lines[5])
        value["attributes"]["cost_usd"] = "0.999"
        lines[5] = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        tampered = b"\n".join(lines) + b"\n"
        with self.assertRaises(RuntimeTraceIntegrityError):
            parse_runtime_trace_jsonl(tampered)


if __name__ == "__main__":
    unittest.main()
