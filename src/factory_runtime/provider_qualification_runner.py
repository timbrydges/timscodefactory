"""Deterministic locked-corpus runner for provider qualification measurements.

The runner does not decide whether a provider should be promoted. It guarantees
that every candidate is measured against the exact same corpus bytes and that a
complete observation exists for every case before a measurement can be emitted.
Partial, reordered, duplicated, or mismatched evidence fails closed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol

from jsonschema import Draft202012Validator

from .provider_qualification import (
    ProviderQualificationError,
    ProviderQualificationMeasurement,
)


_CORPUS_SCHEMA_PATH = "factory/schemas/provider-qualification-corpus.schema.json"
_EXPECTED_SCHEMA_VERSION = "1.0"
_EXPECTED_OUTCOMES = frozenset({"VERIFIED_REPAIR", "CORRECT_ESCALATION"})


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ProviderQualificationCase:
    case_id: str
    category: str
    expected_outcome: str
    fixture_ref: str
    oracle_ref: str
    original_command: tuple[str, ...]
    protected_paths: tuple[str, ...]
    tags: tuple[str, ...]


@dataclass(frozen=True)
class LockedProviderQualificationCorpus:
    corpus_id: str
    corpus_digest: str
    cases: tuple[ProviderQualificationCase, ...]
    source_path: Path

    @property
    def case_count(self) -> int:
        return len(self.cases)


@dataclass(frozen=True)
class ProviderQualificationCaseObservation:
    case_id: str
    verified_repair: bool
    escalated: bool
    policy_violations: int
    unsafe_edit_attempts: int
    protected_path_requests: int
    verification_false_positive: bool
    execution_failure: bool
    cost_usd: Decimal
    latency_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not self.case_id:
            raise ProviderQualificationError("qualification observation case_id is invalid")
        for name in ("verified_repair", "escalated", "verification_false_positive", "execution_failure"):
            if not isinstance(getattr(self, name), bool):
                raise ProviderQualificationError(f"qualification observation {name} must be boolean")
        for name in ("policy_violations", "unsafe_edit_attempts", "protected_path_requests", "latency_ms"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ProviderQualificationError(
                    f"qualification observation {name} must be a nonnegative integer"
                )
        if (
            not isinstance(self.cost_usd, Decimal)
            or not self.cost_usd.is_finite()
            or self.cost_usd < 0
        ):
            raise ProviderQualificationError(
                "qualification observation cost_usd must be finite and nonnegative"
            )
        if self.verified_repair and self.escalated:
            raise ProviderQualificationError(
                "qualification observation cannot be both verified repair and escalation"
            )
        if self.verification_false_positive and self.verified_repair:
            raise ProviderQualificationError(
                "verification false positive cannot also be a verified repair"
            )


class ProviderQualificationCaseRunner(Protocol):
    async def run_case(
        self,
        *,
        candidate_id: str,
        case: ProviderQualificationCase,
    ) -> ProviderQualificationCaseObservation:
        ...


@dataclass(frozen=True)
class ProviderQualificationRun:
    candidate_id: str
    corpus: LockedProviderQualificationCorpus
    observations: tuple[ProviderQualificationCaseObservation, ...]
    measurement: ProviderQualificationMeasurement


def _load_validator(factory_repository_root: Path) -> Draft202012Validator:
    path = factory_repository_root.resolve() / _CORPUS_SCHEMA_PATH
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderQualificationError("qualification corpus schema cannot be loaded") from exc
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def load_provider_qualification_corpus(
    factory_repository_root: Path,
    corpus_path: Path,
) -> LockedProviderQualificationCorpus:
    root = factory_repository_root.resolve()
    path = corpus_path.resolve()
    try:
        raw = path.read_bytes()
        parsed = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderQualificationError("provider qualification corpus is not valid UTF-8 JSON") from exc
    validator = _load_validator(root)
    errors = sorted(validator.iter_errors(parsed), key=lambda item: list(item.absolute_path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "<root>"
        raise ProviderQualificationError(
            f"provider qualification corpus schema violation at {location}: {first.message}"
        )
    if parsed.get("schema_version") != _EXPECTED_SCHEMA_VERSION:
        raise ProviderQualificationError("provider qualification corpus schema version is unsupported")

    cases: list[ProviderQualificationCase] = []
    seen: set[str] = set()
    for item in parsed["cases"]:
        case_id = item["case_id"]
        if case_id in seen:
            raise ProviderQualificationError(f"duplicate qualification case_id: {case_id}")
        seen.add(case_id)
        if item["expected_outcome"] not in _EXPECTED_OUTCOMES:
            raise ProviderQualificationError("qualification case expected_outcome is unsupported")
        protected_paths = tuple(item["protected_paths"])
        if len(set(protected_paths)) != len(protected_paths):
            raise ProviderQualificationError(f"qualification case {case_id} has duplicate protected paths")
        tags = tuple(item["tags"])
        if len(set(tags)) != len(tags):
            raise ProviderQualificationError(f"qualification case {case_id} has duplicate tags")
        cases.append(
            ProviderQualificationCase(
                case_id=case_id,
                category=item["category"],
                expected_outcome=item["expected_outcome"],
                fixture_ref=item["fixture_ref"],
                oracle_ref=item["oracle_ref"],
                original_command=tuple(item["original_command"]),
                protected_paths=protected_paths,
                tags=tags,
            )
        )

    return LockedProviderQualificationCorpus(
        corpus_id=parsed["corpus_id"],
        corpus_digest=_sha256(raw),
        cases=tuple(cases),
        source_path=path,
    )


async def run_provider_qualification(
    candidate_id: str,
    corpus: LockedProviderQualificationCorpus,
    runner: ProviderQualificationCaseRunner,
) -> ProviderQualificationRun:
    if not isinstance(candidate_id, str) or not candidate_id:
        raise ProviderQualificationError("qualification candidate_id is invalid")
    if not isinstance(corpus, LockedProviderQualificationCorpus) or not corpus.cases:
        raise ProviderQualificationError("locked qualification corpus is required")

    observations: list[ProviderQualificationCaseObservation] = []
    for case in corpus.cases:
        try:
            observation = await runner.run_case(candidate_id=candidate_id, case=case)
        except Exception as exc:
            raise ProviderQualificationError(
                f"qualification case runner failed for {case.case_id}; partial run discarded"
            ) from exc
        if not isinstance(observation, ProviderQualificationCaseObservation):
            raise ProviderQualificationError(
                f"qualification case {case.case_id} returned invalid observation type"
            )
        if observation.case_id != case.case_id:
            raise ProviderQualificationError(
                f"qualification observation case mismatch for {case.case_id}"
            )
        observations.append(observation)

    if len(observations) != corpus.case_count:
        raise ProviderQualificationError("qualification run is incomplete")
    if tuple(item.case_id for item in observations) != tuple(item.case_id for item in corpus.cases):
        raise ProviderQualificationError("qualification observation order does not match locked corpus")

    verified_repairs = sum(1 for item in observations if item.verified_repair)
    policy_violations = sum(item.policy_violations for item in observations)
    unsafe_edit_attempts = sum(item.unsafe_edit_attempts for item in observations)
    protected_path_requests = sum(item.protected_path_requests for item in observations)
    verification_false_positives = sum(
        1 for item in observations if item.verification_false_positive
    )
    execution_failures = sum(1 for item in observations if item.execution_failure)
    expected_escalations = sum(
        1 for case in corpus.cases if case.expected_outcome == "CORRECT_ESCALATION"
    )
    correct_escalations = sum(
        1
        for case, observation in zip(corpus.cases, observations, strict=True)
        if case.expected_outcome == "CORRECT_ESCALATION" and observation.escalated
    )
    total_cost = sum((item.cost_usd for item in observations), Decimal("0"))
    total_latency = sum(item.latency_ms for item in observations)

    measurement = ProviderQualificationMeasurement(
        candidate_id=candidate_id,
        corpus_id=corpus.corpus_id,
        corpus_digest=corpus.corpus_digest,
        case_count=corpus.case_count,
        verified_repairs=verified_repairs,
        policy_violations=policy_violations,
        unsafe_edit_attempts=unsafe_edit_attempts,
        protected_path_requests=protected_path_requests,
        verification_false_positives=verification_false_positives,
        correct_escalations=correct_escalations,
        expected_escalations=expected_escalations,
        execution_failures=execution_failures,
        total_cost_usd=total_cost,
        total_latency_ms=total_latency,
    )
    return ProviderQualificationRun(
        candidate_id=candidate_id,
        corpus=corpus,
        observations=tuple(observations),
        measurement=measurement,
    )
