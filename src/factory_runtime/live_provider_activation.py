"""Fail-closed preparation and authorization checks for live provider qualification.

This module does not invoke a provider and never reads provider credentials. It
binds any future paid qualification attempt to the checked-in live activation
policy, provider target catalog, locked evaluation corpus, exact source commit,
Factory owner identity and a bounded spend reservation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import yaml


_POLICY_PATH = "factory/profiles/provider-live-activation.yaml"
_MODELS_PATH = "factory/profiles/provider-models.yaml"
_QUALIFICATION_PATH = "factory/evals/provider-qualification.yaml"
_CORPUS_PATH = "factory/evals/provider-repair-corpus-v1.json"
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class LiveProviderActivationError(RuntimeError):
    """Live-provider activation or preparation is not safe to continue."""


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_bytes())
    except (OSError, yaml.YAMLError) as exc:
        raise LiveProviderActivationError(f"cannot read activation config: {path}") from exc
    if not isinstance(value, dict):
        raise LiveProviderActivationError(f"activation config must be a mapping: {path}")
    return value


def _decimal(value: object, field: str) -> Decimal:
    if not isinstance(value, str):
        raise LiveProviderActivationError(f"{field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise LiveProviderActivationError(f"{field} is invalid") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise LiveProviderActivationError(f"{field} must be positive and finite")
    return parsed


def _sha256_file(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LiveProviderActivationError(f"cannot read locked qualification corpus: {path}") from exc
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class LiveProviderPreparation:
    owner: str
    baseline_alias: str
    challenger_alias: str
    baseline_model_id: str
    challenger_model_id: str
    corpus_digest: str
    max_cost_usd_per_call: Decimal
    max_cost_usd_per_candidate_run: Decimal
    max_cost_usd_per_qualification_session: Decimal
    all_live_targets_disabled: bool


@dataclass(frozen=True)
class LiveQualificationAuthorization:
    actor: str
    target_alias: str
    model_id: str
    corpus_digest: str
    source_commit: str
    reserved_cost_usd: Decimal


def validate_live_provider_preparation(repository_root: Path) -> LiveProviderPreparation:
    root = Path(repository_root).resolve()
    policy = _load_yaml(root / _POLICY_PATH)
    models = _load_yaml(root / _MODELS_PATH)
    qualification = _load_yaml(root / _QUALIFICATION_PATH)

    if policy.get("schema_version") != "1.0" or policy.get("default") != "deny":
        raise LiveProviderActivationError("live activation policy must be schema 1.0 and default deny")
    if policy.get("owner") != "Tim Brydges":
        raise LiveProviderActivationError("live activation owner binding drifted")
    if policy.get("provider_family") != "openai":
        raise LiveProviderActivationError("live activation provider family drifted")
    for flag in (
        "qualification_only",
        "requires_owner_approval",
        "requires_quality_gate",
        "requires_fresh_pricing",
        "requires_ephemeral_provider_credential",
        "requires_provider_broker",
    ):
        if policy.get(flag) is not True:
            raise LiveProviderActivationError(f"live activation policy requires {flag}=true")
    if policy.get("auto_activation") != "prohibited":
        raise LiveProviderActivationError("automatic live-provider activation must be prohibited")

    limits = policy.get("limits")
    if not isinstance(limits, dict):
        raise LiveProviderActivationError("live activation spend limits are missing")
    per_call = _decimal(limits.get("max_cost_usd_per_call"), "max_cost_usd_per_call")
    per_candidate = _decimal(
        limits.get("max_cost_usd_per_candidate_run"), "max_cost_usd_per_candidate_run"
    )
    per_session = _decimal(
        limits.get("max_cost_usd_per_qualification_session"),
        "max_cost_usd_per_qualification_session",
    )
    if not (per_call <= per_candidate <= per_session):
        raise LiveProviderActivationError("live activation spend limits are not monotonically bounded")
    if per_session > Decimal("5.00"):
        raise LiveProviderActivationError("qualification session cap exceeds the locked USD 5.00 ceiling")
    if limits.get("max_output_tokens_per_call") != 4096:
        raise LiveProviderActivationError("live activation output-token cap drifted")
    if limits.get("max_credential_ttl_seconds") != 900:
        raise LiveProviderActivationError("live activation credential TTL cap drifted")
    if limits.get("max_pricing_age_seconds") != 86400:
        raise LiveProviderActivationError("live activation pricing freshness cap drifted")

    approved = policy.get("approved_live_targets")
    if not isinstance(approved, dict) or set(approved) != {
        "coding_primary_sol_live",
        "coding_primary_terra_live",
    }:
        raise LiveProviderActivationError("approved live target set drifted")
    expected_roles = {
        "coding_primary_sol_live": ("gpt-5.6-sol", "quality_baseline"),
        "coding_primary_terra_live": ("gpt-5.6-terra", "cost_challenger"),
    }

    targets = models.get("targets")
    selectors = models.get("selectors")
    if not isinstance(targets, dict) or not isinstance(selectors, dict):
        raise LiveProviderActivationError("provider target catalog is malformed")
    coding_selector = selectors.get("FACTORY_CODING_MODEL")
    if not isinstance(coding_selector, dict):
        raise LiveProviderActivationError("FACTORY_CODING_MODEL selector is missing")
    if coding_selector.get("default_target") != "coding_primary_dry_run":
        raise LiveProviderActivationError("live preparation must keep the dry-run target as default")
    if coding_selector.get("authority_effect") != "none":
        raise LiveProviderActivationError("provider selector must have no authority effect")

    disabled = True
    for alias, (model_id, role) in expected_roles.items():
        policy_target = approved.get(alias)
        catalog_target = targets.get(alias)
        if not isinstance(policy_target, dict) or not isinstance(catalog_target, dict):
            raise LiveProviderActivationError(f"live target is missing: {alias}")
        if policy_target.get("model_id") != model_id or policy_target.get("role") != role:
            raise LiveProviderActivationError(f"live activation target binding drifted: {alias}")
        if catalog_target.get("provider_family") != "openai":
            raise LiveProviderActivationError(f"live target family drifted: {alias}")
        if catalog_target.get("model_id") != model_id:
            raise LiveProviderActivationError(f"live target model ID drifted: {alias}")
        if catalog_target.get("execution_mode") != "live":
            raise LiveProviderActivationError(f"live target execution mode drifted: {alias}")
        if catalog_target.get("live_credentials") != "brokered_lease_only":
            raise LiveProviderActivationError(f"live target credential policy drifted: {alias}")
        if catalog_target.get("cost_mode") != "metered":
            raise LiveProviderActivationError(f"live target cost mode drifted: {alias}")
        if policy_target.get("enabled") is not False or catalog_target.get("enabled") is not False:
            disabled = False

    if qualification.get("principle") != "quality_first":
        raise LiveProviderActivationError("provider qualification must remain quality-first")
    corpus_policy = qualification.get("corpus")
    promotion = qualification.get("promotion")
    if not isinstance(corpus_policy, dict) or corpus_policy.get("minimum_cases") != 20:
        raise LiveProviderActivationError("provider qualification corpus size drifted")
    if not isinstance(promotion, dict):
        raise LiveProviderActivationError("provider qualification promotion policy is missing")
    if promotion.get("owner_approval_required") is not True:
        raise LiveProviderActivationError("provider qualification must require owner approval")
    if promotion.get("live_target_activation_automatic") is not False:
        raise LiveProviderActivationError("provider qualification may not auto-activate a live target")

    corpus_digest = _sha256_file(root / _CORPUS_PATH)
    if not _DIGEST.fullmatch(corpus_digest):
        raise LiveProviderActivationError("qualification corpus digest is invalid")

    return LiveProviderPreparation(
        owner="Tim Brydges",
        baseline_alias="coding_primary_sol_live",
        challenger_alias="coding_primary_terra_live",
        baseline_model_id="gpt-5.6-sol",
        challenger_model_id="gpt-5.6-terra",
        corpus_digest=corpus_digest,
        max_cost_usd_per_call=per_call,
        max_cost_usd_per_candidate_run=per_candidate,
        max_cost_usd_per_qualification_session=per_session,
        all_live_targets_disabled=disabled,
    )


def authorize_live_qualification(
    repository_root: Path,
    *,
    actor: str,
    target_alias: str,
    corpus_digest: str,
    source_commit: str,
    reserved_cost_usd: Decimal,
) -> LiveQualificationAuthorization:
    """Authorize one exact live qualification request or fail before credentials.

    The current checked-in preparation intentionally has both live targets
    disabled, so this function must reject all paid execution until a later
    owner-reviewed activation commit flips one exact target on.
    """

    preparation = validate_live_provider_preparation(repository_root)
    if actor != "timbrydges":
        raise LiveProviderActivationError("only the Factory owner may authorize live qualification")
    if target_alias not in {preparation.baseline_alias, preparation.challenger_alias}:
        raise LiveProviderActivationError("requested live target is not approved")
    if corpus_digest != preparation.corpus_digest:
        raise LiveProviderActivationError("qualification corpus digest does not match locked corpus")
    if not isinstance(source_commit, str) or not _COMMIT.fullmatch(source_commit):
        raise LiveProviderActivationError("qualification source commit must be an exact SHA")
    if not isinstance(reserved_cost_usd, Decimal) or not reserved_cost_usd.is_finite():
        raise LiveProviderActivationError("qualification spend reservation must be a finite Decimal")
    if reserved_cost_usd <= 0 or reserved_cost_usd > preparation.max_cost_usd_per_qualification_session:
        raise LiveProviderActivationError("qualification spend reservation exceeds the session cap")
    if preparation.all_live_targets_disabled:
        raise LiveProviderActivationError(
            "live qualification is prepared but disabled; no provider credential may be requested"
        )
    raise LiveProviderActivationError(
        "live target activation state requires an owner-reviewed target-specific authorization implementation"
    )
