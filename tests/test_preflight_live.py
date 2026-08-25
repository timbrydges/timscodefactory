from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.preflight import (
    EXPECTED_OIDC_PREFIX,
    _environment_matches_expected,
    _oidc_prefix_matches,
    _ruleset_matches_expected,
)


ROOT = Path(__file__).resolve().parents[1]


class LiveRulesetPreflightTests(unittest.TestCase):
    def setUp(self):
        self.expected = json.loads(
            (ROOT / "config/github/main-branch-ruleset.json").read_text(encoding="utf-8")
        )
        self.observation = json.loads(
            (ROOT / "config/github/main-branch-ruleset-observation.json").read_text(encoding="utf-8")
        )
        self.live = copy.deepcopy(self.expected)
        self.live.update(
            {
                "id": self.observation["ruleset_id"],
                "updated_at": self.observation["ruleset_updated_at"],
            }
        )
        self.live["rules"][3]["parameters"].update(
            {
                "required_reviewers": [],
                "require_extra_approval_for_unattributed_changes": False,
            }
        )

    def test_pf19_accepts_visible_owner_bypass(self):
        self.assertTrue(_ruleset_matches_expected(self.live, self.expected, self.observation))

    def test_pf19_accepts_redaction_with_fresh_owner_observation(self):
        self.live.pop("bypass_actors")
        self.assertTrue(_ruleset_matches_expected(self.live, self.expected, self.observation))

    def test_pf19_accepts_equivalent_utc_timestamp(self):
        self.live.pop("bypass_actors")
        self.live["updated_at"] = "2026-08-25T17:46:42Z"
        self.assertTrue(_ruleset_matches_expected(self.live, self.expected, self.observation))

    def test_pf19_rejects_redaction_with_stale_owner_observation(self):
        self.live.pop("bypass_actors")
        stale = copy.deepcopy(self.observation)
        stale["ruleset_updated_at"] = "2026-08-25T00:00:00Z"
        self.assertFalse(_ruleset_matches_expected(self.live, self.expected, stale))

    def test_pf19_rejects_live_ruleset_drift(self):
        self.live["rules"][4]["parameters"]["required_status_checks"].pop()
        self.assertFalse(_ruleset_matches_expected(self.live, self.expected, self.observation))

    def test_pf20_accepts_approval_free_owner_environment_with_main_only(self):
        environment = {
            "name": "production",
            "can_admins_bypass": True,
            "protection_rules": [{"id": 1, "type": "branch_policy"}],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }
        policies = {
            "branch_policies": [
                {"id": 1, "node_id": "x", "name": "main", "type": "branch"}
            ]
        }
        self.assertTrue(_environment_matches_expected(environment, policies))

    def test_pf20_rejects_owner_approval_gate_or_tag_policy(self):
        environment = {
            "name": "production",
            "can_admins_bypass": True,
            "protection_rules": [
                {"type": "branch_policy"},
                {"type": "required_reviewers"},
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }
        policies = {"branch_policies": [{"name": "main", "type": "tag"}]}
        self.assertFalse(_environment_matches_expected(environment, policies))

    def test_pf20_rejects_disabled_owner_bypass(self):
        environment = {
            "name": "production",
            "can_admins_bypass": False,
            "protection_rules": [{"type": "branch_policy"}],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }
        policies = {"branch_policies": [{"name": "main", "type": "branch"}]}
        self.assertFalse(_environment_matches_expected(environment, policies))

    def test_pf21_requires_exact_immutable_oidc_prefix(self):
        self.assertTrue(_oidc_prefix_matches({"sub_claim_prefix": EXPECTED_OIDC_PREFIX}))
        self.assertFalse(
            _oidc_prefix_matches(
                {"sub_claim_prefix": "repo:timbrydges/timscodefactory"}
            )
        )


if __name__ == "__main__":
    unittest.main()
