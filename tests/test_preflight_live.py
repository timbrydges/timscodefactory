from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.preflight import _ruleset_matches_expected


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


if __name__ == "__main__":
    unittest.main()
