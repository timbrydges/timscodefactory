from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.provider_qualification_runner import (  # noqa: E402
    load_provider_qualification_corpus,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "factory/evals/provider-repair-corpus-v1.json"
ORACLE_SCHEMA_PATH = ROOT / "factory/schemas/provider-qualification-oracle.schema.json"


def run_command(command: tuple[str, ...], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
        env={"PATH": __import__("os").environ.get("PATH", ""), "PYTHONPATH": ""},
    )


class ProviderQualificationCorpusV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = load_provider_qualification_corpus(ROOT, CORPUS_PATH)
        schema = json.loads(ORACLE_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        cls.oracle_validator = Draft202012Validator(schema)

    def oracle_for(self, case):
        path = ROOT / case.oracle_ref
        self.assertTrue(path.is_file(), case.oracle_ref)
        oracle = json.loads(path.read_text(encoding="utf-8"))
        errors = sorted(
            self.oracle_validator.iter_errors(oracle),
            key=lambda item: list(item.absolute_path),
        )
        self.assertEqual(errors, [], f"oracle schema errors for {case.case_id}: {errors}")
        return oracle

    def test_corpus_is_locked_to_twenty_balanced_realistic_cases(self):
        self.assertEqual(self.corpus.corpus_id, "provider-repair-corpus-v1")
        self.assertEqual(self.corpus.case_count, 20)
        self.assertEqual(
            Counter(case.category for case in self.corpus.cases),
            Counter({"repair": 12, "escalation": 4, "safety": 4}),
        )
        self.assertEqual(len({case.case_id for case in self.corpus.cases}), 20)
        self.assertTrue(self.corpus.corpus_digest.startswith("sha256:"))

    def test_every_case_binds_existing_fixture_and_matching_oracle(self):
        for case in self.corpus.cases:
            with self.subTest(case=case.case_id):
                fixture = ROOT / case.fixture_ref
                self.assertTrue(fixture.is_dir(), case.fixture_ref)
                oracle = self.oracle_for(case)
                self.assertEqual(oracle["case_id"], case.case_id)
                self.assertEqual(oracle["expected_outcome"], case.expected_outcome)
                self.assertEqual(len(set(oracle["allowed_edit_paths"])), len(oracle["allowed_edit_paths"]))
                self.assertEqual(
                    len(set(oracle["forbidden_edit_paths"])),
                    len(oracle["forbidden_edit_paths"]),
                )
                self.assertFalse(
                    set(oracle["allowed_edit_paths"]) & set(oracle["forbidden_edit_paths"])
                )
                self.assertTrue(case.original_command)
                self.assertEqual(case.original_command[0], "python")

    def test_all_repair_cases_fail_before_gold_and_pass_visible_plus_hidden_after_gold(self):
        repairs = [case for case in self.corpus.cases if case.expected_outcome == "VERIFIED_REPAIR"]
        self.assertEqual(len(repairs), 12)
        for case in repairs:
            with self.subTest(case=case.case_id):
                oracle = self.oracle_for(case)
                self.assertIsNone(oracle["expected_escalation_reason"])
                self.assertIsInstance(oracle["hidden_test_ref"], str)
                hidden = ROOT / oracle["hidden_test_ref"]
                self.assertTrue(hidden.is_file())
                self.assertGreaterEqual(len(oracle["gold_replacements"]), 1)

                with tempfile.TemporaryDirectory() as tmp:
                    workspace = Path(tmp) / "workspace"
                    shutil.copytree(ROOT / case.fixture_ref, workspace)
                    initial = run_command(case.original_command, workspace)
                    self.assertNotEqual(
                        initial.returncode,
                        0,
                        f"{case.case_id} unexpectedly passes before repair:\n{initial.stdout}",
                    )

                    for edit in oracle["gold_replacements"]:
                        self.assertIn(edit["path"], oracle["allowed_edit_paths"])
                        target = workspace / edit["path"]
                        self.assertTrue(target.is_file())
                        text = target.read_text(encoding="utf-8")
                        self.assertEqual(
                            text.count(edit["old_text"]),
                            1,
                            f"gold replacement not unique for {case.case_id}",
                        )
                        target.write_text(
                            text.replace(edit["old_text"], edit["new_text"], 1),
                            encoding="utf-8",
                            newline="\n",
                        )

                    tests_dir = workspace / "tests"
                    tests_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(hidden, tests_dir / "test_hidden.py")
                    repaired = run_command(case.original_command, workspace)
                    self.assertEqual(
                        repaired.returncode,
                        0,
                        f"{case.case_id} gold repair failed visible/hidden verification:\n{repaired.stdout}",
                    )

    def test_escalation_and_safety_cases_fail_and_have_no_hidden_gold_fix(self):
        escalation_cases = [
            case for case in self.corpus.cases if case.expected_outcome == "CORRECT_ESCALATION"
        ]
        self.assertEqual(len(escalation_cases), 8)
        for case in escalation_cases:
            with self.subTest(case=case.case_id):
                oracle = self.oracle_for(case)
                self.assertIsNone(oracle["hidden_test_ref"])
                self.assertEqual(oracle["gold_replacements"], [])
                self.assertIsInstance(oracle["expected_escalation_reason"], str)
                self.assertTrue(oracle["expected_escalation_reason"])
                with tempfile.TemporaryDirectory() as tmp:
                    workspace = Path(tmp) / "workspace"
                    shutil.copytree(ROOT / case.fixture_ref, workspace)
                    failed = run_command(case.original_command, workspace)
                    self.assertNotEqual(
                        failed.returncode,
                        0,
                        f"{case.case_id} must begin as a failing/escalation case",
                    )

    def test_oracles_never_live_inside_candidate_fixture(self):
        for case in self.corpus.cases:
            fixture = (ROOT / case.fixture_ref).resolve()
            oracle = (ROOT / case.oracle_ref).resolve()
            try:
                oracle.relative_to(fixture)
            except ValueError:
                pass
            else:
                self.fail(f"oracle leaked into candidate fixture for {case.case_id}")


if __name__ == "__main__":
    unittest.main()
