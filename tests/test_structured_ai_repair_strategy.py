from __future__ import annotations

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from factory_runtime.diagnostics import RuntimeDiagnostics, sanitize_text_for_model  # noqa: E402
from factory_runtime.repair import RepairContext  # noqa: E402
from factory_runtime.structured_repair import (  # noqa: E402
    ApplyEditsDecision,
    EscalateDecision,
    LiteralReplaceEdit,
    ReadFilesDecision,
    StructuredAIRepairStrategy,
    StructuredRepairError,
    StructuredRepairModelEscalation,
    StructuredRepairPolicy,
)


class FakeModel:
    def __init__(self, *decisions) -> None:
        self.decisions = list(decisions)
        self.turns = []

    async def decide(self, turn):
        self.turns.append(turn)
        if not self.decisions:
            raise AssertionError("unexpected extra model turn")
        return self.decisions.pop(0)


def diagnostics() -> RuntimeDiagnostics:
    return RuntimeDiagnostics(
        request_digest="sha256:" + "1" * 64,
        stdout_digest="sha256:" + "2" * 64,
        stderr_digest="sha256:" + "3" * 64,
        stdout_excerpt="1 failed, 9 passed",
        stderr_excerpt="AssertionError: expected 2, got 1",
        redaction_count=0,
        stdout_truncated=False,
        stderr_truncated=False,
    )


def context(diag: RuntimeDiagnostics | None = None) -> RepairContext:
    observation = SimpleNamespace(diagnostics=diag)
    return RepairContext(
        repair_id="repair-1",
        attempt_number=1,
        original_command=("python", "-m", "pytest", "tests/test_app.py"),
        initial_failure=observation,
        previous_failure=observation,
    )


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


class StructuredAIRepairStrategyTests(unittest.TestCase):
    def test_read_then_literal_replace_changes_only_requested_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "src/app.py", "def add(a, b):\n    return a - b\n")
            write(root, "tests/test_app.py", "assert True\n")
            model = FakeModel(
                ReadFilesDecision(paths=("src/app.py",)),
                ApplyEditsDecision(
                    summary="Fix addition operator",
                    edits=(
                        LiteralReplaceEdit(
                            path="src/app.py",
                            old_text="    return a - b\n",
                            new_text="    return a + b\n",
                        ),
                    ),
                ),
            )

            action = asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))

            self.assertEqual(action.summary, "Fix addition operator")
            self.assertIn("return a + b", (root / "src/app.py").read_text(encoding="utf-8"))
            self.assertEqual((root / "tests/test_app.py").read_text(encoding="utf-8"), "assert True\n")
            self.assertEqual(model.turns[0].files, ())
            self.assertEqual(model.turns[1].files[0].path, "src/app.py")

    def test_model_requires_sanitized_runtime_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "app.py", "x = 1\n")
            model = FakeModel(ReadFilesDecision(paths=("app.py",)))
            with self.assertRaises(StructuredRepairError):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(None)))
            self.assertEqual(model.turns, [])

    def test_inventory_excludes_workflows_env_keys_and_lockfiles(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "src/app.py", "x = 1\n")
            write(root, ".github/workflows/ci.yml", "name: ci\n")
            write(root, ".env", "TOKEN=secret\n")
            write(root, "cert.pem", "secret\n")
            write(root, "package-lock.json", "{}\n")
            model = FakeModel(EscalateDecision(reason="inspect inventory only"))

            with self.assertRaises(StructuredRepairModelEscalation):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))

            inventory = model.turns[0].inventory
            self.assertIn("src/app.py", inventory)
            self.assertNotIn(".github/workflows/ci.yml", inventory)
            self.assertNotIn(".env", inventory)
            self.assertNotIn("cert.pem", inventory)
            self.assertNotIn("package-lock.json", inventory)

    def test_source_context_is_redacted_before_model_exposure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            secret = "sk-" + "A" * 24
            write(root, "src/config.py", f'API_KEY = "{secret}"\nVALUE = 1\n')
            model = FakeModel(
                ReadFilesDecision(paths=("src/config.py",)),
                EscalateDecision(reason="context inspected"),
            )

            with self.assertRaises(StructuredRepairModelEscalation):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))

            exposed = model.turns[1].files[0]
            self.assertNotIn(secret, exposed.content)
            self.assertIn("[REDACTED", exposed.content)
            self.assertGreater(exposed.redaction_count, 0)

    def test_model_cannot_edit_file_it_did_not_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "a.py", "A = 1\n")
            write(root, "b.py", "B = 1\n")
            model = FakeModel(
                ReadFilesDecision(paths=("a.py",)),
                ApplyEditsDecision(
                    summary="bad scope",
                    edits=(LiteralReplaceEdit("b.py", "B = 1", "B = 2"),),
                ),
            )
            with self.assertRaises(StructuredRepairError):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))
            self.assertEqual((root / "b.py").read_text(encoding="utf-8"), "B = 1\n")

    def test_path_traversal_request_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "app.py", "x = 1\n")
            model = FakeModel(ReadFilesDecision(paths=("../outside.py",)))
            with self.assertRaises(StructuredRepairError):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))

    def test_parent_symlink_escape_is_not_available_to_model(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp)
            outside_root = Path(outside)
            write(outside_root, "secret.py", "SECRET = 1\n")
            (root / "linked").symlink_to(outside_root, target_is_directory=True)
            write(root, "safe.py", "SAFE = 1\n")
            model = FakeModel(ReadFilesDecision(paths=("linked/secret.py",)))
            with self.assertRaises(StructuredRepairError):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))
            self.assertEqual((outside_root / "secret.py").read_text(encoding="utf-8"), "SECRET = 1\n")

    def test_ambiguous_literal_replace_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "app.py", "VALUE = 1\nVALUE = 1\n")
            model = FakeModel(
                ReadFilesDecision(paths=("app.py",)),
                ApplyEditsDecision(
                    summary="ambiguous",
                    edits=(LiteralReplaceEdit("app.py", "VALUE = 1", "VALUE = 2"),),
                ),
            )
            with self.assertRaises(StructuredRepairError):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))
            self.assertEqual((root / "app.py").read_text(encoding="utf-8"), "VALUE = 1\nVALUE = 1\n")

    def test_all_edits_validate_before_any_file_is_modified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "a.py", "A = 1\n")
            write(root, "b.py", "B = 1\nB = 1\n")
            model = FakeModel(
                ReadFilesDecision(paths=("a.py", "b.py")),
                ApplyEditsDecision(
                    summary="second edit invalid",
                    edits=(
                        LiteralReplaceEdit("a.py", "A = 1", "A = 2"),
                        LiteralReplaceEdit("b.py", "B = 1", "B = 2"),
                    ),
                ),
            )
            with self.assertRaises(StructuredRepairError):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))
            self.assertEqual((root / "a.py").read_text(encoding="utf-8"), "A = 1\n")
            self.assertEqual((root / "b.py").read_text(encoding="utf-8"), "B = 1\nB = 1\n")

    def test_model_cannot_edit_through_redacted_placeholder(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            secret = "sk-" + "B" * 24
            write(root, "config.py", f'API_KEY = "{secret}"\n')
            model = FakeModel(
                ReadFilesDecision(paths=("config.py",)),
                ApplyEditsDecision(
                    summary="try secret edit",
                    edits=(
                        LiteralReplaceEdit(
                            "config.py",
                            'API_KEY = "[REDACTED_API_KEY]"',
                            'API_KEY = "replacement"',
                        ),
                    ),
                ),
            )
            with self.assertRaises(StructuredRepairError):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))
            self.assertIn(secret, (root / "config.py").read_text(encoding="utf-8"))

    def test_model_escalation_is_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "app.py", "x = 1\n")
            model = FakeModel(EscalateDecision(reason="insufficient safe context"))
            with self.assertRaisesRegex(StructuredRepairModelEscalation, "insufficient safe context"):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))

    def test_turn_budget_exhaustion_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "a.py", "A = 1\n")
            write(root, "b.py", "B = 1\n")
            model = FakeModel(
                ReadFilesDecision(paths=("a.py",)),
                ReadFilesDecision(paths=("b.py",)),
            )
            policy = StructuredRepairPolicy(max_model_turns=2)
            with self.assertRaisesRegex(StructuredRepairError, "turn budget"):
                asyncio.run(StructuredAIRepairStrategy(model, policy).apply(root, context(diagnostics())))
            self.assertEqual(len(model.turns), 2)

    def test_source_file_change_after_read_is_detected(self):
        class MutatingModel(FakeModel):
            def __init__(self, root: Path):
                super().__init__(ReadFilesDecision(paths=("app.py",)))
                self.root = root

            async def decide(self, turn):
                self.turns.append(turn)
                if len(self.turns) == 1:
                    return ReadFilesDecision(paths=("app.py",))
                (self.root / "app.py").write_text("VALUE = 99\n", encoding="utf-8")
                return ApplyEditsDecision(
                    summary="stale context",
                    edits=(LiteralReplaceEdit("app.py", "VALUE = 1", "VALUE = 2"),),
                )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root, "app.py", "VALUE = 1\n")
            model = MutatingModel(root)
            with self.assertRaisesRegex(StructuredRepairError, "changed after model read"):
                asyncio.run(StructuredAIRepairStrategy(model).apply(root, context(diagnostics())))
            self.assertEqual((root / "app.py").read_text(encoding="utf-8"), "VALUE = 99\n")

    def test_model_text_sanitizer_bounds_and_redacts(self):
        secret = "ghp_" + "Z" * 30
        sanitized = sanitize_text_for_model(
            "start\n" + f"token={secret}\n" + "x" * 1000 + "\nend",
            max_chars=512,
        )
        self.assertNotIn(secret, sanitized.text)
        self.assertIn("[REDACTED", sanitized.text)
        self.assertTrue(sanitized.truncated)
        self.assertLessEqual(len(sanitized.text), 512)

    def test_policy_bounds_fail_closed(self):
        with self.assertRaises(StructuredRepairError):
            StructuredRepairPolicy(max_model_turns=0)
        with self.assertRaises(StructuredRepairError):
            StructuredRepairPolicy(max_edits=33)


if __name__ == "__main__":
    unittest.main()
