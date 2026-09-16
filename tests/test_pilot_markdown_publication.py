from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = (
    "architecture/plan.md",
    "docs/adr/0001-pilot-design.md",
    "docs/implementation/README.md",
)


class PilotMarkdownPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "core.whitespace", "blank-at-eol,blank-at-eof,space-before-tab")

    def git(self, *args, check=True):
        return subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env,
            check=check, capture_output=True, text=True,
        )

    def write(self, path, content):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))

    def install_attributes(self, script_name="configure_pilot_live_runtime"):
        spec = importlib.util.spec_from_file_location(
            script_name, ROOT / "scripts" / f"{script_name}.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = ROOT / module.TEMPLATES[".gitattributes"]
        shutil.copyfile(source, self.repo / ".gitattributes")
        self.git("add", ".gitattributes")

    def test_observed_builder_failure_accepts_markdown_without_rewriting_bytes(self):
        content = "# Implementation\n\nTask: `pilot-001-release-readiness-checklist`  \nSchema version: `1.0`  \nDetails.\n"
        for path in DOCUMENTS:
            self.write(path, content)
        self.git("add", ".")
        before = self.git("diff", "--cached", "--check", check=False)
        self.assertNotEqual(before.returncode, 0)
        self.assertIn("trailing whitespace", before.stdout)

        for script in ("bootstrap_pilot_repo", "configure_pilot_live_runtime"):
            with self.subTest(deployment=script):
                self.install_attributes(script)
                self.git("diff", "--cached", "--check")
                for path in DOCUMENTS:
                    self.assertEqual((self.repo / path).read_bytes(), content.encode("utf-8"))

    def test_source_and_other_paths_still_reject_trailing_whitespace(self):
        self.install_attributes()
        for path in ("src/release_readiness.py", "tests/unit/test_cli.py", "unscoped.md"):
            with self.subTest(path=path):
                self.write(path, "content  \n")
                self.git("add", path)
                result = self.git("diff", "--cached", "--check", "--", path, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("trailing whitespace", result.stdout)

    def test_markdown_still_rejects_conflicts_and_blank_lines_at_eof(self):
        self.install_attributes()
        path = DOCUMENTS[-1]
        for content, diagnostic in (
            ("# Document\n\n", "new blank line at EOF"),
            ("<<<<<<< ours\nours\n=======\ntheirs\n>>>>>>> theirs\n", "conflict marker"),
        ):
            with self.subTest(diagnostic=diagnostic):
                self.write(path, content)
                self.git("add", path)
                result = self.git("diff", "--cached", "--check", check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stdout)


if __name__ == "__main__":
    unittest.main()
