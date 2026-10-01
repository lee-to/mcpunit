"""End-to-end checks for the composition recipe, using the real audit CLI."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import run


BINARY = Path(__file__).resolve().parents[2] / "target" / "debug" / "mcpunit"


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "reports with spaces"

    def read(self, name):
        return json.loads((self.output / name).read_text(encoding="utf-8"))

    def assert_linked(self, status):
        manifest = self.read("manifest.json")
        audit = self.read("audit.json")
        behavior = self.read("behavior.json")
        self.assertEqual(manifest["audit"]["status"], "completed")
        self.assertEqual(audit["audit"]["total_score"]["value"], 100)
        self.assertEqual(audit["findings"], [])
        self.assertEqual(audit["schema"]["version"], "1")
        self.assertEqual(manifest["behavior"]["status"], status)
        self.assertEqual(behavior["status"], status)
        self.assertEqual(manifest["behavior"]["run_id"], behavior["run_id"])
        self.assertEqual(manifest["subject"], behavior["subject"])
        self.assertEqual(
            audit["test"]["target"]["server"]["version"],
            manifest["subject"]["revision"]["value"],
        )
        for reference in [manifest["audit"]["report"], manifest["behavior"]["report"],
                          behavior["effect_journal"]]:
            self.assertEqual(reference["sha256"], run.digest(self.output / reference["path"]))
        sarif = self.read("audit.sarif")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_successful_audit_with_missing_effect_fails_behavior(self):
        self.assertEqual(run.compose(BINARY, self.output, "broken"), 1)
        self.assert_linked("failed")
        behavior = self.read("behavior.json")
        self.assertTrue(behavior["assertions"][0]["passed"])
        self.assertFalse(behavior["assertions"][1]["passed"])
        self.assertEqual(behavior["observed_events"], [])

    def test_working_backend_passes_both_checks(self):
        self.assertEqual(run.compose(BINARY, self.output, "working"), 0)
        self.assert_linked("passed")
        behavior = self.read("behavior.json")
        self.assertEqual(behavior["observed_events"], behavior["expected_events"])

    def test_skipped_behavior_is_missing_and_not_a_pass(self):
        self.assertEqual(run.compose(BINARY, self.output, "working", skip_behavior=True), 2)
        manifest = self.read("manifest.json")
        self.assertEqual(manifest["audit"]["total_score"], 100)
        self.assertEqual(manifest["behavior"]["status"], "missing")
        self.assertIsNone(manifest["behavior"]["run_id"])
        self.assertIsNone(manifest["behavior"]["report"])
        self.assertFalse((self.output / "behavior.json").exists())

    def test_timed_out_behavior_preserves_incomplete_evidence(self):
        original = run.check_behavior

        def timeout_fixture(command, cwd, identity, journal, timeout):
            return original(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                cwd, identity, journal, 0.1,
            )

        with patch.object(run, "check_behavior", side_effect=timeout_fixture):
            self.assertEqual(run.compose(BINARY, self.output, "working"), 2)
        self.assert_linked("incomplete")
        self.assertIn("timed out", self.read("behavior.json")["reason"])

    def test_malformed_behavior_response_is_incomplete(self):
        original = run.check_behavior

        def malformed_fixture(command, cwd, identity, journal, timeout):
            return original(
                [sys.executable, "-c", "print('null'); print('null')"],
                cwd, identity, journal, timeout,
            )

        with patch.object(run, "check_behavior", side_effect=malformed_fixture):
            self.assertEqual(run.compose(BINARY, self.output, "working"), 2)
        self.assert_linked("incomplete")
        self.assertIn("JSON-RPC responses", self.read("behavior.json")["reason"])

    def test_failed_audit_does_not_start_behavior(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 2, stdout="", stderr="fixture audit startup error",
        )):
            self.assertEqual(run.compose(BINARY, self.output, "working"), 2)
        manifest = self.read("manifest.json")
        self.assertEqual(manifest["audit"]["status"], "incomplete")
        self.assertEqual(manifest["behavior"]["status"], "missing")
        self.assertFalse((self.output / "behavior.json").exists())

    def test_existing_evidence_cannot_be_overwritten(self):
        self.assertEqual(run.compose(BINARY, self.output, "working"), 0)
        before = (self.output / "manifest.json").read_bytes()
        with self.assertRaises(FileExistsError):
            run.compose(BINARY, self.output, "broken")
        self.assertEqual((self.output / "manifest.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
