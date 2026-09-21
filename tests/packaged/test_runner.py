"""Fail-closed acceptance-report and local-transport regressions; no native UI."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("packaged_acceptance", Path(__file__).with_name("run.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class PackagedAcceptanceTests(unittest.TestCase):
    def result(self, code, stdout="", stderr=""):
        return subprocess.CompletedProcess([], code, stdout, stderr)

    def test_capability_success_requires_both_typed_reports_without_visibility_claim(self):
        helper = {"check": "native_review_ui", "ready": True, "visibility_verified": False}
        approver = {"check": "native_review", "ready": True, "visibility_verified": False,
                    "authentication_available": True}
        self.assertEqual(RUNNER.native_report(self.result(0, json.dumps(helper)), self.result(0, json.dumps(approver))),
                         "capability_available_no_human_decision")
        for field, value in (("ready", False), ("visibility_verified", True), ("check", "different")):
            with self.subTest(field=field), self.assertRaises(RUNNER.AcceptanceError):
                RUNNER.native_report(self.result(0, json.dumps({**helper, field: value})), self.result(0, json.dumps(approver)))
        with self.assertRaises(RUNNER.AcceptanceError):
            RUNNER.native_report(self.result(0, json.dumps(helper)), self.result(0, "{}"))
        with self.assertRaises(RUNNER.AcceptanceError):
            RUNNER.native_report(self.result(0, "invalid JSON"), self.result(0, json.dumps(approver)))

    def test_only_recognized_headless_failure_qualifies_and_never_as_human_presence(self):
        helper = self.result(2, stderr="opaque-approve-helper: no Linux display is configured; use an interactive desktop session")
        approver = self.result(1, stderr="opaque-approver: native review UI unavailable")
        self.assertEqual(RUNNER.native_report(helper, approver), "capability_unavailable_fail_closed")
        for bad in (self.result(1), self.result(-9), self.result(2, stderr="unexpected crash"),
                    self.result(2, stdout="unexpected approval", stderr=helper.stderr)):
            with self.subTest(result=bad), self.assertRaises(RUNNER.AcceptanceError):
                RUNNER.native_report(bad, approver)
        with self.assertRaises(RUNNER.AcceptanceError):
            RUNNER.native_report(helper, self.result(0, '{}'))

    def test_execution_environment_does_not_inherit_agent_or_provider_credentials(self):
        environment = RUNNER.clean_environment(Path("/isolated-home"), Path("/isolated-tmp"), Path("/installed"))
        self.assertEqual(set(environment), {"HOME", "TMPDIR", "PATH", "LC_ALL", "LANG"})
        self.assertEqual(environment["PATH"], "/installed:/usr/bin:/bin")

    def test_timeout_kills_pipe_holding_descendant_and_reports_only_fixed_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ready, effect = root / "ready", root / "late-effect"
            child = ("import pathlib,time,sys; pathlib.Path(sys.argv[1]).write_text('ready'); "
                     "time.sleep(0.8); pathlib.Path(sys.argv[2]).write_text('unexpected')")
            parent = ("import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]]); "
                      "print('synthetic-sensitive-output',flush=True); time.sleep(10)")
            start = time.monotonic()
            with mock.patch.object(RUNNER, "COMMAND_TIMEOUT_SECONDS", 0.3), self.assertRaises(RUNNER.AcceptanceError) as caught:
                RUNNER.execute([sys.executable, "-c", parent, child, ready, effect], environment={}, cwd=root, stage="installer")
            self.assertEqual(str(caught.exception), "installer command timed out")
            self.assertTrue(ready.exists(), "the descendant must have started before testing its cancellation")
            self.assertLess(time.monotonic() - start, 2)
            time.sleep(0.85)
            self.assertFalse(effect.exists(), "the cancelled process group must not perform a late side effect")

    def test_execute_preserves_success_and_rejects_unrecognized_diagnostic_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = RUNNER.execute([sys.executable, "-c", "print('ok')"], environment={}, cwd=temporary)
            self.assertEqual((result.returncode, result.stdout), (0, "ok\n"))
            with self.assertRaisesRegex(RUNNER.AcceptanceError, "unrecognized installed command stage"):
                RUNNER.execute(["not-invoked"], environment={}, cwd=temporary, stage="untrusted-output")

    def test_local_transport_copies_exact_bytes_and_rejects_other_urls_and_auth_headers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, checksum = root / "archive", root / "checksum"
            archive.write_bytes(b"controlled transport unit bytes\x00\xff")
            checksum.write_bytes(b"controlled checksum unit bytes")
            url = "https://github.com/opaque-dev/opaque/releases/download/v0.3.0/opaque-0.3.0-target.tar.gz"
            log, output = root / "requests", root / "download"
            environment = {"OPAQUE_PACKAGED_ARCHIVE": str(archive), "OPAQUE_PACKAGED_CHECKSUM": str(checksum),
                           "OPAQUE_PACKAGED_URL": url, "OPAQUE_PACKAGED_REQUESTS": str(log)}
            for suffix, source in (("", archive), (".sha256", checksum)):
                result = subprocess.run([sys.executable, str(Path(__file__).with_name("transport.py")), "-fsSL", "-o", str(output), url + suffix],
                                        env=environment, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(output.read_bytes(), source.read_bytes())
            recorded = log.read_bytes()
            for arguments in (["-fsSL", "-o", str(output), "https://other.invalid/archive"],
                              ["-fsSL", "-H", "Authorization: synthetic", "-o", str(output), url],
                              ["-fsSL", "-o", str(output), url + ".sig"]):
                result = subprocess.run([sys.executable, str(Path(__file__).with_name("transport.py")), *arguments],
                                        env=environment, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 22)
                self.assertEqual(output.read_bytes(), checksum.read_bytes())
                self.assertEqual(log.read_bytes(), recorded)


if __name__ == "__main__":
    unittest.main()
