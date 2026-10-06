"""Release dependency-manifest gate: direct extraction and native postprocessing."""
import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_artifacts as release
import verify_auditable_binary as verify

MANIFEST = '{"packages":[{"name":"fixture","version":"0.1.0","source":"local","root":true}]}'


class VerifyAuditableBinaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="opaque-auditable-test-")
        self.addCleanup(temporary.cleanup)
        self.binary_dir = Path(temporary.name)
        for name in release.BINS:
            (self.binary_dir / name).write_bytes(b"inert executable fixture")

    def completed(self, returncode, stdout="", stderr=""):
        return subprocess.CompletedProcess(["rust-audit-info"], returncode, stdout=stdout, stderr=stderr)

    def test_every_release_binary_has_bounded_direct_extraction(self):
        with patch.object(verify.subprocess, "run", return_value=self.completed(0, stdout=MANIFEST)) as run:
            results = [verify.check_binary(self.binary_dir / name) for name in release.BINS]
        self.assertTrue(all(ok for ok, _ in results), results)
        self.assertEqual(run.call_count, len(release.BINS))
        for call in run.call_args_list:
            self.assertEqual(call.args[0][0], "rust-audit-info")
            self.assertEqual(call.args[0][2:], [str(256 * 1024**2), str(8 * 1024**2)])

    def test_extraction_failure_rejects_even_parseable_json(self):
        for report in ("", MANIFEST):
            with self.subTest(report=report), patch.object(verify.subprocess, "run",
                    return_value=self.completed(1, stdout=report, stderr="No dependency information found")):
                ok, message = verify.check_binary(self.binary_dir / "opaque")
            self.assertFalse(ok)
            self.assertIn("no embedded dependency manifest", message)

    def test_guessed_audit_reports_and_malformed_manifests_are_rejected(self):
        reports = ("not json", "null", "[]", "{}", '{"lockfile":{},"vulnerabilities":{"found":false}}',
                   '{"packages":[]}', '{"packages":[null]}', '{"packages":[{}]}',
                   '{"packages":[{"root":true},{"root":true}]}')
        for report in reports:
            with self.subTest(report=report), patch.object(verify.subprocess, "run",
                    return_value=self.completed(0, stdout=report)):
                ok, _ = verify.check_binary(self.binary_dir / "opaque")
            self.assertFalse(ok)

    def test_missing_extractor_fails_with_install_hint(self):
        with patch.object(verify.subprocess, "run", side_effect=FileNotFoundError()):
            ok, message = verify.check_binary(self.binary_dir / "opaque")
        self.assertFalse(ok)
        self.assertIn("cargo install rust-audit-info", message)

    def test_timeout_is_reported_not_raised(self):
        with patch.object(verify.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="rust-audit-info", timeout=120)):
            ok, message = verify.check_binary(self.binary_dir / "opaque")
        self.assertFalse(ok)
        self.assertIn("timed out", message)

    def test_missing_binary_fails_before_any_subprocess_call(self):
        with patch.object(verify.subprocess, "run") as run:
            ok, message = verify.check_binary(self.binary_dir / "does-not-exist")
        run.assert_not_called()
        self.assertFalse(ok)
        self.assertIn("no such file", message)

    def test_main_reports_every_failing_binary(self):
        argv = ["verify_auditable_binary.py", "--binary-dir", str(self.binary_dir), "--bin", "opaque", "--bin", "opaqued"]
        with patch.object(verify.sys, "argv", argv), patch.object(verify.subprocess, "run", side_effect=FileNotFoundError()), \
                contextlib.redirect_stderr(io.StringIO()) as error, self.assertRaises(SystemExit) as raised:
            verify.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("opaque:", error.getvalue())
        self.assertIn("opaqued:", error.getvalue())

    def test_default_checks_all_standalone_and_bundled_rust_binaries(self):
        macos = self.binary_dir / release.APP / "Contents/MacOS"
        macos.mkdir(parents=True)
        for name in ("opaque-approver", "opaque-approve-helper"):
            (macos / name).write_bytes(b"inert bundled fixture")
        argv = ["verify_auditable_binary.py", "--binary-dir", str(self.binary_dir)]
        with patch.object(verify.sys, "argv", argv), \
                patch.object(verify.subprocess, "run", return_value=self.completed(0, stdout=MANIFEST)) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            verify.main()
        self.assertEqual(run.call_count, len(release.BINS) + 2)
        (macos / "opaque-approve-helper").unlink()
        with patch.object(verify.sys, "argv", argv), \
                patch.object(verify.subprocess, "run", return_value=self.completed(0, stdout=MANIFEST)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit):
            verify.main()

    # Ordinary protocol-test jobs don't install these tools. The release
    # qualification matrix installs both and requires the real round trip.
    if shutil.which("cargo-auditable") and shutil.which("rust-audit-info"):
        def test_real_stripped_and_signed_binary_passes_but_plain_build_fails(self):
            crate = self.binary_dir / "fixture-crate"
            subprocess.run(["cargo", "new", "--quiet", "--bin", str(crate)], check=True, capture_output=True)
            with (crate / "Cargo.toml").open("a") as stream:
                stream.write('\n[profile.release]\nstrip = true\n')
            target = crate / "target"
            env = dict(os.environ, CARGO_TARGET_DIR=str(target))
            subprocess.run(["cargo", "generate-lockfile", "--offline"], check=True, capture_output=True, cwd=crate, env=env)
            subprocess.run(["cargo", "auditable", "build", "--quiet", "--release", "--locked"],
                           check=True, capture_output=True, cwd=crate, env=env)
            binary = target / "release" / crate.name
            ok, message = verify.check_binary(binary)
            self.assertTrue(ok, message)
            strip = ["strip", str(binary)]
            if sys.platform.startswith("linux"):
                strip.insert(1, "--keep-section=.dep-v0")
            subprocess.run(strip, check=True, capture_output=True)
            if sys.platform == "darwin":
                subprocess.run(["codesign", "--force", "--sign", "-", str(binary)], check=True, capture_output=True)
                subprocess.run(["codesign", "--verify", "--strict", str(binary)], check=True, capture_output=True)
            ok, message = verify.check_binary(binary)
            self.assertTrue(ok, message)
            plain_target = crate / "plain-target"
            subprocess.run(["cargo", "build", "--quiet", "--release", "--locked"], check=True, capture_output=True,
                           cwd=crate, env=dict(env, CARGO_TARGET_DIR=str(plain_target)))
            ok, message = verify.check_binary(plain_target / "release" / crate.name)
            self.assertFalse(ok, message)


if __name__ == "__main__":
    unittest.main()
