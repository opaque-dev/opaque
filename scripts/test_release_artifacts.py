"""Release archive regressions using inert executables, never installed globally."""
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import release_artifacts as release


class ReleaseArtifactsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="opaque-release-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.binaries = self.root / "binaries"
        self.binaries.mkdir()
        (self.source / "Cargo.toml").write_text('[workspace.package]\nversion = "0.3.0"\n')
        for name in release.LICENSE_FILES:
            (self.source / name).write_text(f"fixture license: {name}\n")
        for command in (["init", "-q"], ["add", "Cargo.toml", *release.LICENSE_FILES],
                        ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                         "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]):
            subprocess.run(["git", "-C", str(self.source), *command], check=True, capture_output=True)
        self.revision = subprocess.check_output(["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True).strip()
        for name in release.BINS:
            path = self.binaries / name
            path.write_text(f'#!/bin/sh\nif [ "$1" = "--version" ]; then echo "{name} 0.3.0+{self.revision[:7]}"; fi\n')
            path.chmod(0o755)
        self.args = dict(version="0.3.0", revision=self.revision, target="x86_64-unknown-linux-gnu")

    def manifest(self, **overrides):
        return release.create_manifest(self.source, self.binaries, **(self.args | overrides))

    def archive(self, *, omit=(), extra=None):
        archive = self.root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for path in sorted(self.binaries.iterdir()):
                if path.name not in omit:
                    output.add(path, arcname=path.name)
            if extra:
                info, data = extra
                output.addfile(info, io.BytesIO(data) if data is not None else None)
        return archive

    def test_complete_archive_smokes_extracted_tools_and_exact_version(self):
        manifest = self.manifest()
        result = release.verify_archive(self.archive(), **self.args, smoke=True)
        self.assertEqual(result, manifest)
        self.assertEqual(set(manifest["files"]), set(release.BINS + release.LICENSE_FILES))

    def test_license_texts_are_source_bound_and_required(self):
        self.manifest()
        for name in release.LICENSE_FILES:
            self.assertEqual((self.binaries / name).read_bytes(), (self.source / name).read_bytes())
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "payload sets"):
                release.verify_archive(self.archive(omit=(name,)), **self.args)
        (self.binaries / "LICENSE").write_text("changed license")
        with self.assertRaisesRegex(ValueError, "payload verification"):
            release.verify_archive(self.archive(), **self.args)

    def test_manifest_git_reads_trust_only_the_exact_source_root_and_keep_identity_gates(self):
        with patch.object(release, "run", wraps=release.run) as invoke:
            self.manifest()
        commands = [call.args[0] for call in invoke.call_args_list]
        self.assertEqual(len(commands), 3)
        prefix = ["git", "-c", "safe.directory=" + str(self.source.resolve()), "-C", str(self.source.resolve())]
        self.assertTrue(all(command[:5] == prefix for command in commands))
        self.assertFalse(any("--global" in command or "safe.directory=*" in command for command in commands))
        with self.assertRaisesRegex(ValueError, "expected revision"):
            self.manifest(revision="0" * 40)
        (self.source / "untracked").write_text("changed source")
        with self.assertRaisesRegex(ValueError, "must be clean"):
            self.manifest()

    def test_missing_new_tool_fails_before_any_smoke(self):
        self.manifest()
        with self.assertRaisesRegex(ValueError, "required tool|payload sets"):
            release.verify_archive(self.archive(omit=("opaque-mcp-contract",)), **self.args, smoke=True)

    def test_modified_binary_is_rejected_even_with_intact_manifest(self):
        self.manifest()
        (self.binaries / "opaque").write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "payload verification"):
            release.verify_archive(self.archive(), **self.args)

    def test_wrong_revision_target_or_version_is_rejected(self):
        self.manifest()
        archive = self.archive()
        for update in ({"revision": "0" * 40}, {"version": "0.4.0"}, {"target": "aarch64-unknown-linux-gnu"}):
            with self.subTest(update=update), self.assertRaisesRegex(ValueError, "identity mismatch"):
                release.verify_archive(archive, **(self.args | update))

    def test_links_traversal_duplicates_and_internal_payloads_are_rejected(self):
        self.manifest()
        for name, kind in (("../outside", tarfile.REGTYPE), ("opaque", tarfile.REGTYPE),
                           ("opaque-linked", tarfile.SYMTYPE), ("docs/product/internal.md", tarfile.REGTYPE)):
            info = tarfile.TarInfo(name)
            info.type = kind
            info.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
            with self.subTest(name=name), self.assertRaises(ValueError):
                release.verify_archive(self.archive(extra=(info, b"")), **self.args, smoke=True)
        self.assertFalse((self.root / "outside").exists())

    def test_dirty_source_is_local_candidate_and_cannot_pass_release_gate(self):
        (self.source / "untracked.txt").write_text("local change")
        with self.assertRaisesRegex(ValueError, "must be clean"):
            self.manifest()
        manifest = self.manifest(allow_dirty=True)
        self.assertEqual(manifest["qualification"], "local_candidate")
        archive = self.archive()
        with self.assertRaisesRegex(ValueError, "dirty source"):
            release.verify_archive(archive, **self.args)
        self.assertEqual(release.verify_archive(archive, **self.args, allow_dirty=True), manifest)

    def test_source_version_and_revision_must_match(self):
        for update in ({"revision": "0" * 40}, {"version": "0.4.0"}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.manifest(**update)

    def test_missing_macos_app_prevents_manifest_generation(self):
        with self.assertRaisesRegex(ValueError, "complete reviewer app"):
            self.manifest(target="aarch64-apple-darwin")

    def test_metadata_cannot_claim_signed_or_qualified_release(self):
        self.manifest()
        path = self.binaries / release.MANIFEST
        manifest = json.loads(path.read_text())
        manifest["qualification"] = "live_qualified"
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "qualification claim"):
            release.verify_archive(self.archive(), **self.args)

    def test_smoke_rejects_mismatched_compiled_version(self):
        path = self.binaries / "opaque"
        path.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "opaque 0.2.0"; fi\n')
        self.manifest()
        with self.assertRaisesRegex(ValueError, "binary version mismatch"):
            release.verify_archive(self.archive(), **self.args, smoke=True)

    def test_smoke_binds_compiled_revision_and_accepts_longer_git_abbreviations(self):
        path = self.binaries / "opaqued"
        for suffix in ("", "+unknown", "+" + self.revision[:6], "+" + "f" * 40):
            with self.subTest(suffix=suffix):
                path.write_text(f'#!/bin/sh\nif [ "$1" = "--version" ]; then echo "opaqued 0.3.0{suffix}"; fi\n')
                self.manifest()
                with self.assertRaisesRegex(ValueError, "binary version mismatch"):
                    release.verify_archive(self.archive(), **self.args, smoke=True)
        for length in (12, 40):
            with self.subTest(length=length):
                path.write_text(f'#!/bin/sh\nif [ "$1" = "--version" ]; then echo "opaqued 0.3.0+{self.revision[:length]}"; fi\n')
                self.manifest()
                release.verify_archive(self.archive(), **self.args, smoke=True)


if __name__ == "__main__":
    unittest.main()
