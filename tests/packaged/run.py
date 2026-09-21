#!/usr/bin/env python3
"""Install a trusted build archive in disposable homes and exercise real custody.

The installer download is controlled local transport. This does not verify a
published release signature, enroll a workstation, or request native approval.
Linux requires root and two existing non-root accounts in a disposable runner.
macOS runs under the current account without installing or registering services.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import acceptance_coverage as COVERAGE
SPEC = importlib.util.spec_from_file_location("release_artifacts", ROOT / "scripts/release_artifacts.py")
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
NATIVE_MAGIC = {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
COMMAND_TIMEOUT_SECONDS = 15
CLEANUP_TIMEOUT_SECONDS = 2
TIMEOUT_DIAGNOSTICS = {"installer": "installer command timed out", "installed": "installed command timed out"}


class AcceptanceError(Exception):
    """Fixed, credential-free diagnostic safe for the qualification report."""


def require(condition, message):
    if not condition:
        raise AcceptanceError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def host_target():
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(platform.machine())
    os_target = {"Darwin": "apple-darwin", "Linux": "unknown-linux-gnu"}.get(platform.system())
    require(arch and os_target, "unsupported native acceptance host")
    return f"{arch}-{os_target}"


def stop_owned_group(process):
    # The real installer can spawn tar/curl children that inherit its pipes.
    # Killing only the shell can leave communicate waiting and children running.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.communicate(timeout=CLEANUP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        process.wait(timeout=CLEANUP_TIMEOUT_SECONDS)


def execute(command, *, environment, cwd, account=None, coverage=None, stage="installed"):
    require(stage in TIMEOUT_DIAGNOSTICS, "unrecognized installed command stage")
    options = {}
    if account and os.geteuid() == 0:
        options = {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": []}
    process = subprocess.Popen([str(value) for value in command], env=environment, cwd=cwd,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True, **options)
    try:
        stdout, stderr = process.communicate(timeout=COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        stop_owned_group(process)
        raise AcceptanceError(TIMEOUT_DIAGNOSTICS[stage]) from None
    except BaseException:
        stop_owned_group(process)
        raise
    if coverage is not None and Path(command[0]).name in RELEASE.BINS:
        COVERAGE.profiles(coverage, roles={"installed"}, process_ids={process.pid})
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def private_directory(path, account, mode=0o700):
    path.mkdir(mode=mode)
    path.chmod(mode)
    if os.geteuid() == 0:
        os.chown(path, account.pw_uid, account.pw_gid)


def clean_environment(home, temporary, prefix):
    # Intentionally construct a fresh environment: provider credentials,
    # delegated-session tokens, display state and host configuration stay out.
    return {"HOME": str(home), "TMPDIR": str(temporary), "PATH": f"{prefix}:/usr/bin:/bin",
            "LC_ALL": "C", "LANG": "C"}


def native_report(helper, approver):
    if helper.returncode == 0:
        try:
            report = json.loads(helper.stdout)
        except ValueError:
            raise AcceptanceError("installed helper capability report is not JSON") from None
        require(report == {"check": "native_review_ui", "ready": True, "visibility_verified": False},
                "installed helper capability report does not match its protocol")
    else:
        require(helper.returncode == 2 and helper.stdout == "" and any(
            reason in helper.stderr for reason in (
                "no Linux display is configured", "run the reviewer as the signed-in macOS console user",
                "no macOS screen is available", "cannot inspect the active macOS console session")),
                "installed helper did not report a recognized headless capability denial")
    if approver.returncode == 0:
        try:
            report = json.loads(approver.stdout)
        except ValueError:
            raise AcceptanceError("installed approver capability report is not JSON") from None
        require(helper.returncode == 0 and report == {"check": "native_review", "ready": True,
                "visibility_verified": False, "authentication_available": True},
                "installed approver capability report does not match its protocol")
        return "capability_available_no_human_decision"
    require(approver.returncode == 1 and approver.stdout == "" and any(
        reason in approver.stderr for reason in (
            "native review UI unavailable", "native authentication unavailable in this macOS session",
            "pkcheck is required", "polkit authentication tools are unavailable",
            "Opaque polkit action is not installed")),
            "installed approver did not report a recognized capability denial")
    return "capability_unavailable_fail_closed"


def acceptance(args):
    require(args.target == host_target(), "archive target must match the executing host")
    coverage = COVERAGE.load(args.coverage_input, root=ROOT, purpose="packaged") if getattr(args, "coverage_input", None) else None
    linux = platform.system() == "Linux"
    if linux:
        require(os.geteuid() == 0 and args.owner_user and args.peer_user,
                "Linux acceptance requires root and two explicit existing runner accounts")
        try:
            owner, peer = pwd.getpwnam(args.owner_user), pwd.getpwnam(args.peer_user)
        except KeyError:
            raise AcceptanceError("requested Linux runner account is unavailable") from None
        require(owner.pw_uid != 0 and peer.pw_uid != 0 and owner.pw_uid != peer.pw_uid,
                "Linux custody owner and peer must be distinct non-root accounts")
    else:
        require(os.geteuid() != 0 and not args.owner_user and not args.peer_user,
                "macOS acceptance must use its current non-root account")
        owner, peer = pwd.getpwuid(os.geteuid()), None

    report = {"schema": "opaque.packaged-acceptance.v1", "status": "failed", "target": args.target,
              "version": args.version, "source_revision": args.revision, "transport": "controlled_local_archive_via_real_installer",
              "published_signature_verified": False, "native_human_approval": False,
              "service_registration": False, "cases": []}
    with tempfile.TemporaryDirectory(prefix="opaque-packaged-") as temporary:
        root = Path(temporary)
        root.chmod(0o711)
        private = root / "private"
        private.mkdir(mode=0o700)
        archive = private / "candidate.tar.gz"
        shutil.copyfile(args.archive, archive)
        manifest = RELEASE.verify_archive(archive, version=args.version, revision=args.revision,
                                         target=args.target, allow_dirty=args.allow_dirty)
        report.update({"archive_sha256": digest(archive), "source_tree_sha256": manifest["source_tree_sha256"],
                       "candidate_qualification": manifest["qualification"]})
        if coverage:
            require(manifest["source_revision"] == coverage["source"]["revision"]
                    and manifest["source_tree_sha256"] == coverage["source"]["release_tree_sha256"],
                    "instrumented archive source identity differs")
            require(all(manifest["files"][name]["sha256"] == coverage["objects"][name]["sha256"]
                        for name in RELEASE.BINS), "archive differs from collector mapping objects")
        payload = root / "payload"
        payload.mkdir(mode=0o755)
        payload.chmod(0o755)
        with tarfile.open(archive, "r:gz") as stream:
            for name, description in manifest["files"].items():
                data = stream.extractfile(name).read()
                require(hashlib.sha256(data).hexdigest() == description["sha256"], "archive changed during extraction")
                path = payload / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o755 if description["executable"] else 0o644)
        for name in RELEASE.BINS:
            with (payload / name).open("rb") as stream:
                require(stream.read(4) in NATIVE_MAGIC, "archive contains an inert or non-native tool")
        report["cases"].append("complete_source_bound_native_payload")

        home, scratch, prefix = root / "owner-home", root / "owner-tmp", root / "installed"
        for path, mode in ((home, 0o700), (scratch, 0o700), (prefix, 0o755)):
            private_directory(path, owner, mode)
        environment = clean_environment(home, scratch, prefix)
        if coverage:
            environment.update(COVERAGE.environment(coverage, "installed"))
        transport = root / "transport"
        transport.mkdir(mode=0o755)
        transport.chmod(0o755)
        archive_copy = transport / "candidate.tar.gz"
        shutil.copyfile(archive, archive_copy)
        archive_copy.chmod(0o644)
        checksum = transport / "candidate.sha256"
        checksum.write_text(report["archive_sha256"] + "  candidate.tar.gz\n")
        checksum.chmod(0o644)
        shim = transport / "curl"
        shim.write_text(f"#!{sys.executable}\n" + (Path(__file__).with_name("transport.py")).read_text())
        shim.chmod(0o755)
        request_log = scratch / "transport-requests.jsonl"
        archive_url = f"https://github.com/opaque-dev/opaque/releases/download/v{args.version}/opaque-{args.version}-{args.target}.tar.gz"
        install_environment = {**environment, "PATH": f"{transport}:/usr/bin:/bin",
                               "OPAQUE_VERSION": args.version, "OPAQUE_INSTALL": str(prefix),
                               "OPAQUE_PACKAGED_ARCHIVE": str(archive_copy), "OPAQUE_PACKAGED_URL": archive_url,
                               "OPAQUE_PACKAGED_CHECKSUM": str(checksum), "OPAQUE_PACKAGED_REQUESTS": str(request_log)}
        installed = execute(["/bin/sh", ROOT / "install.sh"], environment=install_environment, cwd=root, account=owner, stage="installer")
        require(installed.returncode == 0 and "Checksum verified." in installed.stdout,
                "real installer did not verify and install the selected archive")
        for name in RELEASE.BINS:
            path = prefix / name
            require(path.is_file() and not path.is_symlink() and digest(path) == manifest["files"][name]["sha256"]
                    and stat.S_IMODE(path.stat().st_mode) == 0o755, "installed payload differs from its verified archive")
        requests = [json.loads(line) for line in request_log.read_text().splitlines()]
        require(requests == [archive_url, archive_url + ".sha256"], "installer used an unexpected transport request")
        report["cases"].append("real_installer_checksum_and_exact_payload")

        for name in RELEASE.BINS:
            if name == "opaque-approve-helper":
                continue
            result = execute([prefix / name, "--help"], environment=environment, cwd=home, account=owner, coverage=coverage)
            require(result.returncode == 0 and result.stdout.strip(), "installed CLI help failed")
        for name in ("opaque", "opaqued"):
            result = execute([prefix / name, "--version"], environment=environment, cwd=home, account=owner, coverage=coverage)
            matched = re.fullmatch(re.escape(f"{name} {args.version}") + r"\+([0-9a-f]{7,40})", result.stdout.strip())
            require(result.returncode == 0 and matched and args.revision.startswith(matched[1]),
                    "installed binary identity differs from its selected revision")
        report["cases"].append("installed_cli_help_and_revision")

        approver = prefix / "opaque-approver"
        custody = home / "custody"
        def call(*arguments, account=owner, extra_environment=None):
            return execute([approver, *arguments], environment={**environment, **(extra_environment or {})}, cwd=root, account=account, coverage=coverage)
        def denied(result, expected):
            require(result.returncode == 1 and not result.stdout and expected in result.stderr,
                    "installed custody guard did not reject the selected mutation")
        result = call("init", "--state-dir", custody, "--name", "Packaged acceptance")
        require(result.returncode == 0, "installed approver could not initialize custody")
        public = json.loads(result.stdout)
        require(re.fullmatch(r"[0-9a-f]{64}", public.get("public_key_hex", "")), "installed approver returned invalid public identity")
        key, state = custody / "workstation.key", custody / "workstation.json"
        require(key.stat().st_size == 32 and state.is_file(), "installed custody files are incomplete")
        for path, mode in ((custody, 0o700), (key, 0o600), (state, 0o600)):
            require(path.stat().st_uid == owner.pw_uid and stat.S_IMODE(path.stat().st_mode) == mode,
                    "installed custody ownership or permissions differ from the account boundary")
        original = {path: digest(path) for path in (key, state)}
        denied(call("list", "--state-dir", custody), "workstation is not enrolled")
        denied(call("init", "--state-dir", custody, "--name", "Reinitialize"), "already exists")
        require(all(digest(path) == value for path, value in original.items()), "restart or reinitialization replaced custody")
        report["cases"].append("installed_custody_owner_permissions_restart_and_reinit_denial")

        custody.chmod(0o755)
        denied(call("list", "--state-dir", custody), "owned, private 0700 directory")
        custody.chmod(0o700)
        key.chmod(0o644)
        denied(call("list", "--state-dir", custody), "owned private file")
        key.chmod(0o600)
        alias = home / "custody-alias"
        alias.symlink_to(custody)
        denied(call("list", "--state-dir", alias), "owned, private 0700 directory")
        alias.unlink()
        hardlink = custody / "extra-key-link"
        os.link(key, hardlink)
        denied(call("list", "--state-dir", custody), "owned private file")
        hardlink.unlink()
        saved_key = custody / "original.key"
        key.rename(saved_key)
        key.symlink_to(saved_key)
        denied(call("list", "--state-dir", custody), "credential unavailable")
        key.unlink()
        saved_key.rename(key)
        saved_state = state.read_bytes()
        mutated = json.loads(saved_state)
        mutated["public_key_hex"] = "00" * 32
        state.write_text(json.dumps(mutated))
        denied(call("list", "--state-dir", custody), "state/key mismatch")
        state.write_bytes(saved_state)
        denied(call("list", "--state-dir", custody), "workstation is not enrolled")
        require(all(digest(path) == value for path, value in original.items()), "custody mutation recovery changed the original identity")
        report["cases"].append("installed_custody_mode_symlink_hardlink_and_identity_mutations")

        forbidden = home / "delegated-custody"
        denied(call("init", "--state-dir", forbidden, "--name", "Delegated",
                    extra_environment={"OPAQUE_SESSION_TOKEN": "synthetic-delegated-session"}),
               "outside delegated agent sessions")
        require(not forbidden.exists(), "delegated-session denial created custody")
        report["cases"].append("installed_delegated_session_denial_before_custody")
        if peer:
            denied(call("list", "--state-dir", custody, account=peer), "custody directory unavailable")
            probe = execute([sys.executable, "-c", "import pathlib,sys\ntry: pathlib.Path(sys.argv[1]).read_bytes()\nexcept PermissionError: sys.exit(0)\nsys.exit(9)", key],
                            environment=environment, cwd=root, account=peer)
            require(probe.returncode == 0 and not probe.stdout, "separate Linux account could read owner custody")
            report["cases"].append("installed_linux_distinct_uid_and_spoofed_home_denial")

        helper_result = execute([prefix / "opaque-approve-helper", "--check-ui"], environment=environment, cwd=home, account=owner, coverage=coverage)
        approver_result = call("check-native")
        report["native_capability"] = native_report(helper_result, approver_result)
        report["cases"].append("installed_native_capability_protocol_without_prompt")
        if not linux:
            app = home / "Applications" / RELEASE.APP
            app.parent.mkdir(mode=0o700)
            shutil.copytree(payload / RELEASE.APP, app)
            info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
            require(info.get("CFBundleExecutable") == "OpaqueReviewer", "installed app executable contract differs")
            verified = execute(["/usr/bin/codesign", "--verify", "--deep", "--strict", app], environment=environment, cwd=home)
            require(verified.returncode == 0, "relocated reviewer app signature verification failed")
            for binary in ("OpaqueReviewer", "opaque-approver", "opaque-approve-helper"):
                with (app / "Contents/MacOS" / binary).open("rb") as stream:
                    require(stream.read(4) in NATIVE_MAGIC, "reviewer app contains an inert or non-native binary")
            result = execute([app / "Contents/MacOS/OpaqueReviewer", "--self-test"], environment=environment, cwd=home)
            require(result.returncode == 0 and "native UI not invoked" in result.stdout,
                    "relocated native reviewer launcher self-test failed")
            report["cases"].append("installed_macos_relocated_signed_app_runtime")
        require(not (home / ".opaque").exists(), "installed command unexpectedly initialized default daemon state")
        report["cases"].append("isolated_home_without_default_daemon_state")
        if coverage:
            report["coverage"] = {"qualification": coverage["qualification"],
                                  "input_sha256": COVERAGE.digest(args.coverage_input),
                                  "profiles": COVERAGE.profiles(coverage, roles={"installed"}),
                                  "scope": "Rust workspace runtime counters; system installer, Swift launcher and native human presence are not Rust coverage"}
        report["status"] = "passed"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--target", choices=RELEASE.TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--owner-user")
    parser.add_argument("--peer-user")
    parser.add_argument("--coverage-input", type=Path, help="explicit collector-built objects and fresh LLVM output; never ambient")
    args = parser.parse_args()
    try:
        require(not args.output.exists(), "choose a fresh acceptance output path")
        report = acceptance(args)
    except (AcceptanceError, ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        message = str(error) if isinstance(error, AcceptanceError) else "acceptance prerequisite or subprocess failed"
        parser.exit(1, f"packaged acceptance: {message}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "target": report["target"], "cases_passed": len(report["cases"])}))


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        # Unwind temporary homes/custody when the composed runner cancels its
        # owned process group; default SIGTERM would bypass context cleanup.
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print("Packaged acceptance interrupted; no qualification produced.", file=sys.stderr)
        sys.exit(130)
