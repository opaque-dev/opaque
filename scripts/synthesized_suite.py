#!/usr/bin/env python3
"""Run exact, declared unattended acceptance tests; never measure product coverage.

Only the reviewed manifest selects executables/tests. Captured subprocess output
is bounded and hashed, never copied into JSON/JUnit or printed on failure.
Reports are new private files outside the checkout or inside an ignored directory.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import xml.etree.ElementTree as ET

SCHEMA = "opaque.synthesized-suite.v1"
LIMIT = 8 * 1024 * 1024
ID = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_:.-]{0,255}\Z")
SOFTWARE = ("protocol", "contained", "model", "packaged")
PACKAGED_CHECKS = (
    "complete_source_bound_native_payload", "real_installer_checksum_and_exact_payload",
    "installed_cli_help_and_revision", "installed_custody_owner_permissions_restart_and_reinit_denial",
    "installed_custody_mode_symlink_hardlink_and_identity_mutations",
    "installed_delegated_session_denial_before_custody",
    "installed_native_capability_protocol_without_prompt", "isolated_home_without_default_daemon_state",
)
# Match complete fixed diagnostics from tests/packaged/run.py. Never publish
# arbitrary subprocess output, command arguments, or exception payloads.
PACKAGED_FAILURES = {
    b"packaged acceptance: installed binary identity differs from its selected revision\n": "installed_revision_mismatch",
    b"packaged acceptance: acceptance prerequisite or subprocess failed\n": "prerequisite_or_subprocess_failed",
    b"packaged acceptance: installer command timed out\n": "installer_timeout",
    b"packaged acceptance: installed command timed out\n": "installed_command_timeout",
    b"Packaged acceptance interrupted; no qualification produced.\n": "interrupted",
}


class Invalid(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def json_read(path):
    data = Path(path).read_bytes()
    require(len(data) <= 1024 * 1024, "manifest_too_large")
    return json.loads(data, object_pairs_hook=unique_pairs)


def fields(value, required, optional=()):
    require(isinstance(value, dict), "invalid_manifest_object")
    require(set(required) <= set(value) <= set(required) | set(optional), "invalid_manifest_fields")


def valid_name(value, expression=ID):
    require(isinstance(value, str) and expression.fullmatch(value), "invalid_manifest_identifier")


def validate_manifest(value):
    fields(value, ("schema", "scope", "profiles", "targets", "tests", "requirements"))
    require(value["schema"] == SCHEMA, "unsupported_manifest_schema")
    require(isinstance(value["scope"], str) and 1 <= len(value["scope"]) <= 1000, "invalid_manifest_scope")
    require(value["profiles"] == list(SOFTWARE), "invalid_profiles")
    for key in ("targets", "tests", "requirements"):
        require(isinstance(value[key], list) and 0 < len(value[key]) <= 512, "invalid_manifest_collection")
        require(len({entry.get("id") for entry in value[key] if isinstance(entry, dict)}) == len(value[key]), "duplicate_manifest_identifier")
    targets = {}
    compile_identities = set()
    for target in value["targets"]:
        fields(target, ("id", "package", "kind", "name", "features", "platforms", "root", "tools", "build_timeout_seconds"), ("requires_sys_ptrace",))
        for key in ("id", "package", "name"):
            valid_name(target[key], NAME if key == "name" else ID)
        require(target["kind"] in ("test", "lib", "bin"), "invalid_target_kind")
        require(isinstance(target["features"], list) and len(set(target["features"])) == len(target["features"]), "invalid_features")
        for feature in target["features"]:
            valid_name(feature)
        identity = (target["package"], target["kind"], target["name"], tuple(sorted(target["features"])))
        require(identity not in compile_identities, "duplicate_compilation_target")
        compile_identities.add(identity)
        require(isinstance(target["platforms"], list) and target["platforms"] and set(target["platforms"]) <= {"linux", "darwin"}, "invalid_platforms")
        require(type(target["root"]) is bool, "invalid_root_prerequisite")
        require(type(target.get("requires_sys_ptrace", False)) is bool, "invalid_capability_prerequisite")
        require(isinstance(target["tools"], list), "invalid_tools")
        for tool in target["tools"]:
            valid_name(tool)
        require(type(target["build_timeout_seconds"]) is int and 1 <= target["build_timeout_seconds"] <= 2400, "invalid_build_timeout")
        targets[target["id"]] = target
    tests = {}
    identities = set()
    for test in value["tests"]:
        fields(test, ("id", "target", "name", "timeout_seconds", "include_ignored"), ("proof",))
        valid_name(test["id"])
        valid_name(test["name"], NAME)
        require(test["target"] in targets, "unknown_test_target")
        require(type(test["include_ignored"]) is bool, "invalid_ignored_selection")
        require(type(test["timeout_seconds"]) is int and 1 <= test["timeout_seconds"] <= 600, "invalid_test_timeout")
        require(test.get("proof") in (None, "task_state_model"), "unknown_proof_kind")
        identity = (test["target"], test["name"])
        require(identity not in identities, "duplicate_compiled_test")
        identities.add(identity)
        tests[test["id"]] = test
    referenced = set()
    for requirement in value["requirements"]:
        fields(requirement, ("id", "profile", "status", "tests", "description"), ("runner", "platforms"))
        valid_name(requirement["id"])
        require(requirement["profile"] in (*SOFTWARE, "external"), "invalid_requirement_profile")
        require(requirement["status"] in ("implemented", "missing", "external"), "invalid_requirement_status")
        require(isinstance(requirement["description"], str) and 1 <= len(requirement["description"]) <= 1000, "invalid_requirement_description")
        names = requirement["tests"]
        require(isinstance(names, list) and len(names) == len(set(names)) and set(names) <= set(tests), "invalid_requirement_tests")
        if "platforms" in requirement:
            platforms = requirement["platforms"]
            require(isinstance(platforms, list) and platforms and len(platforms) == len(set(platforms))
                    and set(platforms) <= {"linux", "darwin"}, "invalid_requirement_platforms")
        runner = requirement.get("runner")
        if "runner" in requirement:
            require(runner == "installed-artifacts" and requirement["profile"] == "packaged"
                    and requirement["status"] == "implemented" and not names
                    and len(requirement.get("platforms", [])) == 1, "invalid_requirement_runner")
        if requirement["status"] == "implemented":
            require((bool(names) or runner == "installed-artifacts") and requirement["profile"] != "external", "vacuous_requirement")
        else:
            require(not names, "unimplemented_requirement_has_tests")
        require((requirement["profile"] == "external") == (requirement["status"] == "external"), "invalid_external_requirement")
        referenced.update(names)
    require(referenced == set(tests), "unmapped_test")
    require(all(any(r["profile"] == profile for r in value["requirements"]) for profile in SOFTWARE), "missing_profile_requirements")
    return value


@dataclass
class CommandResult:
    returncode: int
    output: bytes
    reason: str | None = None
    cleanup_forced: bool = False


def stop_group(process):
    """Terminate only the process group created for this invocation."""
    forced = False
    denied = None
    try:
        for sig, grace in ((signal.SIGTERM, 0.5), (signal.SIGKILL, 0.5)):
            try:
                os.killpg(process.pid, sig)
                forced = True
            except ProcessLookupError:
                return forced
            except PermissionError as error:
                denied = error
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                process.poll()
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    return forced
                except PermissionError as error:
                    # Darwin can return EPERM for an exited, zombie-only group.
                    # Reap/poll within the same deadline and require real ESRCH;
                    # permission denial alone never proves group removal.
                    denied = error
                time.sleep(0.02)
        if denied is not None:
            raise Invalid("process_group_cleanup_permission_denied") from denied
        return forced
    finally:
        # An inspection error must not bypass retirement of our direct child.
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def invoke(argv, *, cwd, env, timeout):
    require(os.name == "posix", "unsupported_process_cleanup")
    with tempfile.TemporaryFile() as capture:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=capture, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + timeout
        reason = None
        try:
            while process.poll() is None:
                if os.fstat(capture.fileno()).st_size > LIMIT:
                    reason = "output_limit"
                    break
                if time.monotonic() >= deadline:
                    reason = "timeout"
                    break
                time.sleep(0.02)
        finally:
            # Also remove descendants if their test parent exited without them.
            forced = stop_group(process)
        capture.seek(0)
        output = capture.read(LIMIT + 1)
        if len(output) > LIMIT:
            reason = "output_limit"
        elif forced and reason is None:
            reason = "leaked_process_group"
        return CommandResult(process.returncode if process.returncode is not None else -1,
                             output[:LIMIT], reason, forced)


def command_ok(result):
    require(result.reason is None, result.reason or "command_failed")
    require(result.returncode == 0, "command_failed")


def environment(*, execution_home=None):
    # Never forward cloud credentials, agent sessions or test bypass variables.
    keys = ("PATH", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTUP_DIST_SERVER",
            "RUSTUP_UPDATE_ROOT", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT")
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env.setdefault("CARGO_HOME", str(Path.home() / ".cargo"))
    env.setdefault("RUSTUP_HOME", str(Path.home() / ".rustup"))
    env.update({"HOME": str(execution_home or Path.home()), "CARGO_TERM_COLOR": "never",
                "RUST_BACKTRACE": "0", "LC_ALL": "C", "LANG": "C"})
    return env


def git_command(root, *args):
    # A sudo CI runner reads a checkout owned by its invoking user. Trust only
    # this explicitly selected checkout for this invocation; never alter global
    # git configuration or allow arbitrary repositories with safe.directory=*.
    return ["git", "-c", "safe.directory=" + str(Path(root).resolve()), *args]


def source_snapshot(root, executor=invoke):
    env = environment()
    def git(*args):
        result = executor(git_command(root, *args), cwd=root, env=env, timeout=30)
        command_ok(result)
        return result.output
    revision = git("rev-parse", "HEAD").decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40,64}", revision), "invalid_source_revision")
    names = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""})
    require(len(names) <= 20000, "source_inventory_limit")
    total = 0
    hasher = hashlib.sha256(b"opaque.synthesized-source.v1\0")
    release_hasher = hashlib.sha256()
    for name in names:
        relative = Path(os.fsdecode(name))
        require(not relative.is_absolute() and ".." not in relative.parts, "invalid_source_path")
        path = root / relative
        if path.is_symlink():
            body = os.fsencode(os.readlink(path))
            kind = b"symlink"
            mode = 0
        elif path.is_file():
            require(path.stat().st_size <= 64 * 1024 * 1024, "source_file_limit")
            body = path.read_bytes()
            kind = b"file"
            mode = path.stat().st_mode & 0o777
        else:
            body, kind, mode = b"", b"missing", 0
        total += len(body)
        require(total <= 256 * 1024 * 1024, "source_total_limit")
        # Also retain the production archive manifest's digest format so an
        # installed candidate is bound to these exact source bytes, including
        # uncommitted changes, rather than its commit label alone.
        release_hasher.update(name + b"\0")
        if kind == b"file":
            release_hasher.update(b"file\0" + hashlib.sha256(body).digest())
        elif kind == b"symlink":
            release_hasher.update(b"symlink\0" + body)
        else:
            release_hasher.update(b"absent\0")
        for part in (name, kind, str(mode).encode(), hashlib.sha256(body).digest()):
            hasher.update(len(part).to_bytes(8, "big"))
            hasher.update(part)
    status = git("status", "--porcelain=v1", "-z", "--untracked-files=all")
    return {"revision": revision, "dirty": bool(status), "tree_sha256": hasher.hexdigest(),
            "release_tree_sha256": release_hasher.hexdigest(), "status_sha256": digest(status), "file_count": len(names)}


def inventory(output):
    text = output.decode("utf-8", errors="strict")
    names = re.findall(r"^([A-Za-z_][A-Za-z0-9_:.-]*): test$", text, re.MULTILINE)
    summaries = re.findall(r"^(\d+) tests?, (\d+) benchmarks?$", text, re.MULTILINE)
    require(len(summaries) == 1 and int(summaries[0][0]) == len(names) and int(summaries[0][1]) == 0, "invalid_test_inventory")
    require(names and len(names) == len(set(names)), "empty_or_duplicate_inventory")
    return set(names)


def named_pass(output, name):
    text = output.decode("utf-8", errors="strict")
    results = re.findall(r"^test (.+?) \.\.\. (ok|FAILED|ignored(?:, .*)?)$", text, re.MULTILINE)
    summaries = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text, re.MULTILINE)
    require(results == [(name, "ok")], "missing_or_nonpassing_named_result")
    require(len(summaries) == 1 and summaries[0][:5] == ("ok", "1", "0", "0", "0"), "partial_or_skipped_test_result")


def model_proof(output):
    lines = [line.removeprefix(b"TASK_MODEL_COVERAGE ") for line in output.splitlines()
             if line.startswith(b"TASK_MODEL_COVERAGE ")]
    require(len(lines) == 1 and len(lines[0]) <= 4096, "missing_or_duplicate_model_proof")
    proof = json.loads(lines[0], object_pairs_hook=unique_pairs)
    expected = {"schema_version": 1, "fixed_cases": 8, "abstract_states": 79,
                "abstract_edges": 1343, "allowed_edges": 345, "denied_edges": 998,
                "fresh_database_sequences": 1351, "persisted_transition_checks": 8848,
                "max_witness_depth": 6, "declared_depth_bound": 8, "slots": 1,
                "request_identities": 2, "logical_instants": 2, "wall_clock_sleeps": 0,
                "provider_calls": 0}
    # These finite bounds are a reviewed requirement, not inferred universality.
    require(proof == expected and all(type(v) is int for v in proof.values()), "changed_or_incomplete_model_proof")
    return {"scope": "finite sequential one-slot abstraction; not all histories or concurrent schedules",
            "observed": proof}


def artifact(output, target, target_dir):
    matches = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(event, dict) or event.get("reason") != "compiler-artifact":
            continue
        description = event.get("target", {})
        if (event.get("profile", {}).get("test") is True and description.get("name") == target["name"]
                and target["kind"] in description.get("kind", []) and event.get("executable")):
            matches.append(Path(event["executable"]))
    require(len(matches) == 1, "missing_or_ambiguous_test_artifact")
    path = matches[0]
    require(path.is_absolute() and not path.is_symlink() and path.is_file()
            and path.resolve().is_relative_to(target_dir.resolve()), "invalid_test_artifact")
    return path


def build_argv(target, target_dir):
    argv = ["cargo", "test", "--locked", "-p", target["package"]]
    argv += ["--lib"] if target["kind"] == "lib" else ["--" + target["kind"], target["name"]]
    if target["features"]:
        argv += ["--features", ",".join(target["features"])]
    return argv + ["--target-dir", str(target_dir), "--no-run", "--message-format=json"]


def has_sys_ptrace():
    if sys.platform != "linux":
        return False
    try:
        status = Path("/proc/self/status").read_text()
        value = re.search(r"^CapEff:\s*([0-9a-fA-F]+)$", status, re.MULTILINE)
        return bool(value and int(value[1], 16) & (1 << 19))
    except OSError:
        return False


def toolchain_snapshot(root, executor):
    result = executor(["rustc", "-vV"], cwd=root, env=environment(), timeout=30)
    command_ok(result)
    text = result.output.decode("utf-8")
    metadata = {}
    for name, pattern in (("release", r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?"),
                          ("host", r"[a-zA-Z0-9_-]+"),
                          ("commit-hash", r"[0-9a-f]{40}")):
        found = re.findall(r"^" + name + r": (" + pattern + r")$", text, re.MULTILINE)
        require(len(found) == 1, "invalid_toolchain_identity")
        metadata[name] = found[0]
    return metadata


def packaged_report(value, *, source, target, version, archive_sha256):
    fields(value, ("schema", "status", "version", "target", "source_revision", "source_tree_sha256",
                   "archive_sha256", "candidate_qualification", "transport", "published_signature_verified",
                   "native_human_approval", "service_registration", "cases", "native_capability"), ("coverage",))
    require(value["schema"] == "opaque.packaged-acceptance.v1" and value["status"] == "passed", "packaged_runner_did_not_pass")
    require(value["source_revision"] == source["revision"] and value["version"] == version
            and value["source_tree_sha256"] == source["release_tree_sha256"], "packaged_source_identity_mismatch")
    require(value["target"] == target and value["archive_sha256"] == archive_sha256, "packaged_artifact_identity_mismatch")
    require(value["candidate_qualification"] in ("local_candidate", "build_candidate")
            and value["transport"] == "controlled_local_archive_via_real_installer", "invalid_packaged_qualification")
    require(all(value[field] is False for field in ("published_signature_verified", "native_human_approval", "service_registration")),
            "invalid_packaged_external_claim")
    require(value["native_capability"] in ("capability_available_no_human_decision", "capability_unavailable_fail_closed"),
            "invalid_packaged_native_capability")
    platform_check = ("installed_linux_distinct_uid_and_spoofed_home_denial" if target.endswith("unknown-linux-gnu")
                      else "installed_macos_relocated_signed_app_runtime")
    checks = value["cases"]
    require(isinstance(checks, list) and len(checks) == len(set(checks))
            and set(checks) == {*PACKAGED_CHECKS, platform_check}, "missing_or_unexpected_packaged_checks")
    return value


def run_suite(manifest, root, profile, target_dir, *, executor=invoke, snapshot=source_snapshot, model_profile=None,
              packaged_archive=None, packaged_owner_user=None, packaged_peer_user=None, packaged_allow_dirty=False,
              coverage_input=None):
    validate_manifest(manifest)
    require(profile in (*SOFTWARE, "all"), "unknown_profile")
    selected = set(SOFTWARE if profile == "all" else (profile,))
    requirements = [r for r in manifest["requirements"] if r["profile"] in selected
                    and sys.platform in r.get("platforms", [sys.platform])]
    packaged_selected = any(r.get("runner") == "installed-artifacts" for r in requirements)
    require(packaged_selected or not any((packaged_archive, packaged_owner_user, packaged_peer_user, packaged_allow_dirty)),
            "packaged_input_without_selected_runner")
    selected_ids = {name for r in requirements for name in r["tests"]}
    model_tests = {name for r in requirements if r["profile"] == "model" for name in r["tests"]}
    model_digest = None
    if model_profile is not None:
        require(bool(model_tests), "model_input_without_selected_model_test")
        model_profile = Path(model_profile).absolute()
        require(model_profile.is_file() and not model_profile.is_symlink()
                and 0 < model_profile.stat().st_size <= 64 * 1024, "invalid_model_profile_input")
        model_digest = digest(model_profile.read_bytes())
    tests = [t for t in manifest["tests"] if t["id"] in selected_ids]
    started = time.time()
    try:
        initial = snapshot(root)
    except (Invalid, OSError, ValueError, UnicodeError):
        initial = None
    coverage = None
    if coverage_input is not None:
        import acceptance_coverage
        require(profile in ("model", "packaged") and initial is not None, "coverage_requires_explicit_native_acceptance_profile")
        coverage = acceptance_coverage.load(coverage_input, root=root, purpose=profile, source=initial)
    results = {}
    commands = []
    artifacts = {}
    gates = [] if initial is not None else ["initial_source_unavailable"]
    if not requirements:
        gates.append("no_requirements_for_platform")
    try:
        toolchain = toolchain_snapshot(root, executor)
    except (Invalid, OSError, ValueError, UnicodeError):
        toolchain = None
        gates.append("toolchain_unavailable")
    with tempfile.TemporaryDirectory(prefix="opaque-suite-home-") as temporary:
        run_env = environment(execution_home=temporary)
        for target in manifest["targets"]:
            cases = [case for case in tests if case["target"] == target["id"]]
            if not cases:
                continue
            try:
                require(initial is not None, "initial_source_unavailable")
                require(toolchain is not None, "toolchain_unavailable")
                require(sys.platform in target["platforms"], "platform_unavailable")
                require(not target["root"] or os.geteuid() == 0, "root_required")
                require(not target.get("requires_sys_ptrace") or has_sys_ptrace(), "sys_ptrace_required")
                require(all(shutil.which(tool) for tool in ("cargo", "git", *target["tools"])), "tool_unavailable")
                if coverage:
                    require(profile == "model" and target["package"] == "opaqued"
                            and target["kind"] == "test" and target["name"] == "contained_ssh_e2e",
                            "coverage_prebuilt_target_mismatch")
                    require(toolchain["host"] == coverage["target"] and "-nightly" in toolchain["release"],
                            "coverage_native_toolchain_mismatch")
                    binary = Path(coverage["objects"]["model-test"]["path"])
                    require(binary.resolve().is_relative_to(target_dir.resolve()), "coverage_target_directory_mismatch")
                else:
                    built = executor(build_argv(target, target_dir), cwd=root, env=environment(),
                                     timeout=target["build_timeout_seconds"])
                    command_ok(built)
                    binary = artifact(built.output, target, target_dir)
                binary_hash = digest(binary.read_bytes())
                # Libtest's terse listing omits its inventory-count footer.
                # The ordinary format lets us reject a truncated listing.
                inventory_env = run_env.copy()
                if coverage:
                    inventory_env["LLVM_PROFILE_FILE"] = str(Path(temporary) / "inventory-%p-%m-%c.profraw")
                listed = executor([str(binary), "--list"], cwd=root, env=inventory_env, timeout=30)
                command_ok(listed)
                discovered = inventory(listed.output)
                require(all(case["name"] in discovered for case in cases), "required_test_missing")
                artifacts[target["id"]] = {"sha256": binary_hash, "inventory_count": len(discovered),
                                            "inventory_sha256": digest("\n".join(sorted(discovered)).encode()),
                                            "package": target["package"], "kind": target["kind"],
                                            "target_name": target["name"], "features": target["features"]}
            except (Invalid, OSError, ValueError, UnicodeError):
                reason = sys.exc_info()[1]
                code = str(reason) if isinstance(reason, Invalid) else "target_setup_failed"
                for case in cases:
                    results[case["id"]] = {"status": "blocked", "reason": code, "elapsed_ms": 0, "executed": False}
                continue
            for case in cases:
                begin = time.monotonic()
                entry = {"executed": False}
                try:
                    require(digest(binary.read_bytes()) == binary_hash, "test_artifact_changed")
                    argv = [str(binary), "--exact", case["name"], "--test-threads=1", "--color", "never"]
                    if case["include_ignored"]:
                        argv.append("--include-ignored")
                    if case.get("proof"):
                        argv.append("--show-output")
                    case_env = run_env.copy()
                    if case["id"] in model_tests:
                        require(model_profile is not None, "required_real_model_profile_missing")
                        require(digest(model_profile.read_bytes()) == model_digest, "model_profile_changed")
                        case_env["OPAQUE_TEST_REAL_MODEL_PROFILE"] = str(model_profile)
                        if coverage:
                            case_env.update(acceptance_coverage.environment(coverage))
                    result = executor(argv, cwd=root, env=case_env, timeout=case["timeout_seconds"])
                    entry.update(executed=True, output_sha256=digest(result.output),
                                 output_bytes=len(result.output), cleanup_forced=result.cleanup_forced)
                    command_ok(result)
                    named_pass(result.output, case["name"])
                    if case.get("proof") == "task_state_model":
                        entry["proof"] = model_proof(result.output)
                    require(digest(binary.read_bytes()) == binary_hash, "test_artifact_changed")
                    if case["id"] in model_tests:
                        require(digest(model_profile.read_bytes()) == model_digest, "model_profile_changed")
                    entry.update(status="passed", reason=None)
                except (Invalid, OSError, ValueError, UnicodeError) as error:
                    entry.update(status="failed", reason=str(error) if isinstance(error, Invalid) else "test_execution_failed")
                entry["elapsed_ms"] = round((time.monotonic() - begin) * 1000)
                results[case["id"]] = entry
        if packaged_selected:
            begin = time.monotonic()
            entry = {"id": "installed-artifacts", "executed": False}
            try:
                require(initial is not None and toolchain is not None, "packaged_source_or_toolchain_unavailable")
                if coverage:
                    require(toolchain["host"] == coverage["target"] and "-nightly" in toolchain["release"],
                            "coverage_native_toolchain_mismatch")
                require(not initial["dirty"] or packaged_allow_dirty, "packaged_clean_source_required")
                require(toolchain["host"].endswith({"linux": "unknown-linux-gnu", "darwin": "apple-darwin"}.get(sys.platform, "unsupported")),
                        "packaged_native_target_required")
                require(packaged_archive is not None, "required_packaged_archive_missing")
                archive = Path(packaged_archive).absolute()
                require(archive.is_file() and not archive.is_symlink()
                        and 0 < archive.stat().st_size <= 2 * 1024**3, "invalid_packaged_archive_input")
                with archive.open("rb") as stream:
                    archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
                version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
                output = Path(temporary) / "packaged-report.json"
                argv = [sys.executable, "-B", str(root / "tests/packaged/run.py"),
                        "--archive", str(archive), "--version", version, "--revision", initial["revision"],
                        "--target", toolchain["host"], "--output", str(output)]
                for flag, value in (("--owner-user", packaged_owner_user), ("--peer-user", packaged_peer_user)):
                    if value is not None:
                        argv.extend([flag, value])
                if packaged_allow_dirty:
                    argv.append("--allow-dirty")
                if coverage:
                    argv.extend(["--coverage-input", str(coverage_input)])
                result = executor(argv, cwd=root, env=run_env, timeout=300)
                entry.update(executed=True, output_sha256=digest(result.output), output_bytes=len(result.output),
                             cleanup_forced=result.cleanup_forced,
                             exit_code=result.returncode if result.returncode >= 0 else None,
                             signal=-result.returncode if result.returncode < 0 else None)
                if result.returncode != 0:
                    entry["diagnostic"] = PACKAGED_FAILURES.get(result.output, "unrecognized_packaged_failure")
                command_ok(result)
                require(output.is_file() and not output.is_symlink(), "missing_packaged_report")
                qualified = packaged_report(json_read(output), source=initial, target=toolchain["host"],
                                            version=version, archive_sha256=archive_hash)
                if coverage:
                    require(qualified.get("coverage", {}).get("input_sha256") == acceptance_coverage.digest(coverage_input),
                            "packaged_coverage_input_not_executed")
                else:
                    require("coverage" not in qualified, "unsolicited_packaged_coverage_claim")
                require(qualified["candidate_qualification"] != "local_candidate" or packaged_allow_dirty,
                        "packaged_dirty_candidate_not_allowed")
                with archive.open("rb") as stream:
                    require(hashlib.file_digest(stream, "sha256").hexdigest() == archive_hash, "packaged_archive_changed")
                entry.update(status="passed", reason=None, qualification=qualified)
            except (Invalid, OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
                entry.update(status="failed", reason=str(error) if isinstance(error, Invalid) else "packaged_execution_failed")
            entry["elapsed_ms"] = round((time.monotonic() - begin) * 1000)
            commands.append(entry)
    try:
        final = snapshot(root)
        if initial != final:
            gates.append("source_changed_during_run")
    except (Invalid, OSError, ValueError, UnicodeError):
        final = None
        gates.append("final_source_unavailable")
    requirement_results = []
    for requirement in manifest["requirements"]:
        if requirement["profile"] == "external":
            state = "not_selected_external"
        elif requirement["profile"] not in selected:
            state = "not_selected"
        elif sys.platform not in requirement.get("platforms", [sys.platform]):
            state = "not_selected_platform"
        elif requirement["status"] == "missing":
            state = "missing"
        elif gates:
            state = "blocked"
        elif requirement.get("runner") == "installed-artifacts":
            state = commands[0]["status"]
        elif all(results[name]["status"] == "passed" for name in requirement["tests"]):
            state = "passed"
        else:
            state = "failed"
        requirement_results.append({"id": requirement["id"], "profile": requirement["profile"],
                                    "status": state, "tests": requirement["tests"],
                                    **({"runner": requirement["runner"]} if "runner" in requirement else {})})
    selected_requirements = [r for r in requirement_results if r["profile"] in selected and r["status"] != "not_selected_platform"]
    passed = sum(r["status"] == "passed" for r in selected_requirements)
    return {"schema": "opaque.synthesized-suite-result.v1", "profile": profile,
            "scope": manifest["scope"], "status": "passed" if passed == len(selected_requirements) and not gates else "failed",
            "manifest_sha256": digest(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()),
            "source_before": initial, "source_after": final, "gates": gates,
            "model_profile_sha256": model_digest,
            "instrumented_acceptance_input_sha256": coverage["_input_sha256"] if coverage else None,
            "runtime": {"platform": sys.platform, "architecture": platform.machine(),
                        "effective_uid": os.geteuid(), "rustc": toolchain},
            "started_unix": started, "finished_unix": time.time(), "artifacts": artifacts,
            "tests": [{"id": case["id"], "target": case["target"], "name": case["name"], **results[case["id"]]} for case in tests],
            "commands": commands,
            "requirements": requirement_results,
            "counts": {"unique_tests_selected": len(tests),
                       "unique_tests_passed": sum(r["status"] == "passed" for r in results.values()),
                       "scenario_executions": sum(r["executed"] for r in results.values()),
                       "scenario_execution_scope": "exact test process invocations; finite model sequences reported separately",
                       "command_scenarios_selected": len(commands),
                       "command_scenarios_passed": sum(r["status"] == "passed" for r in commands),
                       "command_scenario_executions": sum(r["executed"] for r in commands),
                       "selected_requirements": len(selected_requirements), "selected_requirements_passed": passed,
                       "declared_software_requirements": sum(r["profile"] != "external" for r in requirement_results)},
            "coverage": {"scope": "selected requirements in this manifest only",
                         "overall_product": "not_measured", "line_percent": None, "branch_percent": None,
                         "native_human_qualification": "not_measured"}}


def write_reports(report, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not output.is_symlink() and not any(output.iterdir()), "output_directory_not_empty")
    root = ET.Element("testsuite", name="opaque." + report["profile"])
    failures = 0
    cases = []
    for test in report["tests"]:
        cases.append((test["id"], test["status"], test.get("reason"), test["elapsed_ms"] / 1000))
    for command in report.get("commands", []):
        cases.append(("command." + command["id"], command["status"], command.get("reason"), command["elapsed_ms"] / 1000))
    represented = {name for r in report["requirements"] if r["status"] in ("failed", "missing", "blocked") for name in r["tests"]}
    for requirement in report["requirements"]:
        if requirement["status"] in ("missing", "blocked") or (requirement["status"] == "failed" and not represented and "runner" not in requirement):
            cases.append(("requirement." + requirement["id"], "failed", requirement["status"], 0))
    for gate in report["gates"]:
        cases.append(("gate." + gate, "failed", gate, 0))
    for name, status, reason, elapsed in cases:
        case = ET.SubElement(root, "testcase", name=name, classname="declared-acceptance", time=str(elapsed))
        if status != "passed":
            failures += 1
            ET.SubElement(case, "failure", type=status, message=reason or status)
    root.set("tests", str(len(cases)))
    root.set("failures", str(failures))
    root.set("skipped", "0")
    payloads = {"report.json": json.dumps(report, indent=2, allow_nan=False).encode() + b"\n",
                "junit.xml": ET.tostring(root, encoding="utf-8", xml_declaration=True)}
    for name, payload in payloads.items():
        fd = os.open(output / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)


def safe_output(root, output):
    output = output.absolute()
    require(not output.exists(), "output_directory_exists")
    resolved = output.resolve()
    if resolved.is_relative_to(root.resolve()):
        relative = str(resolved.relative_to(root.resolve()) / "report.json")
        checked = invoke(git_command(root, "check-ignore", "-q", "--no-index", relative),
                         cwd=root, env=environment(), timeout=10)
        require(checked.returncode == 0 and checked.reason is None, "report_directory_must_be_ignored")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=(*SOFTWARE, "all"), default="protocol")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--model-profile", type=Path,
                        help="explicit profile produced by the owned real-model service harness; never inherited from the environment")
    parser.add_argument("--packaged-archive", type=Path, help="explicit trusted native archive for installed-artifacts acceptance")
    parser.add_argument("--packaged-owner-user", help="existing non-root Linux custody owner in a disposable runner")
    parser.add_argument("--packaged-peer-user", help="existing distinct non-root Linux peer in a disposable runner")
    parser.add_argument("--packaged-allow-dirty", action="store_true", help="local candidate only; never release qualification")
    parser.add_argument("--coverage-input", type=Path, help="explicit collector-built native acceptance input; never inherited")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    manifest = validate_manifest(json_read(args.manifest or root / "tests/synthesized-suite.json"))
    output = args.output or Path(tempfile.gettempdir()) / ("opaque-synthesized-" + os.urandom(8).hex())
    output = safe_output(root, output)
    target = (args.target_dir or Path(os.environ.get("CARGO_TARGET_DIR", str(root / "target")))).resolve()
    report = run_suite(manifest, root, args.profile, target, model_profile=args.model_profile,
                       packaged_archive=args.packaged_archive, packaged_owner_user=args.packaged_owner_user,
                       packaged_peer_user=args.packaged_peer_user, packaged_allow_dirty=args.packaged_allow_dirty,
                       coverage_input=args.coverage_input)
    write_reports(report, output)
    print(json.dumps({"status": report["status"], "profile": args.profile, "counts": report["counts"],
                      "overall_product_coverage": "not_measured", "report_directory": str(output)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    def interrupted(_signum, _frame):
        # Unwind invoke's finally block so an interrupted runner does not leave
        # its real daemons or other children in a separate process group.
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Acceptance runner interrupted; no successful coverage claim was produced.", file=sys.stderr)
        sys.exit(130)
    except (Invalid, OSError, ValueError, TypeError, KeyError, UnicodeError):
        print("Acceptance runner failed; no successful coverage claim was produced.", file=sys.stderr)
        sys.exit(1)
