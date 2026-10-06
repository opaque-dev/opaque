#!/usr/bin/env python3
"""Collect production counters across every Cargo workspace package.

Each invocation qualifies one native platform. Linux additionally requires root
and CAP_SYS_PTRACE for the existing split-UID composed-review tests. This runs no
native approval UI or live vendor account. Profiles must be fresh and objects explicitly inventoried;
never combine platform reports or reinterpret a passing test as measured coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import tomllib

import check_llvm_coverage as gate
from rust_coverage_scope import ScopeError, runtime_sources
import synthesized_suite as suite
import acceptance_coverage as acceptance

TOOLCHAIN = "nightly-2026-09-13"
COLLECTOR_VERSION = "0.9.1"
ORIGINAL_PACKAGES = ("opaque-core", "opaque-bounded-work", "opaque-approval")
BASE_FLAGS = ("-C", "instrument-coverage", "--cfg=coverage", "--cfg=coverage_nightly")
BUILD_PROFILE_ENV = {"CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0"}
CACHE_BINDING = ".opaque-coverage-workspace.json"
CACHE_SCHEMA = "opaque.coverage-workspace-cache.v1"
CACHE_TAG_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"


def instrumentation_flags(native_platform, page_size):
    require(native_platform in ("linux", "darwin"), "unsupported_native_platform")
    # DWARF makes the test peer executable artificially large for the daemon's
    # real, fresh executable hash. LLVM source/branch maps and counters are
    # independent of DWARF. Apply the same setting to Cargo and bare-rustc peers.
    flags = [*BASE_FLAGS, "-Zcoverage-options=branch", "-Cdebuginfo=0"]
    if native_platform == "linux":
        flags.append("-Cllvm-args=-runtime-counter-relocation")
    else:
        require(type(page_size) is int and page_size > 0 and page_size & (page_size - 1) == 0,
                "invalid_native_page_size")
        for section in ("cnts", "data", "bits"):
            flags.append(f"-Clink-arg=-Wl,-sectalign,__DATA,__llvm_prf_{section},{page_size:x}")
    return flags
ORIGINAL_REQUIRED_FILES = (
    "crates/opaque-bounded-work/src/task_store.rs",
    "crates/opaque-bounded-work/src/task_api.rs",
    "crates/opaque-bounded-work/src/resource_authority.rs",
    "crates/opaque-core/src/task.rs",
    "crates/opaque-core/src/identity_lifecycle.rs",
    "crates/opaque-approval/src/approval_server/workstation.rs",
)
REQUIRED_FILES = (*ORIGINAL_REQUIRED_FILES,
                  "crates/opaque-providers/src/github/client.rs",
                  "crates/opaque-native-approval/src/lib.rs",
                  "crates/opaque-web/src/lib.rs")
CASES = {
    "task_api_e2e": (
        "task_plan_run_get_list_revoke_end_to_end",
        "ssh_planning_without_tenant_is_denied_before_provider_io",
        "task_rpc_rechecks_changed_workspace_after_source_read_without_publishing",
    ),
    "resource_authority_e2e": ("broker_identity_is_live_for_gateway_queries_disclosures_and_logout",),
    "mcp_gateway_e2e": (
        "adapter_signed_tool_daemon_effect_receipt_and_replay_survive_restart",
        "policy_denial_malformed_input_and_generic_bypass_make_no_http_calls",
        "revoke_during_handshake_stops_final_tool_dispatch_and_does_not_refund",
        "daemon_death_after_effect_recovers_unknown_and_never_replays",
        "expiry_during_handshake_prevents_tool_effect_and_preserves_charge",
        "projected_result_is_useful_bounded_ephemeral_and_never_replays",
        "revoked_after_provider_effect_withholds_projected_result_without_refund",
    ),
    "opaqued": (
        "resource_authority_provisioning_tests::signed_resource_tokens_need_exact_live_provisioning_scopes_despite_operator_role",
        "resource_authority_provisioning_tests::access_and_token_self_revocation_remain_denied_across_restart_and_new_grants",
        "enclave::task::remote_tests::signed_remote_receipt_drives_real_bounded_effects_once_and_survives_restart",
        "enclave::task::remote_tests::requester_reviewer_and_device_revocation_at_real_dispatch_fence_block_all_effects",
        "provisioning_api_tests::native_denial_never_produces_a_binding_or_mandate_challenge",
        "provisioning_api_tests::reviewed_challenges_are_random_peer_bound_signed_and_single_use",
        "provisioning_api_tests::only_the_authenticated_mandate_service_can_issue_for_a_verified_recipient",
        "provisioning_api_tests::request_reuse_and_issuer_role_removal_cannot_extend_a_mandate",
        "identity::lifecycle::tests::removal_regrant_revokes_old_sessions_and_reviewer_epoch",
        "identity::lifecycle::tests::dispatch_writer_fence_serializes_removal",
        "identity::lifecycle::tests::restart_retains_source_revision_and_current_authority",
        "identity::lifecycle::tests::mock_oidc_lifecycle_change_cancels_pending_login_and_fresh_login_succeeds",
    ),
    "synthesized_review_e2e": (
        "synthesized_oidc_review_receipt_and_restart_preserve_authority",
        "synthesized_signed_rejection_leaves_task_uncharged",
        "synthesized_review_timeout_rejects_late_signature_without_effects",
        "synthesized_lifecycle_regrant_during_preparation_keeps_signed_task_charged_and_denied",
    ),
}
CONTAINED_TARGET = "contained_ssh_e2e"
CONTAINED_CASES = (
    "contained_signed_ssh_runs_one_probe_and_rejects_replay_after_restart",
    "contained_guard_crash_preserves_unknown_and_kills_probe_without_replay",
    "contained_inference_rpc_rechecks_authority_after_metadata_without_refunding",
    "contained_ssh_rpc_rejects_absent_and_disabled_principals_without_effects",
    "contained_ssh_rpc_rejects_foreign_tenant_and_broker_bindings_without_effects",
    "contained_ssh_revoke_during_probe_preserves_charge_and_stops_observed_processes",
)
# These exclusions match existing explicitly ignored tests, not missing jobs.
ROOT_CASE = "trust_domain::tests::root_multi_uid_custody_matrix"
DAEMON_ROOT_CASE = "trust_domain::tests::root_enforce_blocks_foreign_custody_then_privileges_drop"
IGNORED_PREREQUISITES = {
    ("opaque-core", "opaque_core", ROOT_CASE): "explicit Linux root custody matrix",
    ("opaqued", "opaqued", DAEMON_ROOT_CASE): "explicit Linux root isolation with irreversible child UID drop",
    ("opaque-bounded-work", "opaque_bounded_work", "ssh::tests::live_vault_host_execution"): "private disposable live Vault/SSH service; separate explicit opt-in",
    ("opaque-bounded-work", "opaque_bounded_work", "task_store::tests::task_pagination_scales"): "explicit 1k/100k receipt scalability measurement",
    ("opaque-web", "opaque_web", "sse::tests::audit_backlog_load_baseline"): "explicit long-running SSE load baseline",
    ("opaque-federation-runtime", "opaque_federation_runtime", "workload_attest::tests::live_signed_and_adhoc_child_socket_attestation"): "explicit signed/unsigned Node binaries and expected macOS Team ID",
}
for _name in ("onepassword::op_cli::tests::live_list_vaults", "onepassword::op_cli::tests::live_list_items",
              "onepassword::op_cli::tests::live_read_field"):
    IGNORED_PREREQUISITES[("opaque-providers", "opaque_providers", _name)] = "authenticated 1Password desktop session; separate explicit opt-in"
for _name, _reason in (
    ("bitwarden::client::tests::live_machine_authentication_and_secret_decryption", "official bws and disposable live Bitwarden account"),
    ("aws::client::tests::live_aws_read_only_identity_and_selected_resources", "explicit live AWS read opt-in, region, account and credential references"),
    ("vault::resolve::snapshot_tests::live_dynamic_fields_share_one_real_lease", "explicit disposable live Vault database role"),
):
    IGNORED_PREREQUISITES[("opaque-providers", "opaque_providers", _name)] = _reason
for _name in CASES["synthesized_review_e2e"]:
    IGNORED_PREREQUISITES[("opaqued", "synthesized_review_e2e", _name)] = "explicit Linux root signed-review composition"
for _name in CONTAINED_CASES:
    IGNORED_PREREQUISITES[("opaqued", CONTAINED_TARGET, _name)] = "explicit marked Vault/OpenSSH/systemd host with Linux root and SYS_PTRACE"
IGNORED_PREREQUISITES[("opaqued", CONTAINED_TARGET, "contained_real_model_completions_require_signed_review_and_survive_restart")] = "owned pinned real-model service profile; separate explicit opt-in"
for _name in ("split_daemon_custody_and_signature_bound_approver", "split_daemon_refuses_stolen_custody"):
    IGNORED_PREREQUISITES[("opaqued", "trust_domain_e2e", _name)] = "explicit marked Linux root host for split-UID daemon custody"
ALLOWED_IGNORED = {name for _package, _target, name in IGNORED_PREREQUISITES}
SCHEMA = "opaque.workspace-coverage-collection.v2"
LIBRARY_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}
ZERO_COUNTER_DIAGNOSTIC = b"LLVM Profile Error: Neither __llvm_profile_counter_bias nor __llvm_profile_bitmap_bias is defined"


def target_kind(kinds):
    require(isinstance(kinds, list) and kinds, "invalid_cargo_target_kind")
    if set(kinds) <= LIBRARY_KINDS:
        return "lib"
    require(len(kinds) == 1, "ambiguous_cargo_target_kind")
    return kinds[0]


def workspace_inventory(metadata, root):
    """Cargo workspace_members is authoritative; default-members is not scope."""
    require(Path(metadata.get("workspace_root", "")).resolve() == root, "metadata_workspace_root_mismatch")
    members = metadata.get("workspace_members")
    require(isinstance(members, list) and members and len(members) == len(set(members)), "invalid_workspace_members")
    descriptions = metadata.get("packages")
    require(isinstance(descriptions, list), "missing_workspace_package_metadata")
    by_id = {item["id"]: item for item in descriptions}
    require(len(by_id) == len(descriptions) and set(members) <= set(by_id), "missing_or_duplicate_workspace_package")
    packages = []
    for identity in members:
        item = by_id[identity]
        manifest = Path(item["manifest_path"])
        require(manifest.is_absolute() and manifest.is_file() and not manifest.is_symlink()
                and manifest.resolve().is_relative_to(root), "invalid_workspace_manifest")
        name = tomllib.loads(manifest.read_text())["package"]["name"]
        require(name == item["name"], "workspace_package_name_mismatch")
        features = item.get("features")
        require(isinstance(features, dict), "invalid_workspace_features")
        targets = []
        for target in item["targets"]:
            kind = target_kind(target["kind"])
            source = Path(target["src_path"])
            require(source.is_absolute() and source.is_file() and not source.is_symlink()
                    and source.resolve().is_relative_to(root), "invalid_workspace_target_source")
            required = target.get("required-features", [])
            require(isinstance(required, list) and set(required) <= set(features), "undeclared_required_target_features")
            targets.append({"name": target["name"], "kind": kind, "source": source.relative_to(root).as_posix(),
                            "test": bool(target.get("test", False)), "required_features": sorted(required),
                            "eligible": kind in ("lib", "bin", "test"),
                            "eligibility": "all_features_native_compiler" if kind in ("lib", "bin", "test")
                                           else "not_a_runtime_library_binary_or_integration_test"})
        require(targets and len({(t["name"], t["kind"]) for t in targets}) == len(targets), "duplicate_or_missing_workspace_target")
        packages.append({"id": identity, "name": name, "manifest": manifest.relative_to(root).as_posix(),
                         "features": sorted(features), "targets": targets})
    require(len({p["name"] for p in packages}) == len(packages), "duplicate_workspace_package_name")
    return sorted(packages, key=lambda p: p["name"])


def expected_artifacts(workspace, *, tests):
    return {(p["name"], t["name"], t["kind"], tests) for p in workspace for t in p["targets"]
            if t["eligible"] and (t["test"] if tests else t["kind"] == "bin")}


def validate_workspace_artifacts(workspace, selected, *, tests):
    expected = expected_artifacts(workspace, tests=tests)
    missing = expected - set(selected)
    require(not missing, "missing_workspace_" + ("test" if tests else "binary") + "_artifacts:"
            + ",".join(f"{p}/{name}/{kind}" for p, name, kind, _ in sorted(missing)))
    require(bool(expected), "workspace_has_no_eligible_" + ("test_targets" if tests else "binaries"))
    return sorted(expected)


def test_inventory(raw):
    """Zero tests are observed inventory, never a successful test execution."""
    if raw.strip() in (b"0 tests, 0 benchmarks", ZERO_COUNTER_DIAGNOSTIC + b"\n0 tests, 0 benchmarks"):
        return set()
    counter_diagnostics(raw)
    return suite.inventory(raw)


def counter_diagnostics(raw, *, zero_tests=False):
    errors = [line for line in raw.splitlines() if b"LLVM Profile Error:" in line]
    require(not errors or (zero_tests and errors == [ZERO_COUNTER_DIAGNOSTIC]),
            "unexpected_llvm_profile_error")
    return ["no_continuous_counters_in_zero_test_harness"] if errors else []


def reviewed_ignored_tests(package, target, ignored):
    unknown = {name for name in ignored if (package, target, name) not in IGNORED_PREREQUISITES}
    require(not unknown, "unreviewed_ignored_workspace_tests:" + package + "/" + target + ":" + ",".join(sorted(unknown)))
    return {name: IGNORED_PREREQUISITES[(package, target, name)] for name in ignored}


def test_execution_counts(executions, targets, skipped):
    unique = set()
    invocations = 0
    for entry in executions:
        require(len(entry["passed_test_names"]) == entry["passed"], "inconsistent_execution_test_count")
        invocations += entry["passed"]
        unique.update((entry["package"], entry["target"], entry["kind"], name) for name in entry["passed_test_names"])
    return {"compiled_tests_on_native_target": sum(t["compiled_tests"] for t in targets),
            "non_ignored_compiled_tests": sum(t["non_ignored_tests"] for t in targets),
            "unique_passed_tests": len(unique), "passed_test_invocations": invocations,
            "repeated_pass_invocations": invocations - len(unique), "test_process_invocations": len(executions),
            "zero_test_process_invocations": sum(e["qualification"] == "no_tests_executed" for e in executions),
            "ignored_tests_not_executed": sum(not s["executed_by_explicit_profile"] for s in skipped),
            "scope": "unique identities include package, target kind, target name and test name; model transitions are not additional tests"}


def require(condition, reason):
    if not condition:
        raise suite.Invalid(reason)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def command_failure_metadata(label, log, *, classification, returncode=None, error_number=None,
                             root, test_context=None):
    """Allowlist failure metadata; never publish captured output or arguments."""
    result = {"command": label if re.fullmatch(r"[A-Za-z0-9_:-]{1,200}", label) else "unrecognized",
              "classification": classification, "exit_code": returncode if returncode is not None and returncode >= 0 else None,
              "signal": -returncode if returncode is not None and returncode < 0 else None,
              "os_error_number": error_number,
              "private_log": log.name if re.fullmatch(r"command-[0-9]{3,8}\.log", log.name) else "unrecognized",
              "output_scope": "metadata only; raw output remains in the private command log"}
    known = set()
    if test_context is not None:
        package, target, requested, inventory = test_context
        identity = r"[A-Za-z0-9_][A-Za-z0-9_:-]{0,199}"
        require(re.fullmatch(identity, package) and re.fullmatch(identity, target), "invalid_failure_test_identity")
        known = {name for name in inventory if isinstance(name, str) and re.fullmatch(identity, name)}
        require(requested is None or requested in known, "invalid_failure_requested_test")
        result["test_context"] = {"package": package, "target": target, "requested_test": requested}
    if not log.is_file() or log.is_symlink():
        return result
    # Only parse bounded first/last windows, even for a runaway diagnostic.
    limit = 65536
    with log.open("rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        raw = stream.read(limit)
        if size > limit:
            stream.seek(max(limit, size - limit))
            raw += b"\n" + stream.read(limit)
    text = raw.decode("utf-8", errors="replace")
    failed = set(re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. FAILED$", text, re.MULTILINE)) & known
    result["failed_tests"] = sorted(failed)[:100]
    result["failed_tests_truncated"] = len(failed) > 100
    result["diagnostic_window_truncated"] = size > limit * 2
    result["observed_libtest_summaries"] = [
        {"result": status, "passed": int(passed), "failed": int(failed_count), "ignored": int(ignored)}
        for status, passed, failed_count, ignored in re.findall(
            r"^test result: (ok|FAILED)\. ([0-9]{1,7}) passed; ([0-9]{1,7}) failed; ([0-9]{1,7}) ignored;", text, re.MULTILINE)[:8]]
    indicators = []
    if re.search(r"^assertion(?: `[^`\n]{1,80}`)? failed", text, re.MULTILINE):
        indicators.append("assertion_failed")
    for pattern, indicator in (
        (r"^fatal: detected dubious ownership in repository at ", "git_checkout_ownership_rejected"),
        (r"^ValueError: release source must be clean;", "release_source_dirty"),
        (r"^ValueError: expected revision does not match source HEAD$", "release_revision_mismatch"),
        (r"^ValueError: unsupported target or invalid version$", "unsupported_release_identity"),
        (r"^.+: error: all eight regular compiled tool files are required$", "missing_regular_compiled_tools"),
    ):
        if re.search(pattern, text, re.MULTILINE):
            indicators.append(indicator)
    result["failure_indicators"] = indicators
    result["observed_os_error_numbers"] = sorted({int(code) for code in re.findall(r"\(os error ([0-9]{1,3})\)", text)})
    locations = []
    for name, file, line, column in re.findall(
            r"^thread '([A-Za-z0-9_:]+)'(?: \([0-9]+\))? panicked at ([^\n]+):([0-9]{1,7}):([0-9]{1,7}):$", text, re.MULTILINE):
        if name not in known or not re.fullmatch(r"[A-Za-z0-9_./-]+\.rs", file):
            continue
        path = Path(file)
        if not path.is_absolute():
            path = root / path
        try:
            relative = path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError):
            continue
        if not path.is_file() or line == "0" or column == "0":
            continue
        location = {"test": name, "source": relative.as_posix(), "line": int(line), "column": int(column)}
        if location not in locations:
            locations.append(location)
    result["panic_locations"] = locations[:32]
    result["panic_locations_truncated"] = len(locations) > 32
    result["python_exception_classes"] = sorted(set(re.findall(
        r"^(?:subprocess\.)?(ValueError|RuntimeError|FileNotFoundError|PermissionError|CalledProcessError|TimeoutExpired|OSError|Invalid):", text, re.MULTILINE)))
    python_locations = []
    for file, line in re.findall(r'^  File "([^"\n]+)", line ([0-9]{1,7}), in [A-Za-z0-9_<>]+$', text, re.MULTILINE):
        if not re.fullmatch(r"[A-Za-z0-9_./-]+\.py", file):
            continue
        path = Path(file)
        if not path.is_absolute():
            path = root / path
        try:
            relative = path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError):
            continue
        if path.is_file() and line != "0":
            location = {"source": relative.as_posix(), "line": int(line)}
            if location not in python_locations:
                python_locations.append(location)
    result["python_locations"] = python_locations[:32]
    result["python_locations_truncated"] = len(python_locations) > 32
    return result


def fresh_directory(path, mode=0o711):
    path.mkdir(mode=mode, parents=False, exist_ok=False)
    path.chmod(mode)
    return path.resolve()


def parse_environment(raw, flags):
    """Read pinned show-env output as assignments, never evaluate shell code."""
    values = {}
    for line in raw.decode().splitlines():
        match = re.fullmatch(r"([A-Z_][A-Z0-9_]*)=(.*)", line)
        require(match is not None, "invalid_collector_environment")
        key, value = match.groups()
        require(key not in values, "duplicate_collector_environment")
        parsed = shlex.split(value)
        require(len(parsed) == 1, "invalid_collector_environment_value")
        values[key] = parsed[0]
    require(values.get("__CARGO_LLVM_COV_RUSTC_WRAPPER") == "1"
            and values.get("CARGO_LLVM_COV") == "1"
            and bool(values.get("RUSTC_WRAPPER")), "missing_instrumentation_wrapper")
    encoded = values.get("__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS", "")
    require(encoded.split("\x1f") == list(BASE_FLAGS), "unexpected_instrumentation_flags")
    values["__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS"] = "\x1f".join(flags)
    return values


def selected_cases(native_platform, contained=False):
    require(native_platform in ("linux", "darwin"), "unsupported_native_platform")
    selected = {target: names for target, names in CASES.items()
                if native_platform == "linux" or target != "synthesized_review_e2e"}
    if native_platform == "linux":
        selected["opaqued"] = (*selected["opaqued"], DAEMON_ROOT_CASE)
    if contained:
        require(native_platform == "linux", "contained_profile_requires_linux")
        selected[CONTAINED_TARGET] = CONTAINED_CASES
        selected["trust_domain_e2e"] = ("split_daemon_custody_and_signature_bound_approver", "split_daemon_refuses_stolen_custody")
    return selected


def contained_prerequisites(native_platform, *, marker=Path("/etc/opaque-contained-fixture"),
                            pid1=Path("/proc/1/comm")):
    require(native_platform == "linux" and os.geteuid() == 0 and suite.has_sys_ptrace(),
            "contained_profile_requires_linux_root_and_sys_ptrace")
    require(marker.read_bytes() == b"opaque-contained-ssh-v1\n" and pid1.read_text().strip() == "systemd",
            "contained_profile_requires_marked_systemd_host")
    require(pwd.getpwnam("opaque").pw_uid == 7382, "contained_profile_requires_host_account")
    for tool in ("vault", "systemctl", "ssh-keygen", "python3", "getent", "setpriv", "useradd", "userdel", "groupadd", "groupdel"):
        require(shutil.which(tool) is not None, "contained_profile_missing_tool_" + tool)
    return {"systemd_pid1": True, "host_uid": 7382, "marker": "opaque-contained-ssh-v1",
            "scope": "disposable actual Vault/OpenSSH/systemd host with synthetic signed review; no native human claim"}


def artifacts(raw, target_dir, *, qualified=False):
    result = {}
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(event, dict) or event.get("reason") != "compiler-artifact" or not event.get("executable"):
            continue
        path = Path(event["executable"])
        require(path.is_absolute() and path.is_file() and not path.is_symlink()
                and path.resolve().is_relative_to(target_dir), "invalid_compiler_artifact")
        target = event.get("target", {})
        kind = target_kind(target.get("kind"))
        key = (target.get("name"), kind, event.get("profile", {}).get("test"))
        if qualified:
            require(isinstance(event.get("package_id"), str) and event["package_id"], "missing_compiler_package_id")
            key = (event["package_id"], *key)
        require(key not in result or result[key] == path, "duplicate_compiler_target")
        result[key] = path
    require(bool(result), "empty_compiler_artifacts")
    return result


def artifact_packages(raw, selected, root, workspace=None):
    """Restore Cargo's runtime package name from each exact compiled manifest."""
    contexts = {}
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(event, dict) or event.get("reason") != "compiler-artifact" or not event.get("executable"):
            continue
        binary = Path(event["executable"])
        if binary not in selected:
            continue
        manifest = Path(event.get("manifest_path", ""))
        require(manifest.is_absolute() and manifest.is_file() and not manifest.is_symlink()
                and manifest.resolve().is_relative_to(root), "invalid_artifact_package_manifest")
        package = tomllib.loads(manifest.read_text())["package"]["name"]
        if workspace is not None:
            registered = {p["id"]: p for p in workspace}
            require(event.get("package_id") in registered, "artifact_not_a_workspace_member")
            expected = registered[event["package_id"]]
            require(package == expected["name"] and manifest.relative_to(root).as_posix() == expected["manifest"],
                    "artifact_workspace_package_mismatch")
        require(binary not in contexts or contexts[binary] == package, "ambiguous_artifact_package")
        contexts[binary] = package
    require(set(contexts) == set(selected), "missing_artifact_package_identity")
    return contexts


def suite_pass(raw, names, *, allowed_ignored=None, allow_empty=False):
    text = raw.decode()
    found = re.findall(r"^test (.+?) \.\.\. (ok|FAILED|ignored(?:, .*)?)$", text, re.MULTILINE)
    require(len(found) == len(names) and {name for name, _ in found} == names,
            "missing_or_duplicate_suite_results")
    ignored = {name for name, status in found if status.startswith("ignored")}
    allowed = ALLOWED_IGNORED if allowed_ignored is None else allowed_ignored
    require(ignored <= allowed and all(status == "ok" or name in ignored for name, status in found),
            "failed_or_unexpected_ignored_test")
    summary = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text, re.MULTILINE)
    require(summary == [("ok", str(len(names) - len(ignored)), "0", str(len(ignored)), "0", "0")]
            and (len(names) > len(ignored) or allow_empty), "vacuous_or_incomplete_suite_result")
    return {"passed": len(names) - len(ignored), "ignored": sorted(ignored)}


def validate_case_inventory(expected, inventories):
    require(bool(expected), "empty_declared_case_selection")
    for target, names in expected.items():
        require(names and len(names) == len(set(names)), "empty_or_duplicate_declared_cases")
        require(target in inventories and bool(inventories[target]), "missing_declared_target_inventory")
        missing = set(names) - inventories[target]
        require(not missing, "required_named_test_not_found:" + target + ":" + ",".join(sorted(missing)))
    return {target: {"compiled_tests": len(inventories[target]), "selected_tests": list(names)}
            for target, names in expected.items()}


def role_requirements(target, name):
    if target == "task_api_e2e" and name == "task_rpc_rechecks_changed_workspace_after_source_read_without_publishing":
        return {"test", "daemon", "peer"}
    if target in ("synthesized_review_e2e", CONTAINED_TARGET):
        # Ordinary baseline execution runs only the shared OIDC helper tests;
        # the daemon/peer ceremonies are ignored until selected by exact name.
        return {"test"} if name is None else {"test", "daemon", "peer"}
    if target == "mcp_gateway_e2e":
        roles = {"test", "daemon"}
        if name in (CASES[target][0], CASES[target][5]):
            roles.add("adapter")
        return roles
    if target in ("task_api_e2e", "resource_authority_e2e", "trust_domain_e2e"):
        return {"test", "daemon"}
    return {"test"}


def profile_inventory(directory, target, name=None):
    profiles = sorted(directory.glob("*.profraw"))
    require(bool(profiles), "no_execution_profiles")
    entries = []
    roles = set()
    for path in profiles:
        require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                "empty_or_invalid_execution_profile")
        role = path.name.split("-", 1)[0]
        require(role in {"test", "daemon", "adapter", "peer"}, "unknown_execution_profile_role")
        process = re.match(r"^[a-z]+-([1-9][0-9]*)-", path.name)
        require(process is not None, "missing_profile_process_identity")
        roles.add(role)
        entries.append({"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size,
                        "role": role, "process_id": int(process[1])})
    require(role_requirements(target, name) <= roles, "missing_required_child_profiles")
    peers = sorted(directory.glob("peer-binary-*"))
    require("peer" not in role_requirements(target, name) or bool(peers), "missing_instrumented_peer_object")
    require(all(p.is_file() and not p.is_symlink() and p.stat().st_size for p in peers),
            "invalid_instrumented_peer_object")
    return entries, peers


def source_inventory(root, workspace):
    inventory = []
    seen = set()
    member_roots = {(root / p["manifest"]).parent for p in workspace}
    for package in workspace:
        production = [t for t in package["targets"] if t["kind"] in ("lib", "bin") and t["eligible"]]
        directory = (root / package["manifest"]).parent
        files = set()
        roots = {(root / target["source"]).parent for target in production}
        if production:
            for path in directory.rglob("*.rs"):
                relative = path.relative_to(directory)
                if path.name == "build.rs" or relative.parts[0] == "target":
                    continue
                if any(other != directory and other.is_relative_to(directory) and path.is_relative_to(other)
                       for other in member_roots):
                    continue
                # Integration/benchmark/example harnesses are not runtime
                # source. Explicit Cargo runtime targets in such a location
                # still win; nested src/tests modules remain inventoried and
                # their reviewed coverage(off) annotations suppress counters.
                if relative.parts[0] in {"tests", "examples", "benches"} and not any(
                        runtime != directory and path.is_relative_to(runtime) for runtime in roots):
                    continue
                files.add(path)
        require(not production or bool(files), "empty_declared_source_package")
        require(all(root / target["source"] in files for target in production), "workspace_runtime_entrypoint_missing_from_scope")
        for path in sorted(files):
            require(not path.is_symlink(), "symlink_in_declared_source_scope")
            require(path not in seen, "overlapping_workspace_production_source")
            seen.add(path)
            inventory.append({"package": package["name"], "path": str(path.relative_to(root)), "sha256": sha(path)})
    by_path = {item["path"]: item for item in inventory}
    for package in workspace:
        entries = [t["source"] for t in package["targets"] if t["kind"] in ("lib", "bin") and t["eligible"]]
        try:
            graph = runtime_sources(root, entries)
        except ScopeError as error:
            raise suite.Invalid("invalid_workspace_runtime_source_graph:" + str(error)) from error
        for name in sorted(graph["sources"]):
            entry = by_path.setdefault(name, {"package": package["name"], "path": name, "sha256": sha(root / name)})
            owners = set(entry.get("packages", [entry["package"]])) | {package["name"]}
            entry["packages"] = sorted(owners)
            if not (root / name).is_relative_to((root / package["manifest"]).parent):
                entry["shared_runtime_source"] = True
                if name in graph["required"]:
                    entry["required_native_mapping"] = True
    inventory = sorted(by_path.values(), key=lambda item: item["path"])
    require(set(REQUIRED_FILES) <= {item["path"] for item in inventory}, "required_source_not_in_inventory")
    return inventory


def unfiltered_runtime_mappings(report, sources, workspace, root, target):
    """Audit native mappings before filename filtering can hide a source."""
    declared = {item["path"] for item in sources}
    measured, seen = {}, {}
    harness_roots = {(root / p["manifest"]).parent / kind for p in workspace for kind in ("tests", "examples", "benches")}
    harness_entries = {root / t["source"] for p in workspace for t in p["targets"] if t["kind"] not in ("lib", "bin")}
    for item in report.get("data", [{}])[0].get("files", []):
        path = Path(item["filename"])
        path = (path if path.is_absolute() else root / path).resolve()
        require(path not in seen or seen[path] == item["filename"], "unsupported_compiler_source_alias:" + str(path))
        require(path not in seen, "duplicate_unfiltered_mapping_source")
        seen[path] = item["filename"]
        if not path.is_relative_to(root):
            continue  # Registry, toolchain and temporary test-peer source.
        name = path.relative_to(root).as_posix()
        if name in declared:
            # LLVM can retain a literal #[path] spelling with ../ segments.
            # Canonical paths identify ownership, but do not necessarily match
            # LLVM's --sources selector. Retain its exact emitted spelling
            # for an anchored include-filename-regex, which does not realpath it.
            measured[name] = item["filename"]
        elif path.is_relative_to(target) or path in harness_entries or any(path.is_relative_to(p) for p in harness_roots):
            continue  # Exact Cargo harness scope; never included in production totals.
        else:
            raise suite.Invalid("uninventoried_workspace_runtime_mapping:" + name)
    require(bool(measured), "no_unfiltered_workspace_runtime_mappings")
    return measured


def validate_report_scope(report, sources, root, expected_mappings=None):
    files = report.get("data", [{}])[0].get("files", [])
    declared = {item["path"] for item in sources}
    measured = set()
    for item in files:
        path = Path(item["filename"]).resolve().relative_to(root).as_posix()
        require(path in declared and path not in measured, "undeclared_or_duplicate_report_source")
        measured.add(path)
    require(set(REQUIRED_FILES) <= measured, "required_source_missing_from_collection")
    require({item["path"] for item in sources if item.get("required_native_mapping")} <= measured,
            "required_shared_runtime_source_missing_from_collection")
    require(expected_mappings is None or measured == set(expected_mappings), "filtered_report_dropped_native_runtime_mapping")
    return sorted(declared - measured)


def package_report_subset(report, packages, root):
    """Select source rows from a validated export and rebuild their own totals.

    LLVM's expanded totals must not qualify a narrower comparison scope. The
    caller validates the complete export first; this keeps the original scope
    comparable while preserving all omitted-package deficits in the main gate.
    """
    require(bool(packages) and len(packages) == len(set(packages))
            and set(packages) <= set(ORIGINAL_PACKAGES), "invalid_report_subset_packages")
    roots = [root / "crates" / package / "src" for package in packages]
    files = [item for item in report["data"][0]["files"]
             if any(Path(item["filename"]).resolve().is_relative_to(directory) for directory in roots)]
    require(bool(files), "empty_report_package_subset")
    totals = {metric: {key: sum(item["summary"][metric][key] for item in files)
                       for key in ("count", "covered")}
              for metric in ("lines", "branches")}
    return {"type": report["type"], "data": [{"files": files, "totals": totals}]}


def workspace_package_coverage(report, sources, workspace, root):
    owners = {item["path"]: item.get("packages", [item["package"]]) for item in sources}
    measured = {p["name"]: [] for p in workspace}
    for item in report["data"][0]["files"]:
        name = Path(item["filename"]).resolve().relative_to(root).as_posix()
        require(name in owners, "undeclared_report_source")
        for owner in owners[name]:
            measured[owner].append(item)
    rows = []
    for package in workspace:
        files = measured[package["name"]]
        production = [t for t in package["targets"] if t["kind"] in ("lib", "bin") and t["eligible"]]
        counts = {metric: {key: sum(f["summary"][metric][key] for f in files) for key in ("count", "covered")}
                  for metric in ("lines", "branches")}
        status = "measured" if counts["lines"]["count"] > 0 else "unqualified_zero_native_mapping" if production else "no_runtime_targets"
        rows.append({"package": package["name"], "manifest": package["manifest"], "status": status,
                     "mapped_files": len(files), "measured": counts,
                     "shared_source_files": sorted(name for name, names in owners.items() if len(names) > 1 and package["name"] in names),
                     "reason": ("No executable mapping was emitted for this package on this native target; "
                                "compiled-out or zero-line code is not qualified by another platform.")
                               if status == "unqualified_zero_native_mapping" else None})
    return rows


def stop_process(process):
    try:
        return suite.stop_group(process)
    except PermissionError:
        # Retain the failure instead of declaring uncertain descendant cleanup
        # successful. Always reap our direct child even if the OS denies the
        # process-group probe during exit.
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        raise suite.Invalid("process_group_cleanup_denied") from None


class Collector:
    def __init__(self, root, output, target, collector, jobs=4, contained=False, *, acceptances=(),
                 acceptance_only=False, acceptance_allow_dirty=False, browser_cache=None):
        self.root, self.output, self.target = root, output, target
        self.collector = collector
        self.contained = contained
        require(len(acceptances) == len(set(acceptances)) and set(acceptances) <= acceptance.PURPOSES,
                "invalid_acceptance_selection")
        require(not acceptance_only or bool(acceptances), "acceptance_only_requires_selection")
        require(not ({"model", "service"} & set(acceptances)) or (contained and sys.platform == "linux"), "model_or_service_coverage_requires_contained_linux")
        self.acceptances = tuple(acceptances)
        self.acceptance_only = acceptance_only
        self.acceptance_allow_dirty = acceptance_allow_dirty
        self.browser_cache = browser_cache
        self.cases = selected_cases(sys.platform, contained)
        self.flags = instrumentation_flags(sys.platform, os.sysconf("SC_PAGE_SIZE"))
        self.env = suite.environment()
        self.env.update({"RUSTUP_TOOLCHAIN": TOOLCHAIN, "CARGO_TARGET_DIR": str(target),
                         "CARGO_BUILD_JOBS": str(jobs), **BUILD_PROFILE_ENV})
        self.commands = 0
        self.last_command_pid = None
        self.package_by_binary = {}
        self.test_kind_by_binary = {}
        self.workspace = []
        self.test_inventories = {}
        self.declared_inventory_validated = False
        self.result = {"schema": SCHEMA, "status": "collecting", "platform": sys.platform,
                       "machine": platform.machine(), "coverage_packages": [],
                       "test_collection_packages": [], "workspace_packages": [],
                       "instrumentation": self.flags, "toolchain": TOOLCHAIN,
                       "debug_symbol_settings": {"cargo_profile_environment": dict(BUILD_PROFILE_ENV),
                                                 "rustc_flag": "-Cdebuginfo=0",
                                                 "scope": "DWARF omitted at build; LLVM source/branch maps and counters retained; no post-build stripping"},
                       "collector_version": COLLECTOR_VERSION, "executions": [], "profiles": [], "acceptance_executions": [],
                       "binaries": [], "failures": [], "failed_commands": [], "test_targets": [], "skipped_tests": [],
                       "not_qualified": ["live vendor accounts", "real model completions", "native human approval",
                                         "contained Vault/OpenSSH/systemd service", "other native platforms"]}

    def command(self, label, argv, env=None, timeout=1800, export=None, test_context=None):
        print(f"coverage: {label}", flush=True)
        self.commands += 1
        log = self.output / f"command-{self.commands:03d}.log"
        def failed(classification, process=None, error=None):
            self.result["failed_commands"].append(command_failure_metadata(label, log,
                classification=classification, returncode=process.returncode if process else None,
                error_number=error.errno if isinstance(error, OSError) else None,
                root=self.root, test_context=test_context))
        # Raw fixture output is private local data; only sanitized reports are CI artifacts.
        with log.open("wb") as stream:
            log.chmod(0o600)
            try:
                process = subprocess.Popen(argv, cwd=self.root, env=env or self.env,
                                           stdin=subprocess.DEVNULL, stdout=stream,
                                           stderr=subprocess.STDOUT if export is None else subprocess.PIPE,
                                           start_new_session=True)
            except OSError as error:
                failed("process_start_error", error=error)
                raise
            self.last_command_pid = process.pid
            try:
                _, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    stop_process(process)
                finally:
                    failed("deadline_exceeded", process)
                raise suite.Invalid("command_timeout") from None
            finally:
                try:
                    leaked = stop_process(process)
                except (OSError, suite.Invalid) as error:
                    failed("process_group_cleanup_failed", process, error)
                    raise
        if leaked:
            failed("owned_process_group_leaked", process)
        require(not leaked, "command_leaked_process_group")
        if process.returncode != 0:
            failed("process_signal" if process.returncode < 0 else "nonzero_exit", process)
        require(process.returncode == 0, f"command_failed_{label}")
        require(log.stat().st_size <= 256 * 1024 * 1024, "command_output_limit")
        if export is not None:
            require(not stderr or b"error:" not in stderr.lower(), "llvm_export_error")
            log.replace(export)
            export.chmod(0o600)
            return export.read_bytes()
        return log.read_bytes()

    def setup(self):
        require(sys.platform in ("linux", "darwin"), "unsupported_native_platform")
        if sys.platform == "linux":
            require(os.geteuid() == 0 and suite.has_sys_ptrace(), "linux_root_and_sys_ptrace_required")
        if self.contained:
            self.result["contained_service_profile"] = contained_prerequisites(sys.platform)
        self.result["source_before"] = suite.source_snapshot(self.root)
        require(not self.acceptances or not self.result["source_before"]["dirty"] or self.acceptance_allow_dirty,
                "acceptance_coverage_requires_clean_source_or_explicit_local_candidate")
        self.env["OPAQUE_BUILD_REVISION"] = self.result["source_before"]["revision"]
        version = self.command("collector-version", [self.collector, "llvm-cov", "--version"]).decode().strip()
        require(version == f"cargo-llvm-cov {COLLECTOR_VERSION}", "unexpected_collector_version")
        verbose = self.command("compiler-identity", ["rustc", "-vV"]).decode()
        require("-nightly" in verbose, "nightly_compiler_required")
        host = re.findall(r"^host: (\S+)$", verbose, re.MULTILINE)
        require(len(host) == 1, "missing_native_target")
        self.result["compiler"] = verbose.strip().splitlines()
        self.result["target"] = host[0]
        metadata_raw = self.command("workspace-metadata", ["cargo", "metadata", "--locked", "--format-version", "1",
                                   "--no-deps", "--all-features", "--filter-platform", host[0]])
        self.workspace = workspace_inventory(json.loads(metadata_raw), self.root)
        self.result["workspace_metadata_sha256"] = hashlib.sha256(metadata_raw).hexdigest()
        self.result["workspace_packages"] = self.workspace
        self.result["coverage_packages"] = [p["name"] for p in self.workspace]
        self.result["test_collection_packages"] = self.result["coverage_packages"][:]
        self.result["feature_selection"] = "all workspace features; native compiler target"
        self.result["source_inventory"] = source_inventory(self.root, self.workspace)
        sysroot = Path(self.command("compiler-sysroot", ["rustc", "--print", "sysroot"]).decode().strip())
        self.llvm_cov = str(sysroot / "lib/rustlib" / host[0] / "bin/llvm-cov")
        self.llvm_profdata = str(sysroot / "lib/rustlib" / host[0] / "bin/llvm-profdata")
        raw = self.command("instrumentation-environment", [self.collector, "llvm-cov", "show-env"])
        # show-env emits diagnostic information on stderr, which command logs merge.
        assignments = b"\n".join(line for line in raw.splitlines() if re.match(rb"[A-Z_][A-Z0-9_]*=", line))
        self.env.update(parse_environment(assignments, self.flags))
        self.env["OPAQUE_COVERAGE_RUSTC"] = str(sysroot / "bin/rustc")
        self.env["OPAQUE_COVERAGE_RUSTFLAGS"] = json.dumps(self.flags)
        require(Path(self.env["CARGO_LLVM_COV_TARGET_DIR"]).resolve() == self.target,
                "collector_changed_target_directory")
        self.result["preflight"] = self.preflight()

    def bind_workspace_cache(self):
        """Cargo can reuse path-dependent objects after a checkout moves.

        In particular, a fresh artifact event may still contain an old
        CARGO_MANIFEST_DIR or LLVM filename. Invalidate only workspace packages
        when the source root changes; registry dependencies and sibling target
        directories are outside this cleanup.
        """
        require(bool(self.workspace), "workspace_metadata_not_loaded")
        path = self.target / CACHE_BINDING
        require(not path.is_symlink(), "symlink_workspace_cache_binding")
        expected = {"schema": CACHE_SCHEMA, "source_root": str(self.root),
                    "workspace_packages": sorted(p["name"] for p in self.workspace)}
        previous = None
        if path.exists():
            require(path.is_file() and path.stat().st_size <= 1024 * 1024,
                    "invalid_workspace_cache_binding")
            try:
                previous = suite.json_read(path)
            except (ValueError, suite.Invalid) as error:
                raise suite.Invalid("invalid_workspace_cache_binding") from error
            require(isinstance(previous, dict) and set(previous) == set(expected)
                    and previous["schema"] == CACHE_SCHEMA
                    and isinstance(previous["source_root"], str)
                    and Path(previous["source_root"]).is_absolute()
                    and isinstance(previous["workspace_packages"], list)
                    and bool(previous["workspace_packages"])
                    and all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name)
                            for name in previous["workspace_packages"])
                    and previous["workspace_packages"] == sorted(set(previous["workspace_packages"])),
                    "invalid_workspace_cache_binding")
        invalidated = previous != expected
        if invalidated:
            # main() creates or explicitly accepts this compiler-cache root.
            # The pinned Cargo requires its standard tag before scoped clean,
            # but does not create it when the caller pre-created the directory.
            tag = self.target / "CACHEDIR.TAG"
            require(not tag.is_symlink(), "symlink_cargo_cache_tag")
            if tag.exists():
                require(tag.is_file() and tag.stat().st_size <= 4096
                        and tag.read_bytes().startswith(CACHE_TAG_SIGNATURE), "invalid_cargo_cache_tag")
            else:
                with tag.open("xb") as stream:
                    stream.write(CACHE_TAG_SIGNATURE + b"\n# Explicit Opaque coverage compiler cache.\n")
            argv = ["cargo", "clean", "--manifest-path", str(self.root / "Cargo.toml"),
                    "--target-dir", str(self.target)]
            for package in expected["workspace_packages"]:
                argv.extend(["--package", package])
            # Never bind an uncertain or failed cleanup as safe for reuse.
            self.command("invalidate-workspace-source-cache", argv)
            temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
            created = False
            try:
                with temporary.open("x") as stream:
                    created = True
                    temporary.chmod(0o600)
                    json.dump(expected, stream, sort_keys=True)
                    stream.write("\n")
                temporary.replace(path)
            finally:
                if created:
                    temporary.unlink(missing_ok=True)
        self.result["workspace_cache"] = {"binding": expected,
            "status": "workspace_packages_invalidated" if invalidated else "same_source_root_reused",
            "reason": "unbound_cache" if previous is None else "source_root_or_workspace_changed" if invalidated else None,
            "invalidated_packages": expected["workspace_packages"] if invalidated else [],
            "scope": "workspace packages only; registry dependencies and sibling target directories preserved"}

    def preflight(self):
        directory = fresh_directory(self.output / "continuous-preflight")
        source = directory / "probe.rs"
        source.write_text("#[inline(never)]\nfn observed(value: bool) -> u32 { if value { 31 } else { 17 } }\n"
                          "fn main() { println!(\"READY:{}\", observed(true)); loop { std::thread::park(); } }\n")
        binary = directory / "probe"
        self.command("continuous-probe-build", ["rustc", str(source), "--edition=2024", *self.flags,
                                                "-o", str(binary)])
        env = dict(self.env, LLVM_PROFILE_FILE=str(directory / "probe-%p-%m-%c.profraw"))
        with (directory / "stderr.log").open("wb") as stderr:
            process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.PIPE, stderr=stderr,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    require(bool(selector.select(10)), "continuous_probe_not_ready")
                    require(process.stdout.readline() == b"READY:31\n", "continuous_probe_bad_result")
                process.kill()  # SIGKILL deliberately prevents atexit profile writes.
                process.wait(timeout=10)
            finally:
                stop_process(process)
                process.stdout.close()
        profiles = list(directory.glob("*.profraw"))
        require(bool(profiles) and all(p.stat().st_size > 0 for p in profiles), "killed_child_lost_profile")
        merged = directory / "probe.profdata"
        self.command("continuous-probe-merge", [self.llvm_profdata, "merge", "--sparse", "--failure-mode=any",
                                                *map(str, profiles), "-o", str(merged)])
        raw = self.command("continuous-probe-export", [self.llvm_cov, "export", str(binary),
                          "-instr-profile=" + str(merged), "--sources", str(source)], export=directory / "probe.json")
        report = json.loads(raw)
        branches = [branch for file in report["data"][0]["files"] for branch in file["branches"]]
        require(len(branches) == 1 and branches[0][4:6] == [1, 0], "killed_child_branch_counters_not_retained")
        return {"status": "passed", "termination": "SIGKILL", "observed_branch_counts": [1, 0],
                "source_sha256": sha(source), "binary_sha256": sha(binary),
                "profile_sha256": [sha(p) for p in profiles]}

    def read_artifacts(self, raw):
        selected = artifacts(raw, self.target, qualified=True)
        self.package_by_binary.update(artifact_packages(raw, set(selected.values()), self.root, self.workspace))
        self.test_kind_by_binary.update({path: kind for (_identity, _name, kind, is_test), path in selected.items() if is_test})
        return {(self.package_by_binary[path], name, kind, is_test): path
                for (_identity, name, kind, is_test), path in selected.items()}

    def build(self):
        require(bool(self.workspace), "workspace_metadata_not_loaded")
        self.bind_workspace_cache()
        self.normal = self.read_artifacts(self.command("build-all-workspace-binaries", ["cargo", "build", "--locked",
                           "--workspace", "--all-features", "--bins", "--message-format=json"]))
        validate_workspace_artifacts(self.workspace, self.normal, tests=False)
        self.baseline = self.read_artifacts(self.command("build-all-workspace-tests", ["cargo", "test", "--locked",
                           "--workspace", "--all-features", "--tests", "--no-run", "--message-format=json"]))
        validate_workspace_artifacts(self.workspace, self.baseline, tests=True)
        self.composition = self.baseline
        self.objects = set(self.baseline.values()) | set(self.normal.values())
        self.result["compiled_target_inventory"] = [{"package": package, "target": name, "kind": kind,
                                                     "test_harness": is_test, "path": str(path)}
            for (package, name, kind, is_test), path in sorted({**self.normal, **self.baseline}.items())]

    def validate_cases(self):
        expected = dict(self.cases)
        binaries = {}
        for target in expected:
            key = ("opaqued", target, "bin" if target == "opaqued" else "test", True)
            require(key in self.composition, "missing_composition_test_artifact")
            binaries[target] = self.composition[key]
        if sys.platform == "linux":
            expected["opaque_core"] = (ROOT_CASE,)
            binaries["opaque_core"] = self.baseline[("opaque-core", "opaque_core", "lib", True)]
        directory = fresh_directory(self.output / "inventory-preflight")
        env = dict(self.env, LLVM_PROFILE_FILE=str(directory / "inventory-%p-%m-%c.profraw"))
        inventories = {}
        for target, binary in binaries.items():
            env["CARGO_PKG_NAME"] = self.package_by_binary[binary]
            inventories[target] = suite.inventory(self.command("preflight-inventory-" + target,
                                                               [str(binary), "--list"], env=env, timeout=60))
        self.result["declared_test_inventory"] = validate_case_inventory(expected, inventories)
        for (package, name, kind, is_test), binary in sorted(self.baseline.items()):
            if not is_test:
                continue
            env["CARGO_PKG_NAME"] = package
            inventory_raw = self.command("workspace-inventory-" + package + "-" + name,
                                         [str(binary), "--list"], env=env, timeout=60)
            names = test_inventory(inventory_raw)
            ignored_raw = self.command("workspace-ignored-" + package + "-" + name,
                                       [str(binary), "--list", "--ignored"], env=env, timeout=60)
            ignored = test_inventory(ignored_raw)
            require(ignored <= names, "ignored_tests_not_in_native_inventory")
            reviewed = reviewed_ignored_tests(package, name, ignored)
            self.test_inventories[binary] = (names, ignored)
            self.result["test_targets"].append({"package": package, "target": name, "kind": kind,
                "compiled_tests": len(names), "non_ignored_tests": len(names - ignored), "ignored_tests": sorted(ignored),
                "compiled_test_names": sorted(names), "non_ignored_test_names": sorted(names - ignored),
                "counter_diagnostics": sorted(set(counter_diagnostics(inventory_raw, zero_tests=not names)
                                                   + counter_diagnostics(ignored_raw, zero_tests=not names))),
                "status": "selected" if names - ignored else "ignored_only" if names else "zero_tests_on_native_target",
                "reason": None if names - ignored else "No non-ignored test will be claimed as passed for this native target."})
            self.result["skipped_tests"].extend({"package": package, "target": name, "test": test,
                 "reason": reviewed[test], "reviewed_prerequisite": reviewed[test],
                 "executed_by_explicit_profile": False} for test in sorted(ignored))
        self.declared_inventory_validated = True

    def execute(self, target, binary, name=None):
        index = len(self.result["executions"])
        directory = fresh_directory(self.output / "profiles" / f"{index:03d}-{target}", 0o1777)
        env = dict(self.env, LLVM_PROFILE_FILE=str(directory / "test-%p-%m-%c.profraw"),
                   OPAQUE_COVERAGE_PROFILE_DIR=str(directory))
        with_home = fresh_directory(self.output / f"home-{index:03d}", 0o700)
        env["HOME"] = str(with_home)
        # Cargo supplies this at runtime. The existing resource gateway fixture
        # uses its package name as a harmless synthetic source credential.
        env["CARGO_PKG_NAME"] = self.package_by_binary[binary]
        names = test_inventory(self.command("inventory-" + target, [str(binary), "--list"], env=env, timeout=60))
        # Inventory itself can produce empty-count test profiles; remove them so
        # their existence cannot satisfy execution/child-profile requirements.
        for path in directory.glob("*.profraw"):
            path.unlink()
        if name is None:
            argv = [str(binary), "--test-threads=1"]
        else:
            require(name in names, "required_named_test_not_found")
            # Capture successful fixture diagnostics so they cannot split the
            # exact libtest result line. Failures still print captured output.
            argv = [str(binary), "--exact", name, "--test-threads=1"]
            if target in ("synthesized_review_e2e", CONTAINED_TARGET, "trust_domain_e2e") or name in (ROOT_CASE, DAEMON_ROOT_CASE):
                argv += ["--include-ignored"]
        raw = self.command("execute-" + target, argv, env=env, timeout=1200,
                           test_context=(self.package_by_binary[binary], target, name, names))
        test_pid = self.last_command_pid
        no_test_execution = name is None and not names - self.test_inventories[binary][1]
        if name is None:
            counts = suite_pass(raw, names, allowed_ignored=self.test_inventories[binary][1], allow_empty=no_test_execution)
        else:
            suite.named_pass(raw, name)
            counts = {"passed": 1, "ignored": []}
        diagnostics = counter_diagnostics(raw, zero_tests=no_test_execution and not names)
        if no_test_execution:
            profiles, peers = (profile_inventory(directory, "zero-tests") if list(directory.glob("*.profraw")) else ([], []))
        else:
            profiles, peers = profile_inventory(directory, target, name)
        self.objects.update(peers)
        self.result["profiles"].extend(profiles)
        self.result["executions"].append({"target": target, "test": name, "package": self.package_by_binary[binary], "binary_sha256": sha(binary),
                                          "kind": self.test_kind_by_binary.get(binary),
                                          "inventory_count": len(names), **counts,
                                          "passed_test_names": sorted(names - set(counts["ignored"])) if name is None else [name],
                                          "qualification": "no_tests_executed" if no_test_execution else "passed",
                                          "counter_diagnostics": diagnostics,
                                          "test_process_id": test_pid,
                                          "profile_process_ids": sorted({p["process_id"] for p in profiles}),
                                          "additional_profile_process_ids": sorted({p["process_id"] for p in profiles} - {test_pid}),
                                          "process_scope": "profile PID distinguishes inherited child counters; semantic roles require explicit fixture tagging",
                                          "profiles": [p["path"] for p in profiles]})
        reasons = dict(re.findall(r"^test (.+?) \.\.\. ignored(?:, (.*))?$", raw.decode(), re.MULTILINE))
        for skipped in self.result["skipped_tests"]:
            if skipped["package"] == self.package_by_binary[binary] and skipped["target"] == target and skipped["test"] in reasons:
                skipped["reason"] = reasons[skipped["test"]] or "compiled #[ignore] without a reason annotation"
        if name is not None:
            for skipped in self.result["skipped_tests"]:
                if skipped["test"] == name and skipped["target"] == target and skipped["package"] == self.package_by_binary[binary]:
                    skipped["executed_by_explicit_profile"] = True

    def export(self, label, objects, profiles):
        merged = self.output / f"{label}.profdata"
        self.command("merge-" + label, [self.llvm_profdata, "merge", "--sparse", "--failure-mode=any",
                     *[p["path"] for p in profiles], "-o", str(merged)])
        objects = sorted(objects)
        argv = [self.llvm_cov, "export", str(objects[0]), "-instr-profile=" + str(merged)]
        for binary in objects[1:]:
            argv += ["--object", str(binary)]
        unfiltered_raw = self.command("mapping-inventory-" + label, [*argv, "--summary-only"],
                                      export=self.output / f"{label}-unfiltered-mappings.json")
        native_mappings = unfiltered_runtime_mappings(json.loads(unfiltered_raw), self.result["source_inventory"],
                                                      self.workspace, self.root, self.target)
        argv += ["--include-filename-regex=^(" + "|".join(re.escape(native_mappings[name])
                                                         for name in sorted(native_mappings)) + ")$"]
        report_path = self.output / ("llvm-coverage.json" if label == "critical" else f"{label}-llvm-coverage.json")
        raw = self.command("export-" + label, argv, export=report_path)
        report = json.loads(raw)
        missing = validate_report_scope(report, self.result["source_inventory"], self.root, native_mappings)
        package_rows = workspace_package_coverage(report, self.result["source_inventory"], self.workspace, self.root)
        if label == "critical":
            self.result["workspace_package_coverage"] = package_rows
        require(all(row["status"] != "unqualified_zero_native_mapping" for row in package_rows),
                "eligible_workspace_package_missing_native_mapping:"
                + ",".join(row["package"] for row in package_rows if row["status"] == "unqualified_zero_native_mapping"))
        summary = gate.evaluate(report, source_root=self.root, required_files=REQUIRED_FILES,
                                require_branches=True, minimum_lines=0, minimum_branches=0)
        require(summary["status"] == "passed", "structural_coverage_validation_failed")
        summary.update({"status": "measured", "thresholds": {"lines": None, "branches": None},
                        "qualification": "measurements only; enforce per-crate tiers and native-target ratchet separately"})
        summary.update({"platform": sys.platform, "target": self.result["target"], "toolchain": TOOLCHAIN,
                        "coverage_packages": self.result["coverage_packages"], "workspace_packages": package_rows,
                        "input_sha256": hashlib.sha256(raw).hexdigest()})
        save(self.output / ("coverage-summary.json" if label == "critical" else f"{label}-summary.json"), summary)
        if label == "critical":
            original = package_report_subset(report, ORIGINAL_PACKAGES, self.root)
            original_summary = gate.evaluate(original, source_root=self.root, required_files=ORIGINAL_REQUIRED_FILES,
                                             require_branches=True, minimum_lines=0, minimum_branches=0)
            require(original_summary["status"] == "passed", "historical_scope_validation_failed")
            original_summary.update({"status": "measured", "thresholds": {"lines": None, "branches": None}})
            original_summary.update({"platform": sys.platform, "target": self.result["target"],
                                     "toolchain": TOOLCHAIN, "input_sha256": hashlib.sha256(raw).hexdigest(),
                                     "coverage_packages": list(ORIGINAL_PACKAGES),
                                     "scope": "historical three-package comparison only; never whole-workspace qualification"})
            save(self.output / "original-scope-summary.json", original_summary)
        return {"coverage_gate": "not_evaluated", "coverage_report_sha256": summary["input_sha256"],
                "unfiltered_mapping_inventory_sha256": hashlib.sha256(unfiltered_raw).hexdigest(),
                "native_mapped_source_files": sorted(native_mappings),
                "merged_profile_sha256": sha(merged), "sources_without_mapping": missing,
                "unmapped_source_scope": "no mapping emitted on this native target; may be test-only coverage(off), compiled-out, or uninstantiated code; not qualification from another OS",
                "measured": summary["measured"], "binary_count": len(objects), "profile_count": len(profiles)}

    def acceptance_input(self, purpose):
        directory = fresh_directory(self.output / ("acceptance-" + purpose))
        profiles = fresh_directory(self.output / "profiles" / ("acceptance-" + purpose), 0o1777)
        normal = {name: path for (_package, name, _kind, is_test), path in self.normal.items() if not is_test}
        names = (acceptance.BINARIES if purpose == "packaged" else {"opaqued", "opaque-web"} if purpose == "browser"
                 else {"opaque", "opaqued"} if purpose == "service" else {"opaqued"})
        require(names <= normal.keys(), "acceptance_missing_normal_workspace_binary")
        objects = {name: normal[name] for name in names}
        if purpose == "model":
            objects["model-test"] = self.baseline[("opaqued", CONTAINED_TARGET, "test", True)]
        value = {"schema": acceptance.SCHEMA, "purpose": purpose, "source": self.result["source_before"],
                 "platform": sys.platform, "target": self.result["target"], "toolchain": TOOLCHAIN,
                 "rustc": self.env["OPAQUE_COVERAGE_RUSTC"], "instrumentation": self.flags,
                 "profile_dir": str(profiles),
                 "qualification": "instrumented_local_candidate" if self.result["source_before"]["dirty"] else "instrumented_build_candidate",
                 "objects": {name: {"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size}
                             for name, path in sorted(objects.items())}}
        path = directory / "input.json"
        save(path, value)
        value = acceptance.load(path, root=self.root, purpose=purpose, source=self.result["source_before"])
        return directory, path, value

    def collect_acceptance(self):
        for purpose in self.acceptances:
            directory, input_path, value = self.acceptance_input(purpose)
            report_path = directory / "suite/report.json"
            if purpose == "packaged":
                binary_dirs = {str(Path(row["path"]).parent) for row in value["objects"].values()}
                require(len(binary_dirs) == 1, "packaged_binaries_do_not_share_build_directory")
                candidate = directory / "candidate"
                argv = [sys.executable, "-B", str(self.root / "tests/packaged/build.py"),
                        "--binary-dir", next(iter(binary_dirs)), "--output", str(candidate)]
                if self.acceptance_allow_dirty:
                    argv.append("--allow-dirty")
                self.command("build-instrumented-package", argv, timeout=300)
                archive = candidate / "candidate.tar.gz"
                archive_hash = sha(archive)
                argv = [sys.executable, "-B", str(self.root / "scripts/synthesized_suite.py"), "--profile", "packaged",
                        "--packaged-archive", str(archive), "--coverage-input", str(input_path),
                        "--output", str(directory / "suite")]
                if sys.platform == "linux":
                    argv += ["--packaged-owner-user", "opaque", "--packaged-peer-user", "nobody"]
                if self.acceptance_allow_dirty:
                    argv.append("--packaged-allow-dirty")
                self.command("execute-installed-package", argv, timeout=600)
                report = json.loads(report_path.read_bytes())
                require(report["status"] == "passed" and len(report["commands"]) == 1
                        and report["counts"]["unique_tests_passed"] == 0
                        and report["counts"]["command_scenarios_passed"] == 1, "installed_acceptance_did_not_pass")
                qualified = report["commands"][0]["qualification"]
                version = tomllib.loads((self.root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
                suite.packaged_report(qualified, source=self.result["source_before"], target=self.result["target"],
                                      version=version, archive_sha256=archive_hash)
                require(sha(archive) == archive_hash, "instrumented_archive_changed")
                require(qualified["coverage"]["input_sha256"] == sha(input_path), "installed_coverage_input_not_executed")
                profiles = acceptance.profiles(value, roles={"installed"})
                require(profiles == qualified["coverage"]["profiles"], "installed_profiles_changed")
                # codesign changes Mach-O bytes in the app. Retain those exact
                # Rust objects as well as the untouched top-level tools.
                if sys.platform == "darwin":
                    for name in ("opaque-approver", "opaque-approve-helper"):
                        self.objects.add(candidate / "payload/Opaque Reviewer.app/Contents/MacOS" / name)
                checks = qualified["cases"]
            elif purpose == "browser":
                argv = [sys.executable, "-B", str(self.root / "tests/browser/run.py"),
                        "--coverage-input", str(input_path), "--output", str(directory / "suite")]
                if self.browser_cache:
                    argv += ["--browser-cache", str(self.browser_cache)]
                self.command("execute-real-chromium", argv, timeout=900)
                report = json.loads(report_path.read_bytes())
                require(report["status"] == "passed" and report["input_sha256"] == sha(input_path)
                        and len(report["tests"]) == 4, "browser_acceptance_did_not_pass")
                profiles = acceptance.profiles(value, roles={"web", "daemon"}, process_ids={p["pid"] for p in report["processes"]})
                require(profiles == report["profiles"], "browser_profiles_changed")
                checks = report["tests"]
            elif purpose == "service":
                require(os.environ.get("container") == "docker", "service_acceptance_requires_owned_container")
                self.command("execute-real-user-service", [sys.executable, "-B", str(self.root / "tests/service/contained.py"),
                    "--opaque", value["objects"]["opaque"]["path"], "--opaqued", value["objects"]["opaqued"]["path"],
                    "--coverage-input", str(input_path), "--output", str(directory / "suite")],
                    env={**self.env, "container": "docker"}, timeout=300)
                report = json.loads(report_path.read_bytes())
                checks = {"real-keyed-seal", "install-enabled-reachable-owned-daemon", "stop-reaped-daemon",
                          "start-and-restart-new-reachable-pids", "uninstall-disabled-removed-and-reaped",
                          "actual-systemctl-unavailable-manager-denied"}
                require(report["schema"] == "opaque.contained-user-service.v1" and report["status"] == "passed"
                        and report["cleanup_errors"] == [] and len(report["checks"]) == len(checks)
                        and set(report["checks"]) == checks and report["coverage"]["input_sha256"] == sha(input_path),
                        "real_user_service_not_qualified")
                profiles = acceptance.profiles(value, roles={"service"}, process_ids=report["rust_process_ids"])
                require(profiles == report["coverage"]["profiles"], "service_profiles_changed")
                checks = report["checks"]
            else:
                self.command("execute-real-model", [sys.executable, "-B", str(self.root / "tests/real-model/service.py"),
                    "--source-root", str(self.root), "--target-dir", str(self.target),
                    "--coverage-input", str(input_path), "--output", str(directory / "model"),
                    "--suite-output", str(directory / "suite")], timeout=2700)
                report = json.loads(report_path.read_bytes())
                service = json.loads((directory / "model-service.json").read_bytes())
                require(service["status"] == "passed" and service["cleanup"] == service["suite_cleanup"] == "stopped_and_reaped"
                        and service["tokens_before"] == 0 and service["tokens_after"] > 0
                        and service["coverage"]["input_sha256"] == sha(input_path), "real_model_service_not_qualified")
                require(report["status"] == "passed" and report["counts"]["unique_tests_passed"] == 1
                        and len(report["tests"]) == 1 and report["tests"][0]["status"] == "passed"
                        and report["instrumented_acceptance_input_sha256"] == sha(input_path), "real_model_case_not_qualified")
                name = "contained_real_model_completions_require_signed_review_and_survive_restart"
                require(report["tests"][0]["name"] == name, "real_model_case_identity_changed")
                profiles, peers = profile_inventory(Path(value["profile_dir"]), CONTAINED_TARGET, name)
                require(profiles == service["coverage"]["profiles"], "real_model_profiles_changed")
                self.objects.update(peers)
                self.result["executions"].append({"target": CONTAINED_TARGET, "package": "opaqued", "kind": "test",
                    "test": name, "passed": 1, "ignored": [], "passed_test_names": [name], "qualification": "passed",
                    "binary_sha256": value["objects"]["model-test"]["sha256"], "via": "actual_model_acceptance",
                    "profiles": [p["path"] for p in profiles]})
                for skipped in self.result["skipped_tests"]:
                    if (skipped["package"], skipped["target"], skipped["test"]) == ("opaqued", CONTAINED_TARGET, name):
                        skipped["executed_by_explicit_profile"] = True
                self.result["not_qualified"].remove("real model completions")
                checks = [name]
            require(report["source_before"] == report["source_after"] == self.result["source_before"],
                    "acceptance_source_identity_changed")
            require(bool(profiles), "acceptance_has_no_native_profiles")
            self.result["profiles"].extend(profiles)
            self.result["acceptance_executions"].append({"purpose": purpose, "status": "passed",
                "input_sha256": sha(input_path), "report_sha256": sha(report_path), "report_path": str(report_path),
                "qualification": value["qualification"], "checks": checks, "profile_count": len(profiles),
                "profile_process_ids": sorted({p["process_id"] for p in profiles}),
                "scope": "Existing acceptance checks with fresh native Rust counters; check count is not additional Rust test count"})

    def collect(self):
        require(self.declared_inventory_validated, "declared_inventory_not_validated")
        if self.acceptance_only:
            self.collect_acceptance()
            self.finish_collection()
            self.result["status"] = "acceptance_only_collected"
            self.result["comparison_scope"] = "Development acceptance-only counters; ordinary workspace tests and selected exact repeats were not executed."
            return
        for (package, name, kind, is_test), binary in sorted(self.baseline.items()):
            if is_test:
                self.execute(name, binary)
        require(any(row["passed"] > 0 for row in self.result["executions"]), "no_workspace_tests_executed")
        baseline_profiles = list(self.result["profiles"])
        baseline_objects = set(self.baseline.values()) | set(self.normal.values())
        self.result["baseline"] = self.export("baseline", baseline_objects, baseline_profiles)
        self.result["baseline"]["execution_count"] = len(self.result["executions"])
        self.result["baseline"]["binary_paths"] = [str(p) for p in sorted(baseline_objects)]
        self.result["baseline"]["profile_paths"] = [p["path"] for p in baseline_profiles]
        if sys.platform == "linux":
            self.execute("opaque_core", self.baseline[("opaque-core", "opaque_core", "lib", True)], ROOT_CASE)
            self.result["ignored_reconciled_by_explicit_execution"] = [ROOT_CASE]
        for target, names in self.cases.items():
            key = ("opaqued", target, "bin" if target == "opaqued" else "test", True)
            require(key in self.composition, "missing_composition_test_artifact")
            for name in names:
                self.execute(target, self.composition[key], name)
        self.collect_acceptance()
        self.finish_collection()

    def finish_collection(self):
        self.result["binaries"] = [{"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size,
                                    "package": self.package_by_binary.get(path),
                                    "kind": "cargo_artifact" if path in self.package_by_binary else "retained_native_fixture_or_packaged_object"}
                                   for path in sorted(self.objects)]
        self.result.update(self.export("critical", self.objects, self.result["profiles"]))
        if sys.platform == "linux":
            # /target can disappear with the owned host. One deduplicated
            # archive retains exact mapping bytes without a second Cargo cache.
            # It stays private local output, never a public CI upload.
            archive = self.output / "mapping-objects.tar.gz"
            seen = set()
            with tarfile.open(archive, "w:gz", compresslevel=1) as stream:
                for row in self.result["binaries"]:
                    path = Path(row["path"])
                    require(sha(path) == row["sha256"] and not path.is_symlink(), "mapping_object_changed_before_retention")
                    if row["sha256"] not in seen:
                        stream.add(path, arcname="objects/" + row["sha256"], recursive=False)
                        seen.add(row["sha256"])
            self.result["retained_mapping_objects"] = {"path": str(archive), "sha256": sha(archive),
                "unique_objects": len(seen), "member_format": "objects/<binary sha256>", "scope": "private local run output"}
        else:
            self.result["retained_mapping_objects"] = {"scope": "exact native object paths and hashes retained in local cache; caller archives before cache reuse"}
        self.result["source_after"] = suite.source_snapshot(self.root)
        self.result["counts"] = test_execution_counts(self.result["executions"], self.result["test_targets"], self.result["skipped_tests"])
        self.result["counts"]["acceptance_command_scenarios"] = len(self.result["acceptance_executions"])
        require(self.result["source_after"] == self.result["source_before"], "source_changed_during_collection")
        self.result["status"] = "collected"
        if self.contained and not self.acceptance_only:
            self.result["not_qualified"].remove("contained Vault/OpenSSH/systemd service")
            self.result["contained_service_profile"]["executed_tests"] = list(CONTAINED_CASES)
        self.result["comparison_scope"] = (
            "Baseline and expanded reports use this native platform and the same declared production source inventory. "
            "Expanded daemon/caller mappings may add production instantiations; compare both denominators, not percentages alone.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--collector", default="cargo-llvm-cov")
    parser.add_argument("--reuse-target-dir", action="store_true",
                        help="Reuse the compiler cache; changed or unbound source roots invalidate workspace packages only; profiles remain fresh")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--build-only", action="store_true", help="discover and compile every workspace target without claiming collected coverage")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--contained", action="store_true",
                        help="Also require real SSH and controlled inference RPC scenarios inside the marked disposable host")
    parser.add_argument("--acceptance", action="append", choices=sorted(acceptance.PURPOSES), default=[],
                        help="Execute this existing acceptance against the same instrumented workspace objects")
    parser.add_argument("--acceptance-only", action="store_true", help="development probe; no ordinary-test or full-collection qualification")
    parser.add_argument("--acceptance-allow-dirty", action="store_true", help="explicit local instrumented candidate only")
    parser.add_argument("--browser-cache", type=Path, help="explicit existing Playwright engine cache")
    args = parser.parse_args(argv)
    output = None
    collector = None
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    previous_sigterm = signal.signal(signal.SIGTERM, interrupted)
    try:
        root = args.source_root.resolve(strict=True)
        require(1 <= args.jobs <= 64, "invalid_build_job_count")
        require(not args.output.resolve().is_relative_to(root), "coverage_output_must_be_outside_source_checkout")
        output = fresh_directory(args.output.absolute())
        if args.reuse_target_dir and args.target_dir.is_dir():
            require(not args.target_dir.is_symlink(), "symlink_target_cache")
            target = args.target_dir.resolve()
        else:
            target = fresh_directory(args.target_dir.absolute())
        fresh_directory(output / "profiles")
        collector = Collector(root, output, target, args.collector, args.jobs, args.contained,
                              acceptances=args.acceptance, acceptance_only=args.acceptance_only,
                              acceptance_allow_dirty=args.acceptance_allow_dirty, browser_cache=args.browser_cache)
        collector.setup()
        if args.preflight_only:
            collector.result["status"] = "preflight_only"
        else:
            collector.build()
            if args.build_only:
                collector.result["status"] = "build_only"
            else:
                collector.validate_cases()
                collector.collect()
        status = 0
    except KeyboardInterrupt:
        result = collector.result if collector else {"schema": SCHEMA, "platform": sys.platform, "failures": []}
        result["status"] = "failed"
        result["failures"].append("interrupted")
        status = 130
    except (suite.Invalid, gate.CoverageError, OSError, ValueError, KeyError, TypeError) as error:
        result = collector.result if collector else {"schema": SCHEMA, "platform": sys.platform, "failures": []}
        result["status"] = "failed"
        result["failures"].append(str(error) if isinstance(error, suite.Invalid) else type(error).__name__)
        print("coverage collection failed; inspect the private command logs and collection.json", file=sys.stderr)
        status = 2
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        if output is not None:
            save(output / "collection.json", collector.result if collector else result)
    return status


if __name__ == "__main__":
    sys.exit(main())
