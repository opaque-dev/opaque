#!/usr/bin/env python3
"""Require per-crate coverage tiers and an exact native-target coverage ratchet."""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

import check_llvm_coverage as llvm
import synthesized_suite as suite

POLICY_SCHEMA = "opaque.coverage-policy.v1"
BASELINE_SCHEMA = "opaque.coverage-baseline.v1"
RESULT_SCHEMA = "opaque.coverage-policy-result.v1"
TARGETS = {"aarch64-apple-darwin": "darwin", "x86_64-apple-darwin": "darwin",
           "aarch64-unknown-linux-gnu": "linux", "x86_64-unknown-linux-gnu": "linux"}
TIERS = {"kernel": {"lines": 100, "branches": 100},
         "enforcement": {"branches": 85}, "general": {"branches": 70}}
METRICS = ("lines", "branches")


class PolicyError(ValueError):
    """Only fixed messages and checked package identities are reported."""


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON keys cannot redefine coverage evidence or policy")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique_object), sha(raw)


def read(path):
    require(path.is_file() and not path.is_symlink(), "input must be a regular non-symlink file")
    return decode(path.read_bytes())


def identity(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def ratio(metric):
    checked = llvm._metric(metric)
    require(checked["count"] > 0, "each package must have measured lines and branches")
    return Fraction(checked["covered"], checked["count"])


def policy_packages(policy, names):
    require(isinstance(policy, dict) and set(policy) == {"schema", "packages"}
            and policy["schema"] == POLICY_SCHEMA, "invalid coverage policy")
    assignments = policy["packages"]
    require(isinstance(assignments, dict) and set(assignments) == set(names),
            "policy must classify every workspace package exactly once, without stale packages")
    require(all(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_-]*", name)
                and isinstance(tier, str) and tier in TIERS for name, tier in assignments.items()), "invalid package tier")
    require(any(tier == "kernel" for tier in assignments.values()),
            "policy requires a real separately measured decision kernel")
    return assignments


def validate_collection(collection, report_hash, *, source, names, target):
    require(isinstance(collection, dict) and collection.get("schema") == "opaque.workspace-coverage-collection.v2",
            "invalid coverage collection schema")
    require(collection.get("status") == "collected" and collection.get("failures") == []
            and collection.get("failed_commands") == [], "coverage collection did not complete successfully")
    require(target in TARGETS and collection.get("target") == target
            and collection.get("platform") == TARGETS[target], "coverage must match the exact native target")
    require(collection.get("source_before") == source == collection.get("source_after")
            and source.get("dirty") is False, "coverage source identity is stale or dirty")
    require(collection.get("coverage_report_sha256") == report_hash, "LLVM export differs from collected coverage")
    for key in ("coverage_packages", "test_collection_packages"):
        values = collection.get(key)
        require(isinstance(values, list) and len(values) == len(set(values)) and set(values) == set(names),
                "collection must include every workspace package")
    require(collection.get("toolchain") == "nightly-2026-09-13"
            and collection.get("feature_selection") == "all workspace features; native compiler target",
            "coverage instrumentation contract differs")
    flags = collection.get("instrumentation", [])
    require(isinstance(flags, list) and "instrument-coverage" in flags
            and "-Zcoverage-options=branch" in flags
            and "--cfg=coverage" in flags and "--cfg=coverage_nightly" in flags,
            "line and branch instrumentation are required")
    preflight = collection.get("preflight", {})
    require(preflight.get("status") == "passed" and preflight.get("termination") == "SIGKILL"
            and preflight.get("observed_branch_counts") == [1, 0],
            "killed-child continuous branch preflight must pass")
    for key, count_key in (("profiles", "profile_count"), ("binaries", "binary_count")):
        rows = collection.get(key)
        require(isinstance(rows, list) and len(rows) == collection.get(count_key)
                and all(isinstance(row, dict) and identity(row.get("sha256"), 64)
                        and isinstance(row.get("path"), str) and row["path"]
                        and type(row.get("bytes")) is int and row["bytes"] > 0 for row in rows)
                and len({row["path"] for row in rows}) == len(rows),
                "profile and object inventories must retain nonempty hashed evidence")
    require(all(item.get("status") == "passed" for item in collection.get("acceptance_executions", [])),
            "an instrumented acceptance command failed")
    require(any(line == "host: " + target for line in collection.get("compiler", [])),
            "compiler host differs from native target")
    require(type(collection.get("profile_count")) is int and collection["profile_count"] > 0
            and type(collection.get("binary_count")) is int and collection["binary_count"] > 0,
            "native profiles and mapping objects are required")


def baseline_header(baseline, *, target):
    require(isinstance(baseline, dict) and baseline.get("schema") == BASELINE_SCHEMA,
            "invalid ratchet baseline schema")
    require(baseline.get("target") == target and baseline.get("platform") == TARGETS.get(target),
            "baseline must match the exact native target; other architectures cannot substitute")
    origin = baseline.get("source", {})
    require(isinstance(origin, dict) and identity(origin.get("revision"), 40)
            and identity(origin.get("tree_sha256"), 64) and identity(origin.get("release_tree_sha256"), 64),
            "baseline requires exact source provenance")
    require("canonical_revision" not in origin or identity(origin["canonical_revision"], 40),
            "canonical baseline revision must be an immutable commit SHA")
    require(identity(baseline.get("coverage_report_sha256"), 64)
            and identity(baseline.get("collection_sha256"), 64), "baseline evidence hashes are required")
    require(baseline.get("toolchain") == "nightly-2026-09-13"
            and baseline.get("feature_selection") == "all workspace features; native compiler target",
            "baseline instrumentation contract differs")
    provenance = baseline.get("package_provenance")
    if provenance is not None:
        require(isinstance(provenance, dict) and set(provenance) == set(baseline.get("packages", {})),
                "per-package baseline provenance must cover every floor")
        for value in provenance.values():
            require(isinstance(value, dict) and set(value) == {"source", "coverage_report_sha256", "collection_sha256"},
                    "invalid per-package evidence identity")
            origin = value["source"]
            require(isinstance(origin, dict) and identity(origin.get("revision"), 40)
                    and ("canonical_revision" not in origin or identity(origin["canonical_revision"], 40))
                    and identity(origin.get("tree_sha256"), 64) and identity(origin.get("release_tree_sha256"), 64)
                    and identity(value["coverage_report_sha256"], 64) and identity(value["collection_sha256"], 64),
                    "per-package baseline requires exact source and evidence hashes")
    rows = baseline.get("packages")
    require(isinstance(rows, dict) and rows and all(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_-]*", name) for name in rows),
            "invalid baseline package identities")
    return rows


def baseline_packages(baseline, *, target, names):
    rows = baseline_header(baseline, target=target)
    require(set(rows) == set(names),
            "baseline package membership differs; new or moved code requires a reviewed native baseline")
    for metrics in rows.values():
        require(isinstance(metrics, dict) and set(metrics) == set(METRICS), "invalid baseline package metrics")
        for metric in metrics.values():
            ratio(metric)
    return rows


def verified_retirements(root, names, baseline):
    """Authorize only documented whole-crate removals; retain their old floors."""
    path = root / "config/coverage-retirements.json"
    if not path.exists() and not path.is_symlink():
        return set()
    record, _ = read(path)
    require(set(record) == {"schema", "packages"}
            and record["schema"] == "opaque.coverage-retirements.v1"
            and isinstance(record["packages"], dict), "invalid coverage retirement record")
    retired = set()
    for name, entry in record["packages"].items():
        require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_-]*", name)
                and isinstance(entry, dict) and set(entry) == {"manifest", "revision", "reason"},
                "invalid retired package identity")
        manifest = entry["manifest"]
        require(manifest == f"crates/{name}/Cargo.toml" and identity(entry["revision"], 40)
                and isinstance(entry["reason"], str) and entry["reason"].strip(),
                "retirement requires an exact historical manifest and reason")
        source_dir = root / "crates" / name
        require(name not in names and not source_dir.exists() and not source_dir.is_symlink(),
                "retired package remains in the workspace or source tree")
        require(isinstance(baseline, dict) and name in baseline.get("packages", {}),
                "retirement cannot exempt a package without a retained historical floor")
        subprocess.run(["git", "merge-base", "--is-ancestor", entry["revision"], "HEAD"],
                       cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        original = subprocess.check_output(["git", "show", f"{entry['revision']}:{manifest}"], cwd=root)
        require(tomllib.loads(original.decode())["package"]["name"] == name,
                "retired source did not declare this package")
        retired.add(name)
    return retired


def available_baseline(baseline, *, target, names, retired_packages=()):
    """Keep qualified same-target floors while exposing every missing/invalid row."""
    if baseline is None:
        return {}, {"status": "missing", "failures": ["baseline:missing"], "source": None}
    try:
        candidates = baseline_header(baseline, target=target)
    except (PolicyError, llvm.CoverageError, ValueError, TypeError):
        return {}, {"status": "invalid", "failures": ["baseline:invalid_target_or_provenance"], "source": None}
    rows, failures = {}, []
    for name in sorted(set(candidates) | set(names)):
        if name not in candidates:
            failures.append(f"{name}:baseline:missing")
        elif name not in names:
            if name not in retired_packages:
                failures.append(f"{name}:baseline:removed_package")
        else:
            try:
                metrics = candidates[name]
                require(isinstance(metrics, dict) and set(metrics) == set(METRICS), "invalid baseline metrics")
                for metric in metrics.values():
                    ratio(metric)
                rows[name] = metrics
            except (PolicyError, llvm.CoverageError, ValueError, TypeError):
                failures.append(f"{name}:baseline:invalid_metrics")
    return rows, {"status": "invalid" if failures else "passed", "failures": failures,
                  "source": baseline["source"]}


def evaluate(measurement, *, policy, baseline, target, history=None, retired_packages=()):
    require(measurement.get("status") == "passed" and measurement.get("failures") == [],
            "structural coverage validation failed")
    packages = measurement["workspace_packages"]
    names = [item["package"] for item in packages]
    require(names and len(names) == len(set(names)), "missing or duplicate workspace measurements")
    require(target in TARGETS, "unsupported native target")
    assignments = policy_packages(policy, names)
    require(not set(retired_packages) & set(names), "active packages cannot be retired")
    prior, baseline_status = available_baseline(baseline, target=target, names=names,
                                              retired_packages=retired_packages)
    rows, failures = [], list(baseline_status["failures"])
    trusted = {}
    if history is not None:
        failures.extend(history["failures"])
        # History remains usable for direct comparisons even when a candidate
        # tried to lower its own floor. Wrong-target or malformed data is absent.
        trusted = history.get("packages", {})
    for package in packages:
        name = package["package"]
        tier = assignments[name]
        row = {"package": name, "tier": tier, "targets": TIERS[tier],
               "measured": package["measured"], "baseline": prior.get(name),
               "baseline_status": "passed" if name in prior else "unavailable",
               "trusted_baseline": trusted.get(name), "gaps": []}
        for metric in METRICS:
            current = package["measured"][metric]
            current_ratio = ratio(current)
            minimum = TIERS[tier].get(metric)
            if minimum is not None and current_ratio < Fraction(minimum, 100):
                needed = -(-(current["count"] * minimum) // 100) - current["covered"]
                row["gaps"].append({"metric": metric, "kind": "tier_target", "additional_covered": needed})
                failures.append(f"{name}:{metric}:below_{minimum}_percent")
            for floors, kind in ((prior, "ratchet"), (trusted, "trusted_ratchet")):
                if name not in floors:
                    continue
                previous = floors[name][metric]
                if current_ratio < ratio(previous):
                    required = -(-(current["count"] * previous["covered"]) // previous["count"])
                    row["gaps"].append({"metric": metric, "kind": kind, "additional_covered": required - current["covered"]})
                    failures.append(f"{name}:{metric}:" + ("regressed" if kind == "ratchet" else "regressed_from_trusted_base"))
        row["status"] = "failed" if row["gaps"] or name not in prior else "passed"
        rows.append(row)
    invalid = baseline_status["status"] != "passed" or (history is not None and history["status"] != "passed")
    return {"schema": RESULT_SCHEMA, "status": "invalid" if invalid else ("failed" if failures else "passed"),
            "target": target, "platform": TARGETS[target], "tiers": TIERS,
            "ratchet": "per-package exact line and branch ratios, compared only with this native target",
            "scope": "all Cargo workspace packages; branch outcomes are not assertions or state-space coverage",
            "failures": failures, "packages": rows, "measured": measurement["measured"],
            "baseline_status": baseline_status, "baseline_source": baseline_status["source"],
            "baseline_history": history}


def git_output(root, *args, data=None):
    result = subprocess.run(suite.git_command(root, *args), cwd=root, input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    require(result.returncode == 0, "trusted baseline Git object is unavailable")
    return result.stdout


def git_tree(root, revision, prefix=None):
    require(identity(revision, 40), "trusted reference must be a full immutable commit SHA")
    require(git_output(root, "cat-file", "-t", revision) == b"commit\n", "trusted reference must identify a commit")
    args = ["ls-tree", "-rz", "--full-tree", revision]
    if prefix is not None:
        args.extend(["--", prefix])
    result = {}
    for entry in git_output(root, *args).split(b"\0"):
        if not entry:
            continue
        header, name = entry.split(b"\t", 1)
        mode, kind, object_id = header.split(b" ")
        require(name not in result and kind == b"blob" and mode in (b"100644", b"100755", b"120000")
                and identity(object_id.decode("ascii"), 40), "invalid source entry in trusted Git tree")
        result[name] = (mode, object_id)
    return result


def verify_source_identity(root, source):
    """Recompute historical source digests without checking out or executing it."""
    entries = git_tree(root, source.get("canonical_revision", source["revision"]))
    require(entries and len(entries) <= 20000, "invalid baseline source inventory")
    ordered = sorted(entries)
    bodies = io.BytesIO(git_output(root, "cat-file", "--batch",
                                  data=b"".join(entries[name][1] + b"\n" for name in ordered)))
    hasher = hashlib.sha256(b"opaque.synthesized-source.v1\0")
    release = hashlib.sha256()
    total = 0
    for name in ordered:
        mode, object_id = entries[name]
        header = bodies.readline().rstrip(b"\n").split(b" ")
        require(len(header) == 3 and header[:2] == [object_id, b"blob"] and header[2].isdigit(),
                "truncated baseline source object")
        size = int(header[2]); total += size
        require(size <= 64 * 1024 * 1024 and total <= 256 * 1024 * 1024, "baseline source size limit")
        body = bodies.read(size)
        require(len(body) == size and bodies.read(1) == b"\n", "truncated baseline source object")
        kind = b"symlink" if mode == b"120000" else b"file"
        permissions = 0 if kind == b"symlink" else (0o755 if mode == b"100755" else 0o644)
        release.update(name + b"\0" + kind + b"\0")
        release.update(body if kind == b"symlink" else hashlib.sha256(body).digest())
        for part in (name, kind, str(permissions).encode(), hashlib.sha256(body).digest()):
            hasher.update(len(part).to_bytes(8, "big")); hasher.update(part)
    require(bodies.read() == b"", "unexpected baseline source objects")
    require(hasher.hexdigest() == source["tree_sha256"] and release.hexdigest() == source["release_tree_sha256"],
            "baseline source hashes differ from immutable Git source")


def verify_baseline_source(root, baseline):
    identities = [baseline["source"]] + [value["source"] for value in baseline.get("package_provenance", {}).values()]
    seen = set()
    for source in identities:
        key = tuple(source[field] for field in ("revision", "tree_sha256", "release_tree_sha256")) + (source.get("canonical_revision"),)
        if key not in seen:
            verify_source_identity(root, source)
            seen.add(key)


def bind_canonical_revision(root, baseline, revision):
    """Preserve the observed revision while proving a durable content equivalent."""
    require(identity(revision, 40), "canonical revision must be a full immutable commit SHA")
    observed = baseline["source"]["revision"]
    # Both objects are required at export time. Later CI may have only the
    # reachable canonical commit, whose full content fingerprints still bind.
    git_tree(root, observed)
    git_tree(root, revision)
    observed_tree = git_output(root, "rev-parse", observed + "^{tree}")
    canonical_tree = git_output(root, "rev-parse", revision + "^{tree}")
    require(observed_tree == canonical_tree, "canonical revision is not the observed immutable Git tree")
    source = dict(baseline["source"], canonical_revision=revision)
    verify_source_identity(root, source)
    baseline["source"]["canonical_revision"] = revision


def baseline_history(root, *, reference, target, allow_bootstrap=False):
    """Protect all prior native floors from edits made in the proposed branch."""
    history = {"status": "invalid", "reference": reference, "failures": [], "packages": {}, "targets": {}}
    try:
        entries = git_tree(root, reference, "config/coverage-baselines")
        paths = {f"config/coverage-baselines/{name}.json".encode(): name for name in TARGETS}
        require(all(not name.endswith(b".json") or name in paths for name in entries),
                "trusted baseline has an unknown native target")
        for path, native in paths.items():
            candidate_path = root / path.decode()
            prior = None
            prior_hash = None
            if path in entries:
                require(entries[path][0] in (b"100644", b"100755"), "trusted baseline must be a regular file")
                prior, prior_hash = decode(git_output(root, "cat-file", "blob", entries[path][1].decode()))
                old = baseline_packages(prior, target=native, names=baseline_header(prior, target=native))
                if native == target:
                    history["packages"] = old
            elif not candidate_path.exists() and native != target:
                continue
            info = {"status": "invalid", "previous_sha256": prior_hash, "candidate_sha256": None}
            history["targets"][native] = info
            try:
                candidate, candidate_hash = read(candidate_path)
                current = baseline_packages(candidate, target=native, names=baseline_header(candidate, target=native))
                info["candidate_sha256"] = candidate_hash
                if prior is None:
                    require(allow_bootstrap, "first target baseline requires explicit bootstrap review")
                    verify_baseline_source(root, candidate)
                    info["status"] = "bootstrap_source_verified"
                else:
                    require(set(old) <= set(current), "candidate baseline cannot remove an existing package")
                    for name in old:
                        for metric in METRICS:
                            require(ratio(current[name][metric]) >= ratio(old[name][metric]),
                                    "candidate baseline cannot lower a trusted line or branch floor")
                    if candidate_hash != prior_hash:
                        if "previous_baseline_sha256" in candidate:
                            require(candidate["previous_baseline_sha256"] == prior_hash,
                                    "candidate baseline predecessor hash differs from trusted bytes")
                        verify_baseline_source(root, candidate)
                    info["status"] = "passed"
            except (PolicyError, llvm.CoverageError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
                history["failures"].append(native + ":baseline_history:invalid_or_lowered_candidate")
        history["status"] = "failed" if history["failures"] else "passed"
    except (PolicyError, llvm.CoverageError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        history["failures"].append("baseline_history:invalid_or_unavailable_trusted_reference")
    return history


def baseline_from_evidence(measurement, collection, collection_hash, previous=None, policy_definition=None,
                           retired_packages=()):
    """Keep only public counters and provenance; no raw output or private paths."""
    names = [row["package"] for row in measurement["workspace_packages"]]
    result = {"schema": BASELINE_SCHEMA, "target": collection["target"], "platform": collection["platform"],
              "source": {key: collection["source_before"][key] for key in ("revision", "tree_sha256", "release_tree_sha256")},
              "toolchain": collection["toolchain"], "feature_selection": collection["feature_selection"],
              "coverage_report_sha256": collection["coverage_report_sha256"], "collection_sha256": collection_hash,
              "packages": {row["package"]: {metric: {key: row["measured"][metric][key] for key in ("count", "covered")}
                                           for metric in METRICS} for row in measurement["workspace_packages"]}}
    baseline_packages(result, target=collection["target"], names=names)
    if previous is not None:
        previous_names = set(previous.get("packages", {}))
        require(previous_names <= set(names) | set(retired_packages),
                "baseline refresh cannot remove an existing package")
        old = baseline_packages(previous, target=collection["target"], names=previous_names)
        retained = previous_names - set(names)
        for name in sorted(retained):
            result["packages"][name] = old[name]
            names.append(name)
        added = set(names) - previous_names
        if added:
            assignments = policy_packages(policy_definition,
                                          [row["package"] for row in measurement["workspace_packages"]])
            require(all(assignments[name] == "kernel" and all(ratio(result["packages"][name][metric]) == 1
                                                              for metric in METRICS) for name in added),
                    "new baseline packages require a freshly measured complete decision kernel")
            # Admission adds a new measured floor; it does not reset existing
            # floors to this run or claim old counters came from this source.
            result["new_kernel_packages"] = sorted(added)
            evidence_fields = ("source", "coverage_report_sha256", "collection_sha256")
            result["package_provenance"] = {name: {key: result[key] for key in evidence_fields} for name in added}
            for name in previous_names:
                result["packages"][name] = old[name]
                result["package_provenance"][name] = previous.get("package_provenance", {}).get(
                    name, {key: previous[key] for key in evidence_fields})
        else:
            for name in previous_names:
                for metric in METRICS:
                    require(ratio(result["packages"][name][metric]) >= ratio(old[name][metric]),
                            "baseline refresh cannot lower an existing package ratchet")
            if retained:
                fields = ("source", "coverage_report_sha256", "collection_sha256")
                result["package_provenance"] = {
                    name: previous.get("package_provenance", {}).get(name, {key: previous[key] for key in fields})
                    if name in retained else {key: result[key] for key in fields} for name in names}
    baseline_packages(result, target=collection["target"], names=names)
    return result


def punchlist(result):
    lines = [f"Coverage policy: {result['status']} ({result.get('target', 'unqualified target')})"]
    for row in result.get("packages", []):
        values = row["measured"]
        metrics = ", ".join(f"{metric} {values[metric]['covered']}/{values[metric]['count']} ({values[metric]['percent']:.2f}%)"
                            for metric in METRICS)
        gaps = "; ".join(f"{gap['kind']} {gap['metric']}: +{gap['additional_covered']} covered" for gap in row["gaps"])
        lines.append(f"{row['package']} [{row['tier']}] {row['status']}: {metrics}; baseline {row['baseline_status']}" + ("; " + gaps if gaps else ""))
    for failure in result.get("failures", []):
        lines.append(failure)
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--baseline", type=Path, help="existing exact-target ratchet; mandatory for enforcement")
    parser.add_argument("--baseline-reference", help="trusted PR base or push-before full commit SHA; mandatory for enforcement")
    parser.add_argument("--allow-baseline-bootstrap", action="store_true", help="explicitly review first adoption only when the verified base tree has no target baseline")
    parser.add_argument("--canonical-revision", help="export only: reachable commit with exactly the observed source's immutable Git tree")
    parser.add_argument("--write-baseline", action="store_true", help="export fresh validated evidence; existing floors cannot decrease")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.is_symlink() or (args.write_baseline and args.output.exists()):
        # Never overwrite an existing ratchet, even with an error report.
        sys.stderr.write("baseline export requires a fresh output path\n")
        return 2
    try:
        report, report_hash = read(args.report)
        collection, collection_hash = read(args.collection)
        metadata_raw = subprocess.check_output(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--all-features", "--format-version", "1"],
                                               cwd=args.source_root, stderr=subprocess.PIPE, timeout=60)
        metadata = json.loads(metadata_raw)
        measured = llvm.evaluate(report, source_root=args.source_root, required_files=[], minimum_lines=0,
                                 require_branches=True, minimum_branches=0, workspace_metadata=metadata)
        require(measured["status"] == "passed", "structural coverage validation failed")
        source = suite.source_snapshot(args.source_root)
        names = [row["package"] for row in measured["workspace_packages"]]
        validate_collection(collection, report_hash, source=source, names=names, target=args.target)
        if args.write_baseline:
            require(not args.output.exists(), "baseline export requires a fresh output path")
            prior = read(args.baseline)[0] if args.baseline else None
            definition = read(args.policy)[0] if args.policy else None
            retired = verified_retirements(args.source_root, names, prior)
            result = baseline_from_evidence(measured, collection, collection_hash, prior, definition, retired)
            if args.baseline:
                result["previous_baseline_sha256"] = read(args.baseline)[1]
            if args.canonical_revision is not None:
                bind_canonical_revision(args.source_root, result, args.canonical_revision)
            status = 0
        else:
            require(args.canonical_revision is None, "canonical revision is set only during a verified baseline export")
            require(args.policy is not None and args.baseline is not None, "policy and exact-target baseline are mandatory")
            policy, policy_hash = read(args.policy)
            baseline, baseline_hash = None, None
            try:
                baseline, baseline_hash = read(args.baseline)
            except (PolicyError, OSError, ValueError, TypeError):
                pass  # Report every qualified current tier; the unavailable ratchet stays a hard failure.
            require(args.baseline.resolve() == (args.source_root / "config/coverage-baselines" / (args.target + ".json")).resolve(),
                    "enforcement must use the canonical native baseline path")
            history = baseline_history(args.source_root, reference=args.baseline_reference, target=args.target,
                                       allow_bootstrap=args.allow_baseline_bootstrap)
            retired = verified_retirements(args.source_root, names, baseline)
            result = evaluate(measured, policy=policy, baseline=baseline, target=args.target, history=history,
                              retired_packages=retired)
            result.update({"source": source, "collection_sha256": collection_hash, "coverage_report_sha256": report_hash,
                           "policy_sha256": policy_hash, "baseline_sha256": baseline_hash,
                           "workspace_metadata_sha256": sha(metadata_raw)})
            status = {"passed": 0, "failed": 1, "invalid": 2}[result["status"]]
    except (PolicyError, llvm.CoverageError, suite.Invalid) as error:
        result = {"schema": RESULT_SCHEMA, "status": "invalid", "failures": [str(error)]}
        status = 2
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        result = {"schema": RESULT_SCHEMA, "status": "invalid", "failures": ["invalid_or_unreadable_policy_evidence"]}
        status = 2
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    if not args.write_baseline or status:
        sys.stdout.write(punchlist(result))
    return status


if __name__ == "__main__":
    sys.exit(main())
