import copy
import json
import subprocess
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_coverage_policy as policy


class CoveragePolicyTests(unittest.TestCase):
    def retirement_fixture(self, root, package_name="ui"):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        crate = root / "crates/ui"
        crate.mkdir(parents=True)
        (crate / "Cargo.toml").write_text(f'[package]\nname = "{package_name}"\nversion = "0.1.0"\n')
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "historical crate"], cwd=root, check=True)
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        shutil.rmtree(crate)
        record = {"schema": "opaque.coverage-retirements.v1", "packages": {
            "ui": {"manifest": "crates/ui/Cargo.toml", "revision": revision, "reason": "separate demo"}}}
        (root / "config").mkdir()
        (root / "config/coverage-retirements.json").write_text(json.dumps(record))
        return record

    def test_documented_retirement_requires_absent_source_and_workspace_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.retirement_fixture(root)
            names = {"kernel", "broker"}
            self.assertEqual(policy.verified_retirements(root, names, self.baseline), {"ui"})
            with self.assertRaises(policy.PolicyError):
                policy.verified_retirements(root, names | {"ui"}, self.baseline)
            (root / "crates/ui").mkdir()
            with self.assertRaises(policy.PolicyError):
                policy.verified_retirements(root, names, self.baseline)
            (root / "crates/ui").rmdir()
            (root / "crates/ui").symlink_to(root / "absent")
            with self.assertRaises(policy.PolicyError):
                policy.verified_retirements(root, names, self.baseline)

    def test_retirement_cannot_name_a_foreign_manifest_revision_or_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = self.retirement_fixture(root)
            path = root / "config/coverage-retirements.json"
            for field, value in (("manifest", "../Cargo.toml"), ("revision", "0" * 40), ("reason", "")):
                changed = copy.deepcopy(record)
                changed["packages"]["ui"][field] = value
                path.write_text(json.dumps(changed))
                with self.assertRaises((policy.PolicyError, subprocess.CalledProcessError)):
                    policy.verified_retirements(root, {"kernel", "broker"}, self.baseline)
            path.write_text(json.dumps(record))
            missing = copy.deepcopy(self.baseline)
            del missing["packages"]["ui"]
            with self.assertRaises(policy.PolicyError):
                policy.verified_retirements(root, {"kernel", "broker"}, missing)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.retirement_fixture(root, package_name="different")
            with self.assertRaises(policy.PolicyError):
                policy.verified_retirements(root, {"kernel", "broker"}, self.baseline)

    def test_retirement_retains_floors_provenance_and_remaining_ratchets(self):
        measured = copy.deepcopy(self.measurement)
        measured["workspace_packages"] = [row for row in measured["workspace_packages"] if row["package"] != "ui"]
        definition = copy.deepcopy(self.policy)
        del definition["packages"]["ui"]
        result = policy.evaluate(measured, policy=definition, baseline=self.baseline,
                                 target=self.target, retired_packages={"ui"})
        self.assertEqual(result["status"], "passed")
        self.assertEqual(policy.evaluate(measured, policy=definition, baseline=self.baseline,
                                         target=self.target)["status"], "invalid")
        exported = policy.baseline_from_evidence(measured, self.collection, "5" * 64,
                                                self.baseline, definition, {"ui"})
        self.assertEqual(exported["packages"]["ui"], self.baseline["packages"]["ui"])
        self.assertEqual(exported["package_provenance"]["ui"]["source"], self.baseline["source"])
        measured["workspace_packages"][1]["measured"]["lines"]["covered"] -= 1
        regressed = policy.evaluate(measured, policy=definition, baseline=self.baseline,
                                    target=self.target, retired_packages={"ui"})
        self.assertIn("broker:lines:regressed", regressed["failures"])
        with self.assertRaises(policy.PolicyError):
            policy.baseline_from_evidence(measured, self.collection, "5" * 64,
                                         self.baseline, definition, {"ui"})

    def setUp(self):
        self.target = "aarch64-apple-darwin"
        self.source = {"revision": "1" * 40, "tree_sha256": "2" * 64,
                       "release_tree_sha256": "3" * 64, "dirty": False}
        self.assignments = {"kernel": "kernel", "broker": "enforcement", "ui": "general"}
        self.policy = {"schema": policy.POLICY_SCHEMA, "packages": self.assignments}
        self.metrics = {"kernel": self.metric(100, 100), "broker": self.metric(90, 85), "ui": self.metric(80, 70)}
        self.measurement = {"status": "passed", "failures": [], "measured": {},
                            "workspace_packages": [{"package": name, "measured": metrics}
                                                   for name, metrics in self.metrics.items()]}
        self.collection = {"schema": "opaque.workspace-coverage-collection.v2", "status": "collected",
                           "failures": [], "failed_commands": [], "target": self.target, "platform": "darwin",
                           "source_before": self.source, "source_after": self.source,
                           "coverage_report_sha256": "4" * 64,
                           "coverage_packages": list(self.assignments), "test_collection_packages": list(self.assignments),
                           "toolchain": "nightly-2026-09-13", "feature_selection": "all workspace features; native compiler target",
                           "instrumentation": ["-C", "instrument-coverage", "--cfg=coverage", "--cfg=coverage_nightly", "-Zcoverage-options=branch"],
                           "compiler": ["host: " + self.target], "profile_count": 4, "binary_count": 3,
                           "profiles": [{"path": f"profile-{i}", "sha256": "6" * 64, "bytes": 128} for i in range(4)],
                           "binaries": [{"path": f"binary-{i}", "sha256": "7" * 64, "bytes": 4096} for i in range(3)],
                           "preflight": {"status": "passed", "termination": "SIGKILL", "observed_branch_counts": [1, 0]},
                           "acceptance_executions": [{"status": "passed"}]}
        self.baseline = policy.baseline_from_evidence(self.measurement, self.collection, "5" * 64)

    def metric(self, lines, branches, count=100):
        return {"lines": {"count": count, "covered": lines, "percent": lines * 100 / count},
                "branches": {"count": count, "covered": branches, "percent": branches * 100 / count}}

    def evaluate(self):
        return policy.evaluate(self.measurement, policy=self.policy, baseline=self.baseline, target=self.target)

    def test_exact_tier_boundaries_pass_without_global_one_hundred_requirement(self):
        result = self.evaluate()
        self.assertEqual(result["status"], "passed")
        self.assertEqual([row["package"] for row in result["packages"]], list(self.assignments))
        self.assertNotIn("lines", result["packages"][1]["targets"])

    def test_each_enforcement_and_general_tier_fails_immediately_even_without_regression(self):
        for name, minimum in (("broker", 85), ("ui", 70)):
            with self.subTest(package=name):
                before = copy.deepcopy(self.metrics[name])
                self.metrics[name]["branches"]["covered"] = minimum - 1
                self.baseline["packages"][name]["branches"]["covered"] = minimum - 1
                result = self.evaluate()
                self.assertIn(f"{name}:branches:below_{minimum}_percent", result["failures"])
                row = next(item for item in result["packages"] if item["package"] == name)
                self.assertEqual(row["gaps"], [{"metric": "branches", "kind": "tier_target", "additional_covered": 1}])
                self.metrics[name].update(before)

    def test_one_uncovered_kernel_line_or_branch_fails_even_if_float_rounds_to_one_hundred(self):
        for metric in policy.METRICS:
            with self.subTest(metric=metric):
                old = self.metrics["kernel"][metric]
                self.metrics["kernel"][metric] = {"count": 10**18, "covered": 10**18 - 1, "percent": 100}
                result = self.evaluate()
                self.assertIn(f"kernel:{metric}:below_100_percent", result["failures"])
                self.assertIn(f"kernel:{metric}:regressed", result["failures"])
                self.metrics["kernel"][metric] = old

    def test_ratchet_is_per_crate_not_hidden_by_another_crates_gain(self):
        self.metrics["broker"]["lines"]["covered"] -= 1
        self.metrics["ui"]["lines"]["covered"] += 10
        self.assertIn("broker:lines:regressed", self.evaluate()["failures"])

    def test_ratchet_checks_line_and_branch_ratios_above_tier(self):
        for metric in policy.METRICS:
            self.baseline["packages"]["broker"][metric]["covered"] = 95
        result = self.evaluate()
        self.assertEqual(result["failures"], ["broker:lines:regressed", "broker:branches:regressed"])

    def test_new_uncovered_denominator_fails_even_when_covered_count_increases(self):
        self.metrics["broker"]["branches"].update(count=110, covered=90)
        self.assertIn("broker:branches:regressed", self.evaluate()["failures"])

    def test_exact_ratio_allows_scale_and_covered_code_removal_without_float_tolerance(self):
        self.metrics["broker"]["branches"].update(count=200, covered=170)
        self.assertEqual(self.evaluate()["status"], "passed")
        self.metrics["broker"]["branches"].update(count=20, covered=17)
        self.assertEqual(self.evaluate()["status"], "passed")

    def test_missing_extra_unknown_or_unclassified_package_never_defaults_to_general(self):
        variants = [dict(self.assignments, surprise="general"), {"kernel": "kernel", "broker": "enforcement"},
                    dict(self.assignments, broker="typo"), dict(self.assignments, kernel="general")]
        for assignments in variants:
            with self.subTest(assignments=assignments), self.assertRaises(policy.PolicyError):
                policy.policy_packages({"schema": policy.POLICY_SCHEMA, "packages": assignments}, self.assignments)

    def test_missing_or_new_baseline_package_does_not_become_zero(self):
        for name in ("ui", "old"):
            baseline = copy.deepcopy(self.baseline)
            if name == "ui": del baseline["packages"][name]
            else: baseline["packages"][name] = self.metric(100, 100)
            result = policy.evaluate(self.measurement, policy=self.policy, baseline=baseline, target=self.target)
            self.assertEqual(result["status"], "invalid")
            self.assertEqual(len(result["packages"]), 3)

    def test_native_platform_and_architecture_baselines_cannot_substitute(self):
        for target in ("x86_64-apple-darwin", "aarch64-unknown-linux-gnu"):
            with self.subTest(target=target):
                result = policy.evaluate(self.measurement, policy=self.policy, baseline=self.baseline, target=target)
                self.assertEqual(result["status"], "invalid")
                self.assertEqual(len(result["packages"]), 3)
                self.assertTrue(all(row["baseline"] is None for row in result["packages"]))
                self.assertFalse(any(gap["kind"] == "ratchet" for row in result["packages"] for gap in row["gaps"]))

    def test_zero_branch_or_line_mapping_is_not_one_hundred(self):
        for metric in policy.METRICS:
            old = self.metrics["ui"][metric]
            self.metrics["ui"][metric] = {"count": 0, "covered": 0, "percent": 100}
            with self.assertRaises(policy.PolicyError): self.evaluate()
            self.metrics["ui"][metric] = old

    def test_invalid_counts_or_missing_baseline_provenance_fail_closed(self):
        for value in (True, -1, "100", float("nan"), 101):
            changed = copy.deepcopy(self.baseline)
            changed["packages"]["kernel"]["lines"]["covered"] = value
            with self.assertRaises((policy.PolicyError, policy.llvm.CoverageError)):
                policy.baseline_packages(changed, target=self.target, names=self.assignments)
        for key in ("source", "coverage_report_sha256", "collection_sha256", "toolchain"):
            changed = copy.deepcopy(self.baseline); del changed[key]
            with self.assertRaises(policy.PolicyError): policy.baseline_packages(changed, target=self.target, names=self.assignments)

    def test_structural_failures_remain_hard(self):
        self.measurement.update(status="failed", failures=["required_source_missing_from_report"])
        with self.assertRaises(policy.PolicyError): self.evaluate()

    def test_collection_binds_exact_hash_revision_source_and_complete_workspace(self):
        def validate(value):
            policy.validate_collection(value, "4" * 64, source=self.source, names=self.assignments, target=self.target)
        validate(self.collection)
        variants = []
        for key, value in (("status", "failed"), ("failed_commands", [{}]), ("coverage_report_sha256", "0" * 64),
                           ("source_after", {**self.source, "dirty": True}), ("coverage_packages", ["kernel"]),
                           ("profile_count", 0), ("compiler", ["host: x86_64-apple-darwin"]),
                           ("instrumentation", ["instrument-coverage"]), ("profiles", []), ("preflight", {}),
                           ("acceptance_executions", [{"status": "failed"}]), ("test_collection_packages", list(self.assignments) * 2)):
            changed = copy.deepcopy(self.collection); changed[key] = value; variants.append(changed)
        for value in variants:
            with self.assertRaises(policy.PolicyError): validate(value)

    def test_baseline_export_has_only_metrics_and_public_provenance(self):
        self.collection["private_log"] = "/private/credential-bearing-output"
        self.collection["source_before"]["private_path"] = "/private/root"
        baseline = policy.baseline_from_evidence(self.measurement, self.collection, "5" * 64)
        encoded = json.dumps(baseline)
        self.assertNotIn("private", encoded)
        self.assertNotIn("percent", encoded)
        self.assertEqual(set(baseline["packages"]), set(self.assignments))

    def test_baseline_refresh_refuses_lowering_floor(self):
        self.metrics["ui"]["lines"]["covered"] -= 1
        with self.assertRaisesRegex(policy.PolicyError, "cannot lower"):
            policy.baseline_from_evidence(self.measurement, self.collection, "5" * 64, self.baseline)

    def test_missing_branch_baseline_does_not_disable_ratchet(self):
        del self.baseline["packages"]["ui"]["branches"]
        result = self.evaluate()
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["packages"][2]["baseline"], None)
        self.assertEqual(result["packages"][1]["baseline_status"], "passed")

    def test_punchlist_names_every_crate_and_exact_gap_without_raw_logs(self):
        self.metrics["ui"]["branches"]["covered"] = 69
        text = policy.punchlist(self.evaluate())
        for name in self.assignments: self.assertIn(name + " [", text)
        self.assertIn("tier_target branches: +1 covered", text)
        self.assertIn("ratchet branches: +1 covered", text)

    def test_existing_baseline_output_is_never_overwritten_even_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_bytes(b"existing ratchet")
            status = policy.main(["--report", "missing", "--collection", "missing", "--source-root", directory,
                                  "--target", self.target, "--write-baseline", "--output", str(path)])
            self.assertEqual(status, 2)
            self.assertEqual(path.read_bytes(), b"existing ratchet")

    def test_new_kernel_baseline_requires_fresh_full_coverage_without_lowering_existing_floors(self):
        previous = copy.deepcopy(self.baseline)
        del previous["packages"]["kernel"]
        result = policy.baseline_from_evidence(self.measurement, self.collection, "5" * 64, previous, self.policy)
        self.assertEqual(result["new_kernel_packages"], ["kernel"])
        self.assertEqual(result["source"], self.baseline["source"])
        self.metrics["kernel"]["branches"]["covered"] = 99
        with self.assertRaises(policy.PolicyError):
            policy.baseline_from_evidence(self.measurement, self.collection, "5" * 64, previous, self.policy)
        self.metrics["kernel"]["branches"]["covered"] = 100
        self.metrics["broker"]["branches"]["covered"] -= 1
        result = policy.baseline_from_evidence(self.measurement, self.collection, "5" * 64, previous, self.policy)
        self.assertEqual(result["packages"]["broker"], previous["packages"]["broker"])
        debt = policy.evaluate(self.measurement, policy=self.policy, baseline=result, target=self.target)
        self.assertIn("broker:branches:regressed", debt["failures"])

    def test_kernel_admission_retains_each_old_floor_and_its_original_evidence(self):
        previous = copy.deepcopy(self.baseline)
        del previous["packages"]["kernel"]
        original = copy.deepcopy(previous)
        fresh = copy.deepcopy(self.collection)
        fresh["source_before"]["revision"] = "f" * 40
        fresh["coverage_report_sha256"] = "e" * 64
        self.metrics["broker"]["lines"]["covered"] = 70
        result = policy.baseline_from_evidence(self.measurement, fresh, "d" * 64, previous, self.policy)
        self.assertEqual(previous, original)
        for name in previous["packages"]:
            self.assertEqual(result["packages"][name], previous["packages"][name])
            self.assertEqual(result["package_provenance"][name]["source"], previous["source"])
            self.assertEqual(result["package_provenance"][name]["collection_sha256"], previous["collection_sha256"])
        self.assertEqual(result["package_provenance"]["kernel"]["source"]["revision"], "f" * 40)
        self.assertEqual(result["package_provenance"]["kernel"]["coverage_report_sha256"], "e" * 64)
        self.assertEqual(result["package_provenance"]["kernel"]["collection_sha256"], "d" * 64)
        self.assertIn("broker:lines:regressed", policy.evaluate(self.measurement, policy=self.policy,
                                                              baseline=result, target=self.target)["failures"])

    def test_package_removal_and_new_general_crate_cannot_reset_membership_ratchet(self):
        previous = copy.deepcopy(self.baseline)
        previous["packages"]["removed"] = self.metric(100, 100)
        with self.assertRaises(policy.PolicyError):
            policy.baseline_from_evidence(self.measurement, self.collection, "5" * 64, previous, self.policy)
        previous = copy.deepcopy(self.baseline)
        del previous["packages"]["ui"]
        self.metrics["ui"].update(self.metric(100, 100))
        with self.assertRaises(policy.PolicyError):
            policy.baseline_from_evidence(self.measurement, self.collection, "5" * 64, previous, self.policy)

    def test_cli_binds_real_input_files_and_reports_tier_debt_without_global_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            packages, files = [], []
            for name, metrics in self.metrics.items():
                crate = root / name
                (crate / "src").mkdir(parents=True)
                (crate / "Cargo.toml").write_text(f'[package]\nname="{name}"\nversion="0.1.0"\n')
                source = crate / "src/lib.rs"
                source.write_text("pub fn decide() {}\n")
                packages.append({"id": name, "name": name, "manifest_path": str(crate / "Cargo.toml"),
                                 "targets": [{"kind": ["lib"], "src_path": str(source)}]})
                files.append({"filename": str(source), "summary": metrics})
            self.metrics["ui"]["branches"]["covered"] = 69
            totals = {metric: {key: sum(item["summary"][metric][key] for item in files)
                               for key in ("count", "covered")} for metric in policy.METRICS}
            report = {"type": "llvm.coverage.json.export", "data": [{"files": files, "totals": totals}]}
            raw = json.dumps(report).encode()
            (root / "llvm.json").write_bytes(raw)
            self.collection["coverage_report_sha256"] = policy.sha(raw)
            baseline_path = root / "config/coverage-baselines" / (self.target + ".json")
            baseline_path.parent.mkdir(parents=True)
            baseline_path.write_text(json.dumps(self.baseline))
            for name, value in (("collection", self.collection), ("policy", self.policy)):
                (root / (name + ".json")).write_text(json.dumps(value))
            metadata = {"workspace_members": list(self.assignments), "packages": packages}
            with patch.object(policy.subprocess, "check_output", return_value=json.dumps(metadata).encode()), \
                    patch.object(policy.suite, "source_snapshot", return_value=self.source), \
                    patch.object(policy, "baseline_history", return_value={"status": "passed", "failures": [], "packages": {}}):
                status = policy.main(["--report", str(root / "llvm.json"), "--collection", str(root / "collection.json"),
                                      "--source-root", str(root), "--target", self.target, "--policy", str(root / "policy.json"),
                                      "--baseline", str(baseline_path), "--output", str(root / "gate.json")])
                result = json.loads((root / "gate.json").read_text())
                baseline_path.unlink()
                missing_status = policy.main(["--report", str(root / "llvm.json"), "--collection", str(root / "collection.json"),
                                              "--source-root", str(root), "--target", self.target, "--policy", str(root / "policy.json"),
                                              "--baseline", str(baseline_path), "--output", str(root / "missing-gate.json")])
                missing = json.loads((root / "missing-gate.json").read_text())
                self.assertEqual(missing_status, 2)
                self.assertEqual(len(missing["packages"]), 3)
                self.assertEqual(missing["baseline_status"]["status"], "missing")
                self.assertIn("ui:branches:below_70_percent", missing["failures"])
                self.assertTrue(all(row["baseline"] is None for row in missing["packages"]))
            self.assertEqual(status, 1)
            self.assertEqual(len(result["packages"]), 3)
            self.assertEqual(result["failures"], ["ui:branches:below_70_percent", "ui:branches:regressed"])
            self.assertEqual(result["coverage_report_sha256"], policy.sha(raw))

    def test_missing_kernel_baseline_keeps_all_sixteen_tiers_and_fifteen_ratchets(self):
        names = ["kernel"] + [f"broker_{i}" for i in range(15)]
        measurements = {name: self.metric(90, 80) for name in names}
        definition = {"schema": policy.POLICY_SCHEMA,
                      "packages": {name: "kernel" if name == "kernel" else "enforcement" for name in names}}
        measured = {**self.measurement, "workspace_packages": [{"package": name, "measured": value}
                                                               for name, value in measurements.items()]}
        baseline = {**self.baseline, "packages": {name: self.metric(95, 85) for name in names if name != "kernel"}}
        result = policy.evaluate(measured, policy=definition, baseline=baseline, target=self.target)
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(len(result["packages"]), 16)
        self.assertIsNone(result["packages"][0]["baseline"])
        self.assertEqual(sum(row["baseline_status"] == "passed" for row in result["packages"]), 15)
        self.assertEqual(sum(gap["kind"] == "ratchet" for row in result["packages"] for gap in row["gaps"]), 30)
        self.assertEqual(sum(gap["kind"] == "tier_target" for row in result["packages"] for gap in row["gaps"]), 17)

    def test_absent_or_wrong_target_baseline_still_reports_current_tier_debt(self):
        self.metrics["ui"]["branches"]["covered"] = 60
        for baseline in (None, {**self.baseline, "target": "x86_64-apple-darwin"}):
            result = policy.evaluate(self.measurement, policy=self.policy, baseline=baseline, target=self.target)
            self.assertEqual(result["status"], "invalid")
            self.assertEqual(len(result["packages"]), 3)
            self.assertIn("ui:branches:below_70_percent", result["failures"])
            self.assertTrue(all(row["baseline"] is None for row in result["packages"]))

    def repository(self, *, with_baseline=True):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE)
        git("init", "-q")
        git("config", "user.email", "fixture@example.invalid")
        git("config", "user.name", "Coverage Fixture")
        (root / "source.rs").write_text("pub fn fixture() {}\n")
        git("add", "source.rs"); git("commit", "-qm", "Source fixture")
        source = policy.suite.source_snapshot(root)
        baseline = copy.deepcopy(self.baseline)
        baseline["source"] = {key: source[key] for key in ("revision", "tree_sha256", "release_tree_sha256")}
        path = root / "config/coverage-baselines" / (self.target + ".json")
        path.parent.mkdir(parents=True)
        if with_baseline:
            path.write_text(json.dumps(baseline))
            git("add", "config"); git("commit", "-qm", "Initial reviewed native floor")
        return root, git("rev-parse", "HEAD").decode().strip(), path, baseline

    def test_trusted_base_rejects_lowered_candidate_and_directly_checks_current_floor(self):
        root, reference, path, baseline = self.repository()
        baseline["packages"]["broker"]["branches"]["covered"] = 80
        path.write_text(json.dumps(baseline))
        history = policy.baseline_history(root, reference=reference, target=self.target)
        self.assertEqual(history["status"], "failed")
        self.metrics["broker"]["branches"]["covered"] = 84
        result = policy.evaluate(self.measurement, policy=self.policy, baseline=baseline,
                                 target=self.target, history=history)
        self.assertIn("broker:branches:regressed_from_trusted_base", result["failures"])
        self.assertEqual(result["packages"][1]["trusted_baseline"]["branches"]["covered"], 85)

    def test_ninety_five_to_ninety_cannot_pass_by_lowering_same_pr_baseline(self):
        root, reference, path, baseline = self.repository()
        baseline["packages"]["broker"]["branches"]["covered"] = 95
        path.write_text(json.dumps(baseline))
        subprocess.check_call(["git", "add", "config"], cwd=root, stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "commit", "-qm", "Higher reviewed floor"], cwd=root)
        reference = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
        baseline["packages"]["broker"]["branches"]["covered"] = 90
        path.write_text(json.dumps(baseline))
        self.metrics["broker"]["branches"]["covered"] = 90
        history = policy.baseline_history(root, reference=reference, target=self.target)
        result = policy.evaluate(self.measurement, policy=self.policy, baseline=baseline, target=self.target, history=history)
        self.assertEqual(result["status"], "invalid")
        self.assertNotIn("broker:branches:below_85_percent", result["failures"])
        self.assertIn("broker:branches:regressed_from_trusted_base", result["failures"])

    def test_trusted_ratios_allow_rescaling_but_not_denominator_growth(self):
        root, reference, path, baseline = self.repository()
        baseline["packages"]["broker"]["branches"].update(covered=170, count=200)
        path.write_text(json.dumps(baseline))
        self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target)["status"], "passed")
        baseline["packages"]["broker"]["branches"]["count"] = 201
        path.write_text(json.dumps(baseline))
        self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target)["status"], "failed")

    def test_removed_or_wrong_target_candidate_is_not_a_new_baseline(self):
        root, reference, path, baseline = self.repository()
        for candidate in ({**baseline, "packages": {"kernel": baseline["packages"]["kernel"]}},
                          {**baseline, "target": "x86_64-apple-darwin"}):
            path.write_text(json.dumps(candidate))
            self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target,
                                                    allow_bootstrap=True)["status"], "failed")
        path.unlink()
        self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target,
                                                allow_bootstrap=True)["status"], "failed")

    def test_missing_truncated_or_mutable_git_reference_never_becomes_bootstrap(self):
        root, reference, path, baseline = self.repository(with_baseline=False)
        path.write_text(json.dumps(baseline))
        for candidate in (None, "main", reference[:12], "0" * 40, "f" * 40):
            history = policy.baseline_history(root, reference=candidate, target=self.target, allow_bootstrap=True)
            self.assertEqual(history["status"], "invalid")
            self.assertEqual(history["packages"], {})

    def test_bootstrap_requires_verified_absence_explicit_review_and_exact_git_source(self):
        root, reference, path, baseline = self.repository(with_baseline=False)
        path.write_text(json.dumps(baseline))
        self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target)["status"], "failed")
        history = policy.baseline_history(root, reference=reference, target=self.target, allow_bootstrap=True)
        self.assertEqual(history["status"], "passed")
        self.assertEqual(history["targets"][self.target]["status"], "bootstrap_source_verified")
        baseline["source"]["tree_sha256"] = "a" * 64
        path.write_text(json.dumps(baseline))
        self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target,
                                                allow_bootstrap=True)["status"], "failed")

    def test_changed_candidate_predecessor_hash_must_match_trusted_bytes(self):
        root, reference, path, baseline = self.repository()
        old_hash = policy.sha(path.read_bytes())
        baseline["previous_baseline_sha256"] = "a" * 64
        path.write_text(json.dumps(baseline))
        self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target)["status"], "failed")
        baseline["previous_baseline_sha256"] = old_hash
        path.write_text(json.dumps(baseline))
        self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target)["status"], "passed")

    def test_other_native_target_floors_cannot_be_removed_by_this_target_job(self):
        root, reference, path, baseline = self.repository()
        foreign = copy.deepcopy(baseline)
        foreign.update(target="x86_64-apple-darwin")
        other = path.with_name("x86_64-apple-darwin.json")
        other.write_text(json.dumps(foreign))
        subprocess.check_call(["git", "add", "config"], cwd=root, stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "commit", "-qm", "Other native baseline"], cwd=root)
        reference = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
        other.unlink()
        history = policy.baseline_history(root, reference=reference, target=self.target)
        self.assertEqual(history["status"], "failed")
        self.assertIn("x86_64-apple-darwin:baseline_history:invalid_or_lowered_candidate", history["failures"])

    def test_unavailable_observed_merge_uses_matching_canonical_source_without_relabeling(self):
        root, reference, path, baseline = self.repository(with_baseline=False)
        canonical = baseline["source"]["revision"]
        baseline["source"].update(revision="f" * 40, canonical_revision=canonical)
        path.write_text(json.dumps(baseline))
        history = policy.baseline_history(root, reference=reference, target=self.target, allow_bootstrap=True)
        self.assertEqual(history["status"], "passed")
        self.assertEqual(json.loads(path.read_text())["source"]["revision"], "f" * 40)
        (root / "source.rs").write_text("pub fn different_decision() {}\n")
        subprocess.check_call(["git", "add", "source.rs"], cwd=root)
        subprocess.check_call(["git", "commit", "-qm", "Different source"], cwd=root)
        wrong = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
        baseline["source"]["canonical_revision"] = wrong
        path.write_text(json.dumps(baseline))
        self.assertEqual(policy.baseline_history(root, reference=reference, target=self.target,
                                                allow_bootstrap=True)["status"], "failed")

    def test_canonical_export_requires_both_observed_and_equivalent_immutable_trees(self):
        root, reference, path, baseline = self.repository(with_baseline=False)
        original = baseline["source"]["revision"]
        subprocess.check_call(["git", "commit", "--allow-empty", "-qm", "Same tree new commit"], cwd=root)
        equivalent = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
        policy.bind_canonical_revision(root, baseline, equivalent)
        self.assertEqual(baseline["source"]["revision"], original)
        self.assertEqual(baseline["source"]["canonical_revision"], equivalent)
        (root / "source.rs").write_text("pub fn changed_decision() {}\n")
        subprocess.check_call(["git", "add", "source.rs"], cwd=root)
        subprocess.check_call(["git", "commit", "-qm", "Different tree"], cwd=root)
        different = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
        with self.assertRaises(policy.PolicyError): policy.bind_canonical_revision(root, baseline, different)
        baseline["source"]["revision"] = "f" * 40
        with self.assertRaises(policy.PolicyError): policy.bind_canonical_revision(root, baseline, equivalent)

    def test_duplicate_json_keys_cannot_reclassify_a_package_or_lower_a_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"packages":{"broker":"enforcement","broker":"general"}}')
            with self.assertRaisesRegex(policy.PolicyError, "duplicate JSON"):
                policy.read(path)

    def test_policy_read_rejects_symlink_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actual.json"
            path.write_text(json.dumps(self.policy))
            alias = path.with_name("alias.json")
            alias.symlink_to(path)
            with self.assertRaises(policy.PolicyError): policy.read(alias)


if __name__ == "__main__":
    unittest.main()
