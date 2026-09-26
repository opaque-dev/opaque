#!/usr/bin/env python3
"""Run the correlation adapter inside a real local AX runner and core SIGKILL example.

No cluster, model, enterprise source, native human ceremony, or live provider.
Only synthetic metadata/effects are used. This is not a full broker RPC adapter.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import adapter

AX_REVISION = "f009cc81c9a571073bc1dd58cd2ed934bf2d5b1c"
CORE = Path(__file__).resolve().parents[2]


def run(command, cwd, log, environment, timeout=300):
    with log.open("xb") as output:
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    if process.returncode:
        raise RuntimeError(f"command failed; inspect {log}")


def persist_or_compare(path: Path, value: object):
    if path.exists():
        if json.loads(path.read_text()) != value:
            raise ValueError("persisted correlation changed; retain the hold")
    else:
        adapter.write_new(path, value)


def inside(output: Path, example: Path, verifier: Path):
    metadata = adapter.fetch_metadata(os.environ["AX_METADATA_URL"])
    atespace, task = adapter.task_identity(metadata)
    assert (atespace, task) == ("synthetic", "opaque-recovery")
    identity = output / "run-id.json"
    if not identity.exists():
        adapter.write_new(identity, {"run_id": str(uuid.uuid4())})
    run_id = adapter.canonical_uuid(json.loads(identity.read_text())["run_id"])
    # Allocate one run ID once, before any attempts. Every logical worker action
    # retains its ID across the producer's crash and subsequent evidence reads.
    values = dict(deployment_id="synthetic-local-ax", run_id=run_id,
                  requester_id="synthetic-requester", scope_id="shared-run",
                  tenant_id="synthetic-tenant", broker_id="synthetic-broker", generation="1",
                  resource="case-1", status="resolved",
                  issuance_round_id="00000000-0000-4000-8000-000000000001")
    contexts = [adapter.bind(metadata, {**values, "action_key": f"worker-{i:02}/action-1"})[0] for i in range(16)]
    request_map = output / "request-ids.json"
    persist_or_compare(request_map, [context["request_id"] for context in contexts])
    public = output / "public-run"
    retained = output / "core-result.json"
    started = output / "producer-started.json"
    recovered = retained.exists()
    if recovered:
        result = json.loads(retained.read_text())
    else:
        if public.exists() or started.exists():
            raise ValueError("prior producer outcome is unresolved; do not rerun it")
        adapter.write_new(started, {"run_id": run_id})
        log = output / "public-reproduction.log"
        run([str(example), str(public), "--request-ids", str(request_map)], output, log, os.environ.copy(), 60)
        result = json.loads(log.read_text().splitlines()[-1])
        adapter.write_new(retained, result)
    assert (result["charged_attempts"], result["unknown"], result["api_accepted"]) == (4, 3, 1)
    assert result["crash"] == "SIGKILL" and result["scope_revoked"]
    reviews = json.loads((public / "review-receipts.json").read_text())
    # The public example creates its own synthetic issuance. Attach the actual
    # resulting round to the exported contexts; it is not part of request identity.
    issuance = reviews[0]["review"]["document"]["round_id"]
    results = []
    arguments = dict(enrollment=public / "producer.json", checkpoint=public / "checkpoint.json",
                     export=public / "scope.json", evidence_binary=verifier,
                     checkpoint_pin=result["checkpoint_sha256"])
    for index, context in enumerate(contexts):
        context["issuance_round_id"] = issuance
        path = output / f"context-{index:02}.json"
        persist_or_compare(path, context)
        inspected = adapter.inspect(SimpleNamespace(context=path, **arguments))
        assert not inspected["retry_authorized"]
        assert inspected["historical_revocation"] is True
        results.append(inspected)
    assert sum(row["execution"] == "unknown" for row in results) == 3
    assert sum(row["execution"] == "api_accepted" for row in results) == 1
    assert sum(row["execution"] == "not_observed" for row in results) == 12
    known = next(i for i, row in enumerate(results) if row["execution"] == "unknown")
    changed = {**contexts[known], "status": "closed"}
    changed_path = output / "changed-context.json"
    persist_or_compare(changed_path, changed)
    try:
        adapter.inspect(SimpleNamespace(context=changed_path, **arguments))
    except ValueError:
        pass
    else:
        raise AssertionError("changed effect was associated with original execution")
    altered = output / "altered-export.json"
    if not altered.exists():
        with altered.open("xb") as file:
            file.write((public / "scope.json").read_bytes() + b" ")
    try:
        adapter.inspect(SimpleNamespace(context=output / f"context-{known:02}.json", **{**arguments, "export": altered}))
    except ValueError:
        pass
    else:
        raise AssertionError("altered scope export was accepted")
    # Required review signatures are verified by the public tool separately.
    reviewed = subprocess.run([str(verifier), "verify-scope-reviews", "--enrollment", str(public / "producer.json"),
        "--checkpoint", str(public / "checkpoint.json"), "--export", str(public / "scope.json"),
        "--receipts", str(public / "review-receipts.json"), "--broker-public-key",
        (public / "review-broker-public-key.txt").read_text(), "--expected-checkpoint-sha256", result["checkpoint_sha256"]],
        capture_output=True, timeout=30, check=True)
    assert json.loads(reviewed.stdout)["review_signatures"] == "verified_historical_bindings"
    return {"result": "passed", "mode": "synthetic_local_ax_runner", "ax_revision": AX_REVISION,
            "actual_ax_metadata": True, "actual_ax_child_command": True,
            "public_core_crash": "SIGKILL", "charged_attempts": 4, "unknown": 3,
            "missing_outcomes_held": 12, "task": task, "atespace": atespace, "run_id": run_id,
            "recovered_existing_run": recovered,
            "checkpoint_sha256": result["checkpoint_sha256"], "actions": results,
            "synthetic_review_signatures_verified": True, "changed_effect_rejected": True,
            "altered_export_rejected": True, "pin_origin": "same_synthetic_run",
            "live_broker_rpc": False, "kubernetes_substrate": False, "native_human_review": False,
            "independent_evaluation": False, "provider_effects": "synthetic_local_files"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ax-source", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--example", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--verifier", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.inside:
        try:
            report = inside(output, args.example, args.verifier)
        except Exception as error:
            adapter.write_new(output / "failed.json", {"result": "failed", "type": type(error).__name__})
            raise
        adapter.write_new(output / "report.pending.json", report)
        (output / "report.pending.json").rename(output / "report.json")
        return
    if args.ax_source is None:
        parser.error("--ax-source must name a clean checkout of the documented AX revision")
    ax = args.ax_source.resolve()
    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(ax), *arguments], text=True).strip()
    if git("rev-parse", "HEAD") != AX_REVISION or git("status", "--porcelain"):
        raise ValueError("AX source must be clean and match the reviewed revision")
    if any((parent / ".git").exists() for parent in (output, *output.parents)):
        raise ValueError("runtime output must remain outside Git")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    allowed = ("PATH", "HOME", "RUSTUP_HOME", "CARGO_HOME", "TMPDIR", "TMP", "TEMP", "CARGO_BUILD_JOBS")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    runner = output / "ax-task-runner"
    # AX's local runner otherwise writes workspace state under /ax. Override its
    # documented test variable at link time; leave the official source untouched.
    # Go's flag splitter accepts a quoted value containing whitespace.
    state = output / "ax-state"
    if '"' in str(state) or "\\" in str(state):
        raise ValueError("output path contains unsupported linker characters")
    linker = f'-X "github.com/google/ax/internal/workspace.AXDir={state}"'
    run(["go", "build", "-ldflags", linker, "-o", str(runner), "./cmd/ax-task-runner"],
        ax, output / "build-ax.log", environment, 600)
    run(["cargo", "build", "--locked", "-p", "opaque", "--bin", "opaque-evidence", "--example", "scope-recovery"],
        CORE, output / "build-core.log", environment, 600)
    binary = CORE / "target/debug"
    workspace = output / "workspace"
    workspace.mkdir(mode=0o700)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    task = {"apiVersion": "ax.io/v1alpha1", "kind": "Task",
            "metadata": {"name": "opaque-recovery", "atespace": "synthetic"},
            "spec": {"debug": False, "workspaces": [{"name": "empty", "path": str(workspace)}],
                     "command": [sys.executable, "-B", str(Path(__file__).resolve()), "--inside", "--output", str(output),
                                 "--example", str(binary / "examples/scope-recovery"),
                                 "--verifier", str(binary / "opaque-evidence")]}}
    task_file = output / "task.yaml"
    task_file.write_text(adapter.yaml.safe_dump(task))
    def launch(iteration):
        log_path = output / f"runner-{iteration}.log"
        with log_path.open("xb") as log:
            process = subprocess.Popen([str(runner), "--port", str(port), "--task-file", str(task_file)],
                                       cwd=workspace, env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = time.monotonic() + 100
                # Report publication precedes Python interpreter shutdown. Wait
                # for AX to observe successful child exit before stopping it.
                while not ((output / "report.json").exists()
                           and "task command completed successfully" in log_path.read_text()):
                    if process.poll() is not None or (output / "failed.json").exists():
                        raise RuntimeError(f"AX child acceptance failed; inspect {output / f'runner-{iteration}.log'}")
                    if time.monotonic() > deadline:
                        raise TimeoutError("AX child acceptance deadline exceeded")
                    time.sleep(0.1)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    launch(1)
    first = json.loads((output / "report.json").read_text())
    if first["recovered_existing_run"]:
        raise AssertionError("first runner did not produce the example")
    preserved = [output / "request-ids.json", output / "public-reproduction.log",
                 output / "producer-started.json", output / "public-run/scope.json",
                 output / "public-run/checkpoint.json"]
    fingerprints = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest() for path in preserved}
    (output / "report.json").rename(output / "first-report.json")
    launch(2)
    report = json.loads((output / "report.json").read_text())
    if report["result"] != "passed" or not report["recovered_existing_run"]:
        raise RuntimeError("AX restart did not recover the existing run")
    for field in ("actions", "run_id", "checkpoint_sha256"):
        if report[field] != first[field]:
            raise AssertionError(f"AX restart changed {field}")
    for path in preserved:
        if hashlib.sha256(path.read_bytes()).hexdigest() != fingerprints[str(path.relative_to(output))]:
            raise AssertionError("AX restart modified existing producer evidence")
    if not state.is_dir() or not list(state.glob("initialized-*")):
        raise AssertionError("AX workspace state was not contained in the selected directory")
    core_revision = subprocess.check_output(["git", "-C", str(CORE), "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(["git", "-C", str(CORE), "status", "--porcelain"], text=True).strip())
    source_paths = [Path(__file__).resolve(), Path(adapter.__file__).resolve(), CORE / "crates/opaque/examples/scope-recovery.rs"]
    qualification = {"result": "passed", "ax_revision": AX_REVISION, "core_revision": core_revision,
                     "core_dirty": dirty, "actual_ax_runner_restart": True, "producer_invocations": 1,
                     "run_identity_preserved": True, "action_evidence_preserved": True,
                     "ax_state_linker_override": str(state), "preserved_file_sha256": fingerprints,
                     "source_sha256": {str(path.relative_to(CORE)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_paths}}
    adapter.write_new(output / "qualification.json", qualification)
    print(json.dumps({"result": "passed", "ax_revision": AX_REVISION, "charged_attempts": 4,
                      "unknown": 3, "missing_outcomes_held": 12, "runner_restart": "same_run_no_producer_replay",
                      "report": str(output / "report.json"), "qualification": str(output / "qualification.json")}, indent=2))


if __name__ == "__main__":
    main()
