#!/usr/bin/env python3
"""Run the public synthetic crash reproduction and verify it in a separate CLI.

No private source, external services or native human ceremony. Generated state
must stay outside Git. Both executables must come from the same selected source.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess


def run(command: list[str], expect_success: bool = True) -> str:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise RuntimeError("reproduction command exceeded 60 seconds") from None
    if (process.returncode == 0) != expect_success:
        raise RuntimeError(f"unexpected command result ({process.returncode}): {stderr}")
    return stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example-bin", type=Path, required=True)
    parser.add_argument("--evidence-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    example = str(args.example_bin.resolve(strict=True))
    verifier = str(args.evidence_bin.resolve(strict=True))
    output = args.output.absolute()
    if output.exists():
        raise SystemExit("output must be a new directory")
    transcript = run([example, str(output)])
    print(transcript, end="")
    result = json.loads(transcript.splitlines()[-1])
    expected = {"synthetic": True, "charged_attempts": 4, "unknown": 3,
                "api_accepted": 1, "scope_revoked": True, "crash": "SIGKILL",
                "human_presence": "not_exercised", "corruption_rejected": True}
    if any(result.get(key) != value for key, value in expected.items()):
        raise RuntimeError("reproduction did not establish the required outcomes")
    command = [verifier, "verify-scope-reviews", "--enrollment", str(output / "producer.json"),
               "--checkpoint", str(output / "checkpoint.json"), "--export", str(output / "scope.json"),
               "--receipts", str(output / "review-receipts.json"), "--broker-public-key",
               (output / "review-broker-public-key.txt").read_text(),
               "--expected-checkpoint-sha256", result["checkpoint_sha256"]]
    verification = json.loads(run(command))
    if verification.get("ok") is not True or verification.get("review_signatures") != "verified_historical_bindings":
        raise RuntimeError("independent CLI did not verify retained review bindings")
    # Keep the original artifacts intact. A forged receipt must fail through the
    # actual CLI, even when the scope export itself remains authentic.
    receipts = json.loads((output / "review-receipts.json").read_text())
    receipts[0]["response"]["signature"] = "0" * 128
    tampered = output / "tampered-receipts.json"
    with tampered.open("x") as destination:
        os.chmod(tampered, 0o600)
        json.dump(receipts, destination)
    command[command.index("--receipts") + 1] = str(tampered)
    run(command, expect_success=False)
    # Invalid external correlation must fail before creating an output directory
    # or starting the producer. Exercise the actual example, including a FIFO.
    invalid = output / "invalid-request-ids.json"
    refused_output = output / "refused-run"
    for value in (["duplicate"] * 16, ["only-one"], ["x" * 129] * 16):
        invalid.write_text(json.dumps(value))
        run([example, str(refused_output), "--request-ids", str(invalid)], expect_success=False)
        if refused_output.exists():
            raise RuntimeError("invalid request IDs created producer state")
    invalid.write_bytes(b" " * 16385)
    run([example, str(refused_output), "--request-ids", str(invalid)], expect_success=False)
    fifo = output / "invalid-request-ids.fifo"
    os.mkfifo(fifo, 0o600)
    run([example, str(refused_output), "--request-ids", str(fifo)], expect_success=False)
    if refused_output.exists():
        raise RuntimeError("invalid request IDs created producer state")
    print(json.dumps({"synthetic": True, "separate_cli_verification": "passed",
                      "forged_review_rejected": True, "invalid_correlation_refused_before_execution": True,
                      "checkpoint_sha256": result["checkpoint_sha256"]}))


if __name__ == "__main__":
    main()
