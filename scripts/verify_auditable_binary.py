#!/usr/bin/env python3
"""Require embedded cargo-auditable data in every final release binary.

Use direct, bounded extraction, with no advisory database or guessed dependencies.
Vulnerability policy remains the separate cargo-deny gate. Downstream users can
inspect the same embedded data and advisory matches with `cargo audit bin`.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

import release_artifacts as release


def check_binary(path):
    """Return (ok, message) for one release binary."""
    if not path.is_file():
        return False, f"{path.name}: no such file at {path}"
    try:
        result = subprocess.run(
            ["rust-audit-info", str(path), str(256 * 1024 * 1024), str(8 * 1024 * 1024)],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        return False, f"{path.name}: `rust-audit-info` is not installed (cargo install rust-audit-info)"
    except subprocess.TimeoutExpired:
        return False, f"{path.name}: dependency manifest extraction timed out"
    if result.returncode != 0:
        detail = (result.stderr or "extraction failed").strip()
        return False, f"{path.name}: no embedded dependency manifest found ({detail})"
    try:
        report = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        detail = (result.stderr or result.stdout or "no output").strip()
        return False, (f"{path.name}: no embedded dependency manifest found "
                        f"-- was it built with `cargo auditable build`? ({detail})")
    if (not isinstance(report, dict) or not isinstance(report.get("packages"), list)
            or not report["packages"] or not all(isinstance(package, dict) for package in report["packages"])
            or sum(package.get("root") is True for package in report["packages"]) != 1):
        return False, f"{path.name}: invalid embedded dependency manifest"
    return True, f"{path.name}: embedded dependency manifest present"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--bin", action="append", dest="bins", default=None,
                         help="binary name to check (repeatable); default is every release binary")
    args = parser.parse_args()
    bins = args.bins or list(release.BINS)
    if args.bins is None and (args.binary_dir / release.APP).exists():
        bins.extend(f"{release.APP}/Contents/MacOS/{name}"
                    for name in ("opaque-approver", "opaque-approve-helper"))
    results = [(name, *check_binary(args.binary_dir / name)) for name in bins]
    failed = [(name, message) for name, ok, message in results if not ok]
    for name, ok, message in results:
        print(message, file=sys.stdout if ok else sys.stderr)
    if failed:
        parser.exit(1, f"verify-auditable-binary: {len(failed)} of {len(results)} binaries are missing embedded dependency data\n")
    print(json.dumps({"checked": [name for name, _, _ in results]}, sort_keys=True))


if __name__ == "__main__":
    main()
