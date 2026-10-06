# Native coverage baselines

Each `<rustc-host>.json` contains reviewed integer line and branch counters for
that exact native target, with source, LLVM export and collection hashes. Missing
files fail CI. No baseline is inferred from a different platform or architecture.

Use the baseline export and review procedure in
[the coverage guide](../../docs/testing-coverage.md). Never lower or regenerate a
baseline just to make a failing change pass. Raw evidence stays outside Git.

CI also compares every candidate against the same target's file in the immutable
pull request base or push-before commit. Initial adoption is explicit and must
prove the verified base tree had no such file. Kernel admission can preserve
older floors alongside fresh kernel evidence using per-package provenance; it
does not relabel old counters or forgive a measured regression.

Whole-crate retirement is recorded in `../coverage-retirements.json`. The gate
verifies the named historical manifest at an ancestor commit, requires the
package to be absent from the current workspace and its entire source directory
to be removed, and retains its historical counters and provenance. Undeclared
removals still fail. Maintained crates retain their native ratchets and tiers;
a retirement cannot exempt an active package or reset a floor.
