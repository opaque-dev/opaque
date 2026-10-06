# What does the coverage gate require?

The coverage gate measures every Cargo workspace package on its native target.
It enforces each crate's tier immediately, together with a line and branch
no-regression check. A passing test count does not establish coverage.

| Tier | Lines | Branches |
| --- | --- | --- |
| Decision kernel | 100% | 100% |
| Enforcement | Ratchet | 85% |
| General | Ratchet | 70% |

The packages assigned to each tier are:

- **Decision kernel:** `opaque-policy-kernel`.
- **Enforcement:** `opaque-core`, `opaque-approval`, `opaque-approve-helper`,
  `opaque-approver`, `opaque-bounded-work`, `opaque-federation-runtime`,
  `opaque-mcp`, `opaque-native-approval`, `opaque-providers`, `opaque-sandbox`,
  `opaque-tenant`, and `opaqued`.
- **General:** `opaque` and `opaque-web`.

The small kernel owns pure policy decisions used by production. It is measured
as its own crate; assigning a broad crate to the kernel tier would not establish
that separation. CLI, dashboard and showcase presentation and setup code use the
general tier. Their shared enforcement components remain in the enforcement tier.
The reviewed classification lives in `config/coverage-policy.json`. A new,
missing, stale or unclassified package fails the gate instead of inheriting a
lower default.

Both lines and branches must also meet or exceed their crate's stored ratio for
the **same operating system and compiler target**, using exact integer ratios.
An improvement in another crate cannot hide a regression. Adding uncovered code
can regress coverage even when the number of covered lines increases. macOS
coverage cannot qualify Linux-only code, and an ARM baseline cannot substitute
for an x86 baseline. A missing baseline is a failure. There is no grandfathered
pass for a crate below its tier, and no additional flat 100% workspace gate.

## Run and inspect the gate

Collect the full native workspace with `scripts/collect_critical_coverage.py`.
Linux collection runs inside the owned disposable host through
`tests/contained-ssh/run.py --coverage`. Keep the selected acceptance commands,
continuous child profiles and their mapping objects. The collector's `collected`
status and its structural `measured` summaries are not a policy pass.

Then use the compiler host reported by `rustc -vV` as `TARGET`. Set `BASE_SHA`
to the full immutable pull request base commit or push-before commit from the
CI event. Fetch that commit and the historical source objects before running;
a missing object or moving branch name is not an acceptable baseline reference:

```sh
python3 -B scripts/check_coverage_policy.py \
  --report "$OUTPUT/llvm-coverage.json" \
  --collection "$OUTPUT/collection.json" \
  --source-root "$SOURCE" \
  --target "$TARGET" \
  --policy config/coverage-policy.json \
  --baseline "$SOURCE/config/coverage-baselines/$TARGET.json" \
  --baseline-reference "$BASE_SHA" \
  --output "$OUTPUT/gate.json"
```

Exit 0 means all tiers and ratchets passed. Exit 1 reports measured coverage
below a tier or a stored ratio. Exit 2 means the evidence, classification or
baseline is invalid or missing. Once current coverage is structurally qualified,
the report retains every crate's exact covered/total counts, tier and additional
covered lines or branch outcomes needed, even if the baseline is unavailable.
Missing floors are explicitly absent; valid same-target floors still compare. A below-target result stays a failure even when all runtime
tests passed.

Source changes, dirty checkouts, failed collections, incomplete package scope,
missing source mappings, missing branch instrumentation, failed killed-child
preflights, missing object/profile inventories and failed instrumented acceptance
commands remain hard failures. The gate binds the LLVM export to the collector's
source snapshot and report hash. It does not accept a different build's test
results as coverage evidence.

## Maintain the ratchet

Versioned baselines contain only integer counters and source/evidence hashes.
They contain no raw logs, private paths, credentials or binaries. A baseline
identifies the exact revision and source tree measured; it is not relabeled as
coverage of a later revision. A hosted PR merge can additionally record a
`canonical_revision` when `--canonical-revision` at export verifies that both
commits have exactly the same immutable Git tree and source fingerprints. The
observed revision stays intact; future checks can read the reachable canonical
content even after the temporary merge object disappears.

After a clean full native collection, export a candidate into a **new** file:

```sh
python3 -B scripts/check_coverage_policy.py \
  --report "$OUTPUT/llvm-coverage.json" \
  --collection "$OUTPUT/collection.json" \
  --source-root "$SOURCE" \
  --target "$TARGET" \
  --policy config/coverage-policy.json \
  --baseline "config/coverage-baselines/$TARGET.json" \
  --write-baseline \
  --output "$OUTPUT/baseline-candidate.json"
```

Review and replace the versioned baseline only after checking its provenance and
all package deltas. Ordinary refresh refuses to lower any existing crate's line
or branch ratio, remove a crate, or overwrite an existing output. Always supply
`--baseline` for a refresh; omitting it is only for the first native baseline.
The export helper's optional previous-file argument does not replace CI's
independent comparison with the trusted base commit.

CI reads every existing native baseline directly from that immutable Git tree.
It rejects candidate files that remove a prior crate or target, lower either
ratio, or claim a predecessor hash different from the actual prior bytes.
Current measurements must also meet the trusted target's floors even if a
proposed file attempts to lower them. Merely editing the same pull request's
baseline cannot make a regression pass.

First adoption requires reviewed source-bound native evidence and the explicit
`--allow-baseline-bootstrap` flag. The gate proves that the target file is absent
from the verified base tree and recomputes the candidate's source fingerprints
from immutable Git objects. An unreadable reference is a failure, not an empty
baseline. Source hashes identify the code; they do not independently authenticate
coverage counters, so review the retained collection and export hashes as well.
CI enables first adoption with these checks and never regenerates baselines to
make its own result pass.

Extracting the decision kernel changes workspace membership and requires fresh
native evidence. The refresh command can add a newly classified kernel only
when its actual measured lines and branches are both complete. During that
admission it retains every existing crate's exact counters and original evidence
identity, then adds the new kernel's counters and fresh evidence. Per-package
provenance records distinguish the two collections. Existing regression or tier
debt still fails the gate; admitting the kernel does not lower those floors or
relabel old measurements. Other package changes require explicit policy and
baseline review.

## Review assertions as well as counters

Coverage shows which mapped code and branch outcomes executed. It does not show
that assertions would detect a wrong decision. Review the production decision
and its oracle together: default denial, first matching rule, invalid budgets,
agent reveal denial and authority boundaries need explicit expected outcomes.
Mutation and property tests should reject widened authority, bypassed review,
replayed effects or refunded logical charges, rather than assert only successful
parsing or lack of a panic.

Fuzzing parser inputs and state properties complements these assertions; its
iterations are not additional unit tests or a proof of every possible history.
Likewise, bounded state-model transitions and repeated stress runs are reported
separately from distinct test cases. Real model generation, native process and
browser evidence keep their declared boundaries: a scripted signed decision is
not a physical human approval ceremony, and controlled protocol peers do not
qualify live vendor accounts.
