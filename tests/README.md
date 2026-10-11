# Automated acceptance and coverage

Run the declared protocol scenarios without a person at the keyboard:

```sh
python3 -B scripts/synthesized_suite.py --profile protocol \
  --target-dir /tmp/opaque-protocol-target --output /tmp/opaque-protocol-run
```

Output directories must be new and outside the checkout. The manifest in
`tests/synthesized-suite.json` names the exact tests and prerequisites. A missing
test, unavailable prerequisite, unexpected ignore, timeout or changed source
tree fails the run. The Linux composed-review cases require root and
`CAP_SYS_PTRACE`; use an isolated Linux runner for those cases.

The contained profile runs real Vault, OpenSSH and systemd in one disposable
Linux Docker host, with separate broker and caller UIDs. It generates temporary
keys, signs one-use SSH certificates, checks host receipts and replay denial,
and exercises crash recovery. The wrapper builds its image, starts only its
owned container and removes it after the run:

```sh
python3 -B tests/contained-ssh/run.py --output /tmp/opaque-contained-run
```

Docker must support privileged systemd containers. Services use literal
loopback addresses inside that host; the profile does not test inter-host
network isolation. The signed OIDC issuer, scripted reviewer and HTTP inference
responses are explicit test implementations. They test the production protocols;
actual model completions and native human approval remain separate qualifications.

## Broker power cut across two machines

A NixOS test boots two VMs. `workstation` runs `opaqued` from the
[NixOS module](../nix/module.nix) under the enforced trust-domain split, with
an `agent` account in the client group and an `outsider` account outside it.
`provider` runs a synthetic MCP upstream that durably records each effect
before answering:

```sh
nix build -L .#checks.x86_64-linux.power-cut
```

Background writeback is disabled on `workstation`
(`vm.dirty_writeback_centisecs = 0`), so after the power cut only data that
something fsynced survives, however long the VM ran first. The test checks
the client-group socket surface and custody file modes, then
runs one completed MCP call as a positive control. A second call is held at the
provider after its effect is recorded, and the workstation loses power
(`crash()`: no shutdown, so unwritten guest page cache is lost, unlike
SIGKILL). After the reboot, the held call's receipt must read `unknown` /
`interrupted` with the attempt charged, a retry must be refused, the first
receipt must still read `accepted`, and the provider must have seen exactly two
effects.

The MCP gateway's insecure fixture mode only dials `127.0.0.1`, so a loopback
forwarder carries the broker's traffic to `provider`, and iptables owner rules
let only the broker's uid use it. Those rules are a deployment pattern under
test, not something opaque installs or enforces. Approval is the insecure test
backend; native human approval and production MCP custody are not exercised.

CI runs this with KVM (`.github/workflows/nix-machine-tests.yml`) and fails if
`/dev/kvm` is missing. On Apple Silicon without a Linux builder, a privileged
`nixos/nix` Docker container can build `checks.aarch64-linux.power-cut` after
adding `sandbox = false` and `system-features = nixos-test kvm big-parallel`
to its `/etc/nix/nix.conf`. QEMU then falls back to software emulation and the
test script takes about five minutes after the build.

## Actual model and browser acceptance

The model profile adds a pinned CPU llama.cpp build and a checksum-verified
SmolLM2 model to the disposable host:

```sh
python3 -B tests/contained-ssh/run.py --real-model --output /tmp/opaque-model-run
```

It checks signed rejection before generation, then actual completions after
scripted signed approval, the model server's generation counter, durable
receipts and replay denial. The service verifies its executable/model hashes
before and after the run and must stop and reap its process group. This qualifies
the pinned engine's bounded response contract on fixed public prompts; it does
not measure model answer quality or native human authentication.

[Browser acceptance](browser/README.md) drives real Chromium, dashboard and daemon
processes without HTTP route mocks. [Installed-artifact acceptance](packaged/README.md)
uses actual compiled tools and the installer in temporary homes. These remain
separate from published-release signatures and platform distribution approval.

## Collect production coverage

The collector discovers every Cargo workspace package, including binary-only
packages and members excluded from Cargo's default member list. It executes
workspace tests and additional daemon task, resource-authority, provisioning,
MCP and composed-review scenarios. It builds
the daemon, adapter and bare-rustc peer with the same pinned instrumentation,
requires fresh child profiles, and verifies that branch counters survive a real
SIGKILL before collecting any results. It preserves crash behavior in the tests.
Coverage builds omit DWARF debug symbols while retaining LLVM source and branch
maps. This keeps the real executable-hashing checks within existing test
deadlines without skipping identity checks or stripping coverage objects.

On macOS, install the pinned tools and run the native collector:

```sh
rustup toolchain install nightly-2026-09-13 --profile minimal --component llvm-tools-preview
cargo +1.95.0 install cargo-llvm-cov --version 0.9.1 --locked
python3 -B scripts/collect_critical_coverage.py \
  --target-dir /tmp/opaque-coverage-target --output /tmp/opaque-coverage-run
```

On Linux, the contained wrapper installs the same tools and collects both the
existing scenarios and contained cases:

```sh
python3 -B tests/contained-ssh/run.py --coverage --output /tmp/opaque-contained-coverage
```

An optional existing `--registry-cache` or `--target-cache` Docker volume can
reduce repeated build time. Do not share a target cache with an active build.
The native collector accepts `--reuse-target-dir` for the same purpose. Neither
option reuses coverage profiles.

The production source scope is the entire Cargo workspace, with a package,
target and source-file inventory derived from Cargo metadata. A newly added
workspace package enters collection automatically. Missing eligible package
artifacts or coverage cannot silently narrow the report.
`original-scope-summary.json` preserves the original three-package scope only
for historical comparison, using the same run's counters. Rust coverage does
not measure JavaScript or Python. Test-only modules remain
excluded through compiler coverage annotations; production functions they call
remain instrumented. Unmapped source files are listed explicitly. Library-only
and expanded exports retain separate denominators because additional daemon
objects can introduce additional production generic instantiations.

Each `collection.json` records the source revision and content fingerprint,
compiler target, exact test inventory, binary/profile hashes, measured counts
and collection failures. `status: collected` means the collection completed;
it does **not** mean the coverage target passed. The separate
`coverage-summary.json` records structural validation and measured counts.
The separate `gate.json` enforces all 16 crates' immediate tiers and exact native
line/branch ratchets: 100% lines and branches for the decision kernel, 85% branches
for enforcement crates and 70% branches for general crates. See the
[coverage and assertion guide](../docs/testing-coverage.md) for classification,
trusted-base comparisons and baseline maintenance. Reports must not be averaged:
one target cannot cover code compiled out on another. Independent Cargo metadata
and source mapping checks still fail any omitted package; per-package counters
expose each crate's remaining gaps.

Raw command logs and runtime artifacts stay in local output. CI publishes only
the collection inventory and sanitized coverage reports, never generated keys,
credentials or raw service logs.

## State evidence

The suite checks durable single-use consumption, retained charges after unknown
outcomes, replay denial after restart, authority changes before dispatch, and
corrupt-row rejection. The finite TaskStore model explores its declared bounded
state space; explicit concurrency and fault scenarios cover other cases.
The original one-slot model retains its fixed bounds. A separate two-slot model
checks 720 declared interleavings, and actual concurrent runs are compared with
permitted serial histories. Killed SQLite writers exercise committed and
uncommitted recovery; SQLite READONLY/FULL cases check atomic rollback and a
positive write control after the limit is restored. These do not exhaust
concurrent schedules or simulate every physical storage failure.
Neither a bounded model nor 100% source coverage proves every possible
execution, deployment, provider account or human ceremony.
