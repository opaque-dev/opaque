# Deployment Guide

Packaging model, supported platforms, and approval architecture requirements for real-world deployment of Opaque.

---

## Two Deployment Modes

Opaque runs in one of two trust configurations, and everything else in this
guide is scoped by which one you choose:

| | **Session mode** (default) | **Trust-domain split** |
|---|---|---|
| Daemon runs as | your own user, in your GUI session | a dedicated service account (`opaque`), as a system service |
| Integrity posture | an agent sharing your uid may obtain the audit key and forge locally valid history | custody files are unreadable/unwritable at the agent's uid, checked at startup; daemon/admin remain trusted |
| Approval factors | local biometric (macOS `LocalAuthentication`), polkit; both need your GUI session | out-of-band factors that don't need the daemon to own a session: paired second device, FIDO2 key, passkey |
| Service manager | LaunchAgent / systemd **user** service | LaunchDaemon / systemd **system** service (`deploy/`) |
| Config | `~/.opaque/config.toml` | `/etc/opaque/config.toml` with `[trust_domain] enforce = true` (see `deploy/config.trust-domain.example.toml`) |

**Session-mode constraint:** the daemon must run inside an interactive GUI
session, because `LocalAuthentication` and polkit present dialogs there.
Headless, SSH, CI, and container environments fail closed *in session mode*;
they are exactly what the trust-domain split is for.

---

## Trust-Domain Split (Service-Account Mode)

The split moves `opaqued` under a principal the agent can never be: a
dedicated service account that exclusively owns every custody file: the
audit database and its chain key, the identity store and delegation signing
key, the config and its seal, the pairing store, and the profiles directory.

What enforcement means concretely (`[trust_domain] enforce = true`):

1. **Startup fails closed** unless every custody file that exists is owned by
   the daemon's own uid with no group/other permission bits and no symlinks
   substituted anywhere. The refusal names each violating path and the fix.
   Loose modes on files the daemon *does* own are self-healed (tightened),
   not fatal.
2. **Connections from the daemon's own uid are refused.** Nothing legitimate
   runs as the service account except the daemon; in session mode the same
   check points the other way (only your own uid may connect).
3. **The cross-domain surface is exactly three inodes:** the socket directory
   (0750), the socket (0660), and the daemon token (0640), all group-owned by
   `trust_domain.socket_group`. Group membership is the coarse transport
   gate; identity + policy decide per principal after that.
4. **The posture is recorded in the audit chain** at every startup
   (`trust_domain.posture` event), so "was the split enforced at the time?"
   is answerable from the log itself.

Setup on Linux (systemd) and macOS (LaunchDaemon) is scripted in the headers
of `deploy/systemd/opaqued.service` and `deploy/launchd/com.opaque.opaqued.plist`.

### Containers (compose / Kubernetes)

In containers the split gets stronger: the daemon and the agent run in
separate containers that share ONLY the socket volume, so the custody files
have no path inside the agent container at all: not merely unreadable,
nonexistent.

- **Compose:** `deploy/docker/compose.yaml` + `bootstrap.sh` (one-shot root
  init that seeds and SEALS the config under the daemon account).
  `scripts/compose-smoke.sh` builds the Linux binaries and verifies the whole
  stack end to end: sealed bootstrap, enforced custody at startup,
  cross-container ping, custody invisibility from the agent, the exact
  0750/0660/0640 socket surface, and refusal of a daemon-uid client.
- **Kubernetes:** `deploy/k8s/opaque.yaml`: separate ServiceAccounts (the
  agent container automounts no API token), runAsUser split (7381/7382),
  socket via a memory emptyDir with `supplementalGroups: [7999]`, custody on
  a PVC mounted only by the daemon container, read-only root filesystems,
  all capabilities dropped.
- **Group mechanics that bite:** a non-root daemon can chgrp the socket
  surface only to a group in its own supplementary set; grant it via
  `group_add` (compose), `supplementalGroups` (k8s), or
  `SupplementaryGroups=` (systemd). `trust_domain.socket_group` accepts a
  numeric gid for container environments with no named groups.
- **Key custody in containers:** the default keyfile backend keeps the seal
  and signing keys on the daemon-only volume. For higher assurance, mount a
  KMS/CSI secret or exchange a SPIFFE/SPIRE SVID into the daemon container
  only; the release policy on that KMS/SPIRE seam is also where
  remote-attestation-before-trust (verify the daemon's measured identity
  before handing it keys) belongs.

Clients discover a split daemon automatically: when no per-user socket
exists, the CLI/MCP try `/run/opaque/opaqued.sock` and verify the split's
shape (daemon-owned socket, no world access, unwritable socket directory)
before connecting.

> **Approval factors in split mode:** the daemon no longer owns a GUI session,
> so session-bound prompts (LocalBio, polkit) cannot fire from it. Configure
> an out-of-band factor (paired second device, FIDO2 hardware key, or
> passkey) so approvals carry a cryptographic approver signature instead.

---

## Upgrading existing custody

The current source writer authenticates the retained audit head and refuses
unsupported older stores. Before replacing a running binary, close admission,
reconcile in-flight work, stop/fence every writer and follow the explicit
[audit-store upgrade procedure](evidence-checkpoints.md#authenticated-local-head-and-older-databases).
It requires independently retained evidence; hashing the current suspect store
is not a substitute. Preserve the original custody on refusal. The service
manager does not perform this migration for you.

Do not roll back task, identity, revocation or replay ledgers to recover service.
An older intact snapshot can pass integrity checks and still resurrect authority.
See [storage and recovery boundaries](storage.md).

## macOS

### Packaging Model

**Daemon packaging direction: code-signed binary + LaunchAgent plist**

The proposed daemon `.pkg` would place:

```
/usr/local/bin/opaqued          (code-signed, notarized)
/usr/local/bin/opaque           (code-signed, notarized)
~/Library/LaunchAgents/com.opaque.daemon.plist
```

**Deferred daemon integration: SMAppService app bundle**

Use `SMAppService.agent(plistName:)` (macOS 13+) to register the LaunchAgent from within an `.app` bundle. Benefits: macOS manages lifecycle, the binary lives inside the signed bundle (tamper-evident), and install/uninstall is cleaner. Deferred from v1 because it requires a `.app` build target and `Info.plist`, which are orthogonal to getting the core security right.

The source-built `Opaque Reviewer.app` is a separate workstation client. It does
not install the daemon or implement this deferred SMAppService lifecycle. The
current release workflow packages tar archives; see [installation](getting-started.md)
and [reviewer setup](remote-approvals.md) for released versus source-only paths.

### LaunchAgent Plist

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.opaque.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/opaqued</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>LimitLoadToSessionType</key>
  <string>Aqua</string>
  <key>ProcessType</key>
  <string>Interactive</string>
  <key>StandardErrorPath</key>
  <string>/tmp/opaqued.err</string>
</dict>
</plist>
```

**Critical fields:**

| Field | Value | Why |
|-------|-------|-----|
| `LimitLoadToSessionType` | `Aqua` | Only loads in GUI login sessions. Prevents loading under SSH, cron, or background contexts where Touch ID is unavailable. |
| `ProcessType` | `Interactive` | Tells macOS the process presents approval dialogs. Prevents aggressive process throttling. |
| `KeepAlive.SuccessfulExit` | `false` | Restarts on crash. Does not restart on clean exit (allows `opaque shutdown` to stick). |

### Why LaunchAgent, Never LaunchDaemon (session mode)

`LocalAuthentication` (`LAContext`) requires:
- An active Aqua GUI session (access to the WindowServer)
- The user's Secure Enclave key (Touch ID) or fallback password dialog
- The user's login keychain

A LaunchDaemon runs with no GUI session. Touch ID is unreachable.
`canEvaluatePolicy` would fail on every request. **LaunchDaemon is
architecturally incompatible with session mode.** The trust-domain split
(`deploy/launchd/com.opaque.opaqued.plist`) *is* a LaunchDaemon, under a
dedicated non-root account, and pairs with out-of-band approval factors
instead of `LocalAuthentication`.

### Code Signing Requirements

The binary must be signed with Hardened Runtime:

```bash
codesign --sign "Developer ID Application: ..." \
  --options runtime \
  --entitlements opaqued.entitlements \
  /usr/local/bin/opaqued
```

Minimal entitlements (no special entitlements needed; `LocalAuthentication` does not require an entitlement when called from a user-session process):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
```

Notarize via `notarytool` so Gatekeeper does not quarantine the binary on first run.

### macOS Edge Cases

| Scenario | Behavior | Status |
|----------|----------|--------|
| Screen locked | Touch ID dialog appears on lock screen (macOS handles this natively) | Works |
| Lid closed (clamshell mode) | No Touch ID sensor; `DeviceOwnerAuthentication` falls back to password dialog | Works |
| No biometric hardware (Mac Mini, older MacBook Pro) | Password dialog only | Works |
| Fast User Switching (background user) | Dialog appears on the user's desktop, may fail if user is not the console user | Needs testing: daemon should `canEvaluatePolicy` before each approval |
| Remote Desktop / VNC | No Touch ID sensor; password fallback | Works but weaker |

### Session Detection (Daemon Startup)

The daemon must verify it is running in a usable GUI session before binding the socket. On macOS, call `canEvaluatePolicy` at startup as a preflight. If it fails, log: `"opaqued requires a macOS GUI session (LaunchAgent, not LaunchDaemon or SSH)"` and exit non-zero.

---

## Linux

### Approval Flow: Two-Step Model

Linux approval uses a two-step flow (implemented in `approval.rs`):

1. **Intent dialog**: Shows the operation details (what the user is approving) via `zenity --question` or `kdialog --yesno`. Falls back to TTY if `isatty(STDIN_FILENO)`.
2. **Polkit authentication**: System authentication dialog (password / fingerprint) via `CheckAuthorization` with `AllowUserInteraction`.

This separation exists because most polkit auth agents do not display the `details` HashMap, meaning the user would authenticate without seeing what operation they are approving (a blind approval). The intent dialog solves this by showing details in a UI we control, while polkit handles only the authentication.

### Supported Desktop Environments

#### Tier 1: Full Support

Tested. Both intent dialog and polkit agent ship by default.

| Desktop | Intent Dialog | Polkit Agent |
|---------|--------------|--------------|
| **GNOME 42+** | `zenity` (ships with GNOME) | `gnome-shell` built-in agent |
| **KDE Plasma 5.20+** | `kdialog` (ships with KDE) | `polkit-kde-authentication-agent-1` |

#### Tier 2: Supported (minor setup may be needed)

Works with one or both components typically pre-installed. May need `zenity` or `kdialog` installed separately.

| Desktop | Intent Dialog | Polkit Agent | Notes |
|---------|--------------|--------------|-------|
| **MATE** | `zenity` (GTK-based, usually present) | `mate-polkit` | Install `zenity` if not present |
| **XFCE** | `zenity` (usually present) | `xfce-polkit` or `polkit-gnome-authentication-agent-1` | Some distros use `polkit-gnome` as fallback |
| **Cinnamon** | `zenity` (GTK-based) | `polkit-gnome-authentication-agent-1` | Linux Mint default; reliable |
| **Budgie** | `zenity` (GNOME stack) | GNOME polkit agent | Works like GNOME |
| **LXQt** | `kdialog` (Qt-based, may need install) | `lxqt-policykit` | May need `kdialog` installed |

#### Tier 3: Supported with Manual Setup

Functional, but the user must ensure a polkit agent is running (tiling WMs do not autostart one).

| Desktop | Intent Dialog | Polkit Agent | User Action Required |
|---------|--------------|--------------|---------------------|
| **Sway / Hyprland / wlroots** | `zenity` (runs under XWayland) | Must manually start `polkit-gnome-authentication-agent-1` or equivalent | Add to compositor autostart config |
| **i3 / dwm / other X11 WMs** | `zenity` | Same: no polkit agent by default | Add to `.xinitrc` or session autostart |

#### Tier 4: Unsupported (Fail Closed)

The daemon must refuse to start in these environments.

| Environment | Reason |
|-------------|--------|
| **Headless / TTY-only** | No `zenity`/`kdialog`, no polkit agent, no display server |
| **SSH sessions** | polkit `allow_inactive=no` blocks auth; intent dialog has no display |
| **Containers / CI** | No interactive session |

### Polkit Credential Caching

Some polkit auth agents (notably GNOME's) cache credentials for a short period (typically 5 minutes). Within that window, the polkit authentication step may auto-succeed without the user re-entering their password.

**This is acceptable** because:
- The intent dialog (zenity/kdialog) still appears for every approval; the user always sees what they are approving
- The credential cache is a polkit agent feature outside Opaque's control
- Disabling it requires modifying system polkit configuration, which is out of scope
- The user explicitly confirmed intent in step 1; the polkit step provides authentication, not intent

### systemd User Service

Recommended unit file at `~/.config/systemd/user/opaqued.service`:

```ini
[Unit]
Description=Opaque Daemon
After=graphical-session.target
Requires=graphical-session.target

[Service]
ExecStart=/usr/local/bin/opaqued
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=%h/.opaque
CapabilityBoundingSet=
AmbientCapabilities=
LimitCORE=0

[Install]
WantedBy=graphical-session.target
```

**Critical fields:**

| Field | Value | Why |
|-------|-------|-----|
| `Requires=graphical-session.target` | — | Only starts when a graphical session is active. Prevents starting under SSH or headless boot. |
| `NoNewPrivileges=true` | — | Prevents privilege escalation via setuid/setgid binaries |
| `ProtectHome=read-only` | — | Daemon can only write to `ReadWritePaths` (`~/.opaque`) |
| `LimitCORE=0` | — | Core dump prevention (secrets may be in process memory) |

Enable and start:

```bash
systemctl --user enable --now opaqued.service
```

### Polkit Policy Installation

Copy the policy file to the system polkit actions directory (requires root):

```bash
sudo cp assets/linux/polkit/com.opaque.approve.policy \
  /usr/share/polkit-1/actions/com.opaque.approve.policy
```

The policy uses `auth_self` for active sessions (user must authenticate with their own password). See `assets/linux/polkit/com.opaque.approve.policy` for the full XML.

### Session Detection (Daemon Startup)

The daemon must verify the following at startup before binding the socket:

1. **Display server**: `$DISPLAY` or `$WAYLAND_DISPLAY` must be set.
2. **Intent dialog binary**: `zenity` or `kdialog` must be in `$PATH`.
3. **Polkit availability**: The `org.freedesktop.PolicyKit1` service must be reachable on the system D-Bus.

If any check fails, log the specific missing component and exit non-zero. Do not silently degrade to a mode where approvals are skipped.

### Sandbox prerequisites

`sandbox.exec` needs one namespace wrapper. At startup and before every exec
the daemon runs each wrapper once with a throwaway `true` in the exact
namespace shape the sandbox uses, queries the kernel for Landlock
(`landlock_create_ruleset` ABI answer, recorded next to the
`/sys/kernel/security/lsm` list) and seccomp, and selects the strongest
strategy those facts support:

| Strategy (audit `sandbox=`) | Requires |
|---|---|
| `bubblewrap+landlock+seccomp` | `bwrap` builds the sandbox shape; kernel has Landlock enabled |
| `bubblewrap+seccomp` | `bwrap` works; kernel without Landlock (`landlock_evidence=... abi-probe=EOPNOTSUPP`) |
| `unshare+landlock+seccomp` | no working `bwrap`; `unshare --user --mount --pid --fork --map-root-user --net` works; Landlock enabled |
| `unshare+seccomp` | as above without Landlock |
| refused: `no sandbox strategy available: ...` | neither wrapper can build its namespaces here; nothing is spawned |

A layer the kernel lacks is dropped with a warning and the strategy name
shrinks accordingly; the `sandbox.created` and `sandbox.completed` audit
events carry the name that was actually used. Nothing is downgraded silently
and nothing runs without a wrapper. The wrapper itself runs unrestricted so it
can finish its setup; the daemon binary re-invoked as
`opaqued __opaque-sandbox-helper` inside the namespaces installs
NO_NEW_PRIVS, Landlock and seccomp on itself, reports readiness to the
daemon, then execs the command. Keep `opaqued` outside `~/.opaque`, `~/.ssh`
and `~/.gnupg`: those paths are hidden inside the sandbox, so the helper
could not be found there.

Install and check:

```bash
sudo apt-get install -y bubblewrap        # Debian/Ubuntu; Fedora: dnf install bubblewrap
cat /sys/kernel/security/lsm              # lists landlock on kernels 5.13+ with the LSM enabled
opaqued 2>&1 | grep "linux sandbox"       # or read the startup log of the running daemon
```

Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor. The
`bubblewrap` package ships an AppArmor profile that permits them for `bwrap`;
for `unshare`, or for a `bwrap` built from source, set
`sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`.

Containers: creating user namespaces needs `CAP_SYS_ADMIN` and a seccomp
profile that allows `unshare`, which Docker's defaults deny. Run the daemon's
container with `--cap-add SYS_ADMIN --security-opt seccomp=unconfined`; on
Docker Desktop's 7.0.12-linuxkit kernel, bubblewrap's loopback setup for
`network.allow = []` additionally needs `--cap-add NET_ADMIN` (or
`--privileged`), otherwise the `bwrap` probe fails and the daemon falls over
to `unshare`. With the default confinement the daemon still starts, logs why
both probes failed, and refuses every exec with the same reasons:

```text
$ opaque exec --profile dev -- echo "hello from sandbox"
!!  operation execution failed: linux sandbox unavailable: sandbox setup failed: no sandbox strategy available: bubblewrap: bwrap probe exit status: 1: bwrap: Creating new namespace failed: Operation not permitted; unshare: unshare probe exit status: 1: unshare: unshare failed: Operation not permitted; install bubblewrap or enable unprivileged user namespaces (Ubuntu 24.04: sysctl kernel.apparmor_restrict_unprivileged_userns=0; containers need CAP_SYS_ADMIN and a seccomp profile that allows unshare); landlock: lsm=securityfs-unreadable abi=v8
  code: operation_failed
```

The refusal is audited as `operation.failed`; no `sandbox.created` event is
written because no sandbox existed.

When `bwrap` is missing, the failover is visible in the startup log and in
the audit rows (Debian 12 container, 7.0.12 kernel):

```text
INFO opaque_sandbox::linux: linux sandbox capabilities detected bubblewrap=false bubblewrap_evidence=bwrap is not on PATH landlock=true landlock_evidence=lsm=securityfs-unreadable abi=v8 seccomp=true user_namespaces=true user_namespaces_evidence=ok
INFO opaque_sandbox::linux: linux sandbox strategy selected for sandbox.exec strategy=unshare+landlock+seccomp
```

```text
sandbox.created|created|profile=dev argument_count=2 sandbox=unshare+landlock+seccomp
sandbox.completed|success|profile=dev exit_code=0 sandbox=unshare+landlock+seccomp
```

On a kernel without Landlock (here: the same kernel with the Landlock
syscalls denied by the container's seccomp profile) the daemon says so and
drops that layer:

```text
WARN opaque_sandbox::linux: landlock unavailable on this kernel; failing over to namespace isolation without the filesystem layer wrapper="bwrap" evidence=lsm=securityfs-unreadable abi-probe=EOPNOTSUPP (LSM built but not enabled at boot)
INFO opaque_sandbox::linux: linux sandbox strategy selected for sandbox.exec strategy=bubblewrap+seccomp
```

---

## Approval Architecture Invariants

These hold across both platforms:

### 1. Approval description is daemon-constructed

The approval dialog text is built by the enclave from verified `OperationRequest` fields (operation name, target, workspace, content hash). The daemon must validate that the operation is in the registry and that target keys match the operation's expected schema before including them in the description. Client-supplied text is never displayed in an approval dialog.

### 2. Content hash binding

Every approval is cryptographically bound to the operation it authorizes via SHA-256 content hash (computed over operation name, sorted targets, secret refs, client identity, and workspace). The first 16 hex characters of the hash are displayed in the approval dialog. Approval audit events include the full hash for forensic correlation.

### 3. Approval leases are daemon-side TTL grants, never a weaker OS policy

`require = "first_use"` grants a lease after the first approval: a `lease_ttl` (default 10 min, capped at 60) during which the same operation/target skips the dialog. `require = "always"` never grants one. Leases live in the daemon's in-memory cache and don't change what the OS mechanism itself verifies; see [Linux polkit](linux-polkit.md#notes) on `auth_self_keep`.

### 4. Fail closed

If the approval UI cannot be presented (no GUI session, no polkit agent, no zenity/kdialog, `canEvaluatePolicy` fails), the operation is denied. The daemon does not fall back to a weaker approval method or skip approval.

### 5. Single approval at a time

The approval semaphore ensures only one approval dialog is active at a time. If the requesting connection drops while an approval is pending, the approval should be cancelled and the semaphore released.

---

## Deployment Checklist

### macOS

- [ ] Binary is code-signed with Developer ID and Hardened Runtime
- [ ] Binary is notarized via `notarytool`
- [ ] LaunchAgent plist installed at `~/Library/LaunchAgents/com.opaque.daemon.plist`
- [ ] Plist has `LimitLoadToSessionType: Aqua`
- [ ] Socket directory `~/.opaque/run/` has permissions `0700`
- [ ] Socket file has permissions `0600`
- [ ] `~/.opaque/` is excluded from Time Machine and Spotlight
- [ ] `canEvaluatePolicy` succeeds at daemon startup

### Linux

- [ ] Polkit policy installed at `/usr/share/polkit-1/actions/com.opaque.approve.policy`
- [ ] `zenity` or `kdialog` is installed and in `$PATH`
- [ ] A polkit authentication agent is running in the desktop session
- [ ] systemd user service installed with `Requires=graphical-session.target`
- [ ] `$DISPLAY` or `$WAYLAND_DISPLAY` is set
- [ ] Socket directory (`$XDG_RUNTIME_DIR/opaque/` or `~/.opaque/run/`) has permissions `0700`
- [ ] Socket file has permissions `0600`
- [ ] `$XDG_RUNTIME_DIR` is mounted as `tmpfs` (prevents socket persistence across reboots)
- [ ] Core dumps disabled (`LimitCORE=0` in systemd unit)

### Both Platforms

- [ ] Daemon runs as the logged-in user, never as root
- [ ] `RUST_LOG=info` in production (never `debug` or `trace`)
- [ ] Provider credentials stored in OS keychain, not in config files
- [ ] No symlinks in the socket path chain
