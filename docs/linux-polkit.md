# Linux Native Approvals (polkit)

Opaque uses a **two-step approval flow** on Linux:

1. **Intent dialog** (zenity/kdialog): displays the operation details so the user knows what they are approving
2. **Polkit authentication**: system password/biometric prompt via PolicyKit

This two-step design exists because most polkit auth agents do not display the operation `details` HashMap, which would otherwise result in blind approvals where the user authenticates without seeing what operation they are authorizing.

## Requirements

- A running graphical session (`$DISPLAY` or `$WAYLAND_DISPLAY` must be set)
- `zenity` (GNOME/GTK desktops) or `kdialog` (KDE/Qt desktops) installed and in `$PATH`
- A polkit authentication agent running in the desktop session
- The Opaque polkit policy file installed (see below)

If any requirement is missing, the daemon will fail closed (refuse to approve operations, not skip approval).

## Policy Installation

Copy the policy file to the system polkit actions directory (requires root):

```bash
sudo cp assets/linux/polkit/com.opaque.approve.policy \
  /usr/share/polkit-1/actions/com.opaque.approve.policy
```

## Policy Details

The policy uses `auth_self` for active sessions:

```xml
<defaults>
  <allow_any>no</allow_any>
  <allow_inactive>no</allow_inactive>
  <allow_active>auth_self</allow_active>
</defaults>
```

- `allow_any=no`: Denies requests from non-local sessions
- `allow_inactive=no`: Denies requests from inactive sessions (SSH, screen locked on some setups)
- `allow_active=auth_self`: Requires the user to authenticate with their own password

## Desktop setup

GNOME/GTK systems commonly use `zenity`; KDE/Qt systems commonly use `kdialog`.
Tiling window managers need a separately started polkit authentication agent.
Check the actual distribution and session rather than assuming the components
are installed. Headless, SSH and container sessions do not supply this local
GUI approval path; use an applicable [out-of-band review](remote-approvals.md)
for supported workflows.

## Credential Caching

Some polkit auth agents (notably GNOME's) cache credentials for a short period (typically 5 minutes). Within that window, the polkit step may auto-succeed without re-entering a password. This is acceptable because the intent dialog (step 1) still appears for every approval, so the user always sees and confirms what they are approving. The credential cache is a polkit agent feature outside Opaque's control.

## Daemon Lifecycle

Use a systemd user service. The CLI installs a user service; inspect its generated unit. See [deployment](deployment.md) for the dedicated service-account alternative.

```bash
systemctl --user enable --now opaqued.service
```

## Notes

- Approval leases ("approve for N minutes") are implemented as daemon-side TTL grants, not by weakening the polkit policy to `auth_self_keep`.
- This factor requires a graphical session and polkit agent. Other approval factors have separate workflow prerequisites.
- Tiling WM users (Sway, i3, etc.) must ensure a polkit agent is running. Common choices: `polkit-gnome-authentication-agent-1` or `lxpolkit`.
