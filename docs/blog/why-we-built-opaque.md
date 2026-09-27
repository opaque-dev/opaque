# Why We Built Opaque

**AI coding tools are powerful. They also need secrets to do useful work.**

When you ask Claude Code to "set my GitHub Actions secret" or "sync my API key
to Codespaces," the agent needs to interact with secrets. The question is: how
much access should it have?

Most solutions today fall into two camps:

1. **Give the agent your credentials.** Paste tokens into prompts, export them
   as environment variables, or drop `.env` files where the agent can read
   them. Fast to set up, terrifying to think about. A single prompt injection
   or tool-use error could exfiltrate everything.

2. **Keep secrets away entirely.** The agent writes code, you manually copy
   secrets into CI dashboards. Safe, but defeats the purpose of agentic
   automation.

Opaque is a third option: **give the agent operations, not secrets.**

## The Core Insight

Most secret-consuming workflows are *write-only* from the agent's
perspective. Setting a GitHub Actions secret requires encrypting a value with
the repo's public key and calling the GitHub API. The agent never needs to see
the plaintext. It just needs to say *what* to do and *where*.

Opaque introduces a local daemon (`opaqued`) that sits between your AI tool
and your secrets. The agent sends operation requests over a Unix socket. The
daemon resolves secret values from your keychain, 1Password, Bitwarden,
or HashiCorp Vault, performs the operation, and returns a sanitized response.
The plaintext never enters the agent's context.

## The Enforcement Pipeline

Every operation flows through a five-stage pipeline with no bypass paths:

1. **Policy** — A deny-by-default allowlist engine evaluates the request
   against rules that match on operation name, client identity, target fields,
   and secret names. No matching rule means the request is denied.

2. **Approval** — If the matching rule requires approval, the daemon triggers
   a native OS prompt. On macOS this is Touch ID via LocalAuthentication; on
   Linux it is polkit. Approval leases prevent prompt fatigue: approve once,
   and subsequent matching requests reuse the lease until it expires.

3. **Execute** — The daemon resolves secret references, calls the provider
   API (GitHub, GitLab, 1Password, Bitwarden, Vault), and captures the
   result. Secret values live only inside the daemon process, in
   zeroize-on-drop buffers.

4. **Sanitize** — The response is scrubbed through a typestate-enforced
   sanitizer. The Rust type system guarantees at compile time that only
   `SanitizedResponse<Sanitized>` values can be returned to clients.
   Regex-based secret-pattern scrubbing adds defense-in-depth.

5. **Audit** — Every step emits structured events to a SQLite audit log
   with correlation IDs. You can query the log with `opaque audit tail`
   to see exactly what happened, when, and for which client.

## Client Identity

The daemon identifies callers through Unix peer credentials (`SO_PEERCRED`
on Linux, `getpeereid` on macOS), resolves the executable path and SHA-256
hash, and on macOS can verify code-signing Team IDs. This lets policy rules
distinguish between "Claude Code signed by a trusted vendor" and "unknown script
in /tmp."

## What Can Agents Do?

Opaque classifies every operation by safety:

- **Safe** — Uses secrets internally but never returns them. Examples:
  `github.set_actions_secret`, `bitwarden.list_projects`. These are the
  only operations exposed to MCP clients.

- **SensitiveOutput** — May return credential-adjacent data (e.g., sandbox
  exec stdout). Restricted by default for agent clients.

- **Reveal** — Explicitly returns plaintext. Never exposed to agents. Used
  only for human-only administrative workflows.

The MCP server (`opaque-mcp`) hard-codes a list of Safe operations. Even if
a policy rule somehow allowed a Reveal operation, the MCP server would not
expose it. This is defense-in-depth: multiple layers must all agree before
an operation reaches the agent.

## Providers

Opaque currently supports:

- **GitHub** — Actions, Codespaces, Dependabot, org, and environment
  secrets. List and delete operations included.
- **GitLab** — CI/CD variable sync with full options (protected, masked,
  raw, environment scope, variable type).
- **1Password** — Vault and item browsing via Connect API or CLI.
- **Bitwarden** — Project and secret browsing via Secrets Manager API.
- **HashiCorp Vault** — KV v1/v2 field reads with lease-aware caching
  and automatic expired-lease revocation.
- **macOS Keychain / Linux secret-tool** — Local secret references via
  `keychain:` ref scheme.

## Getting Started

Opaque is a Rust workspace that builds three binaries: `opaqued` (daemon),
`opaque` (CLI), and `opaque-mcp` (MCP server). The fastest way to try it:

```bash
# Build from source
cargo build --release

# Initialize with a safe demo preset
opaque init --preset safe-demo

# Start the daemon
opaqued

# Test connectivity
opaque ping

# Run a no-op through the full pipeline
opaque execute test.noop
```

For Claude Code, add `opaque-mcp` to your MCP server config and ask Claude
to sync a secret. For Codex or other CLI-based agents, use `opaque agent run`
to wrap the agent in a scoped session.

Full documentation lives in the `docs/` directory of the
[repository](https://github.com/opaque-dev/opaque).

## What's Next

Opaque is under active development. The current focus areas include:

- Cross-compiled release binaries for macOS (x86_64, aarch64) and
  Linux (x86_64, aarch64)
- Vault dynamic secrets with full lease lifecycle management
- Additional policy preset templates for common workflows
- Interactive setup wizard improvements

We believe that AI coding tools and strong security are not at odds. Opaque
is our attempt to prove it.

---

*The current public core uses Apache-2.0; documentation uses CC BY 4.0.
Earlier revisions retain their published terms. See [licensing](../licensing.md).*
