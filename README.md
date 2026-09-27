# Opaque

![CI](https://github.com/opaque-dev/opaque/actions/workflows/ci.yml/badge.svg)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
![Release](https://img.shields.io/github/v/release/opaque-dev/opaque)

**Give agents bounded authority.**

Give agents reviewed work with a fixed scope and expiry. Opaque checks current
authority before dispatch and records the observed result. The local broker
supports CLI and MCP clients and keeps execution credentials in broker custody.

## Try one data read

[Open the demo](https://demo.opaque.info/). Review a task that reads fictional
loan-application metrics. Approve it, run it once, inspect the result, then try
again to see Opaque block the repeat.

The hosted demo uses synthetic data and a separate workflow; it does not connect
to your repository. See the [demo guide](docs/hosted-demo.md) for session limits
and approval methods.

To run the same story on your own machine, clone the
[Harborlight quickstart](https://github.com/opaque-dev/harborlight):
four acts, fifteen minutes, no external accounts, verified in CI against the
released package.

## Run a local operation

Follow the [tutorial](docs/tutorial.md) to configure credentials and policy, then
publish a GitHub Actions secret using a stored reference:

```sh
opaque github set-secret \
  --repo myorg/myrepo \
  --secret-name API_KEY \
  --value-ref keychain:opaque/api-key
```

The broker checks policy, obtains the required approval, calls GitHub, and records
the observed result without returning the secret value to the agent.

[Bounded tasks](docs/bounded-work.md) bind approval to an exact manifest, expiry,
and action limit. Changing the task requires a new review; an uncertain outcome
does not restore a consumed attempt. [Qualified MCP calls](docs/mcp-qualified-tools.md)
use a separate signed contract and review path.

## What the boundary covers

Opaque governs operations routed through its broker. An agent's other credentials,
readable files, and direct access remain outside that boundary. Use a
[dedicated broker identity](docs/deployment.md) to isolate custody from the
agent's OS user; the default same-user setup does not provide that isolation.
The broker, its administrators, and configured approval factors remain trusted.
See the [architecture](docs/architecture.md) for these trust boundaries.

Audit verification checks recorded evidence under specified trust assumptions.
It does not independently prove every provider effect or that every action was
logged. See [evidence verification](docs/evidence-checkpoints.md).

## Install and release status

macOS and Linux are supported. For the published Homebrew package:

```sh
brew install opaque-dev/tap/opaque
```

Each v0.6.0 release archive contains all eight tools (`opaqued`, `opaque`,
`opaque-mcp`, `opaque-mcp-contract`, `opaque-approve-helper`, `opaque-approver`,
`opaque-evidence`, `opaque-web`), the `opaque-release.json` manifest and the
`LICENSE`, `LICENSE-DOCS` and `NOTICE` files; macOS archives add `Opaque Reviewer.app`.
The [scoped authority workflow](docs/scoped-authority.md) is **available from v0.6.0**.
Signed MCP v2 contracts and portable evidence checkpoints ship in the same archives.
Automated tests use synthetic providers and reviewer signatures; they do not qualify
a live provider or a native approval ceremony on your host. Verify an archive with
[installable releases](docs/installable-releases.md), and follow the
[explicit audit migration](docs/evidence-checkpoints.md#authenticated-local-head-and-older-databases)
before upgrading an existing audit store.

[Documentation](docs/README.md) · [Build on the public core](docs/reusable-core.md) ·
[Apache-2.0 code license](LICENSE) · [CC BY 4.0 documentation](LICENSE-DOCS) · [License scope](docs/licensing.md)
