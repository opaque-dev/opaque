# Independent core consumer

Run from a checkout of public Opaque:

```sh
cargo run --manifest-path examples/embedded-policy/Cargo.toml --locked
```

This is a separate Cargo workspace consuming `opaque-core` as a library. It
evaluates an allowed synthetic operation, a denied reveal and an unlisted
operation. It starts no daemon, provider connection or enterprise service.

Policy evaluation is one part of enforcement. It does not authenticate callers,
perform trusted review, reserve a durable grant or execute a provider action.
Use the broker for those complete contracts; an embedding must preserve their
authority and custody boundaries. See [reusable core](../../docs/reusable-core.md).

The example code and core use Apache-2.0. Documentation uses CC BY 4.0;
see [license scope](../../docs/licensing.md).
The Rust interfaces are evolving; pin a reviewed commit when consuming via Git.
