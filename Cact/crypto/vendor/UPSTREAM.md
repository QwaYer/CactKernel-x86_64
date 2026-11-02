# Vendored crates — provenance and re-sync

Everything under `Cact/crypto/vendor/` is third-party Rust code, vendored
verbatim.  **Do not edit these files here** — changes belong upstream; this
directory is refreshed by copying a newer release down.

| Directory | Crate | Version | Upstream |
|---|---|---|---|
| `rustls-0.23.40/` | `rustls` (+ its workspace: benches, examples, tests) | 0.23.40 | <https://github.com/rustls/rustls> |
| `rustls-pki-types/` | `rustls-pki-types` | 1.12.0 | <https://github.com/rustls/pki-types> |
| `rustls-webpki/` | `rustls-webpki` | 0.103.11 | <https://github.com/rustls/webpki> |

`rustls-pki-types` was taken from the crates.io tarball (its
`.cargo-checksum.json` / `.cargo_vcs_info.json` are intact):
upstream commit `4b52db8f3983f4311b10a2e9bf3d61f075a70f21`.

## Licensing

The crate licenses are declared in each `Cargo.toml` and in the `LICENSE*`
files shipped alongside:

| Crate | SPDX |
|---|---|
| `rustls` | `Apache-2.0 OR ISC OR MIT` |
| `rustls-pki-types` | `MIT OR Apache-2.0` |
| `rustls-webpki` | `ISC` |

Upstream does not put an SPDX header in its source files, so CactOS adds one
`// SPDX-License-Identifier: …` line at the top of every `.rs` file — that
single line is the **only** local modification.

## How the kernel builds against it

`Cact/net/rust_net/Cargo.toml` path-depends on `rustls-0.23.40/rustls` and
`rustls-pki-types`, with a `[patch.crates-io]` override for the latter.  The
crypto provider that rustls runs on is CactOS's own
(`Cact/crypto/src/provider.rs`), selected through the `custom-provider`
feature — no `ring`/`aws-lc-rs` backend is compiled.

## Re-sync procedure

```sh
# 1. Fetch the new release, e.g. rustls 0.23.41:
git clone --depth 1 --branch v0.23.41 https://github.com/rustls/rustls /tmp/rustls-new
cargo vendor --no-delete rustls-pki-types rustls-webpki   # or take the crates.io tarball

# 2. Check nothing but our SPDX line differs (one line per .rs file):
diff -r -I 'SPDX-License-Identifier' /tmp/rustls-new/rustls Cact/crypto/vendor/rustls-0.23.40/rustls

# 3. Copy the new tree over, then re-add the SPDX line to every .rs file:
for f in $(find Cact/crypto/vendor/rustls-0.23.40 -name '*.rs'); do
    grep -q SPDX-License-Identifier "$f" || \
    sed -i '1i // SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT\n' "$f"
done

# 4. Update the version in this table and in Cact/net/rust_net/Cargo.toml.
```

The per-file SPDX expressions differ per crate — keep the table above in
step with `Cact/net/rust_net/Cargo.toml`.
