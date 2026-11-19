# Parser fuzzing

> This text is LLM generated.

These opt-in cargo-fuzz targets exercise the host configuration parser and
validator (`host_config`) and the pure `/etc/os-release` parser (`os_release`).
They never run setup, read the host's release file, start processes or change
the host. Production hardening and configuration defaults are unchanged.
The separate workspace keeps libFuzzer's generated entry points outside the
production workspace's unsafe-code lint.

The targets look for panics and check invariants: canonical TOML and the
deprecated host-table alias preserve admission and settings; dual host tables
are refused; irrelevant release fields do not change support; duplicate
identity fields fail closed. UTF-8 inputs are capped at 16 KiB in the harness.
Seed corpora cover supported releases, ambiguous and shell-like identities,
default and legacy host tables, prepared settings and invalid combinations.

Run these commands from the crate's directory, which is the root of the
extracted repository. Replay the committed corpus and harness boundary tests
with stable Rust (in the parent checkout, `just fuzz-check` runs these and is
part of `just check`):

```sh
CARGO_TARGET_DIR=target cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings
CARGO_TARGET_DIR=target cargo test --manifest-path fuzz/Cargo.toml --lib --locked
```

For coverage-guided fuzzing, install nightly Rust and `cargo install cargo-fuzz
--locked`. For example, this bounded run uses a disposable writable corpus,
keeps generated files out of the checkout, and stops after at most 30 seconds
or 10,000 inputs per target:

```sh
mkdir -p /tmp/secure-host-fuzz/host_config /tmp/secure-host-fuzz/os_release
CARGO_TARGET_DIR=target cargo +nightly fuzz run --fuzz-dir fuzz host_config /tmp/secure-host-fuzz/host_config fuzz/corpus/host_config -- -max_total_time=30 -runs=10000 -max_len=16384 -timeout=5 -rss_limit_mb=2048 -artifact_prefix=/tmp/secure-host-fuzz/
CARGO_TARGET_DIR=target cargo +nightly fuzz run --fuzz-dir fuzz os_release /tmp/secure-host-fuzz/os_release fuzz/corpus/os_release -- -max_total_time=30 -runs=10000 -max_len=16384 -timeout=5 -rss_limit_mb=2048 -artifact_prefix=/tmp/secure-host-fuzz/
```

Promote minimized findings to regression tests or seeds before fixing a bug.
These smoke bounds are not a sustained fuzzing service or proof of parser
correctness; CI scheduling and hosted fuzzing remain separate work.
