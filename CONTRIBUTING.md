# Contributing to mcpunit

Thanks for your interest — contributions are welcome. Before sending a
pull request, please read this short guide.

By participating in this project you agree to abide by the
[Code of Conduct](./CODE_OF_CONDUCT.md).

## Quick links

- **Bug reports / feature requests:** open an issue using one of the
  templates under `.github/ISSUE_TEMPLATE/`.
- **Security issues:** see [`SECURITY.md`](./SECURITY.md) — do **not**
  open a public issue.
- **Questions:** GitHub Discussions or email
  <thecutcode@gmail.com>.

## Development setup

mcpunit is a single-crate Rust project with no build-time system
dependencies beyond a stable Rust toolchain.

```bash
git clone https://github.com/lee-to/mcpunit
cd mcpunit
cargo build
cargo test
```

Recommended toolchain: stable Rust ≥ 1.75 (pinned in `Cargo.toml`).

### Running the full quality gate locally

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The CI workflow (`.github/workflows/ci.yml`) runs the same checks on
Linux / macOS / Windows.

### Regenerating example reports

The `.reports/` directory contains a committed audit of the bundled demo
MCP server. If you touch a rule, a reporter, or the scoring engine, you
probably need to regenerate it:

```bash
cargo build --release --example demo
./target/release/mcpunit test \
  --json-out .reports/demo.json \
  --sarif-out .reports/demo.sarif \
  --markdown-out .reports/demo.md \
  --cmd target/release/examples/demo \
  > .reports/demo.txt
```

### Updating insta snapshots

Reporter snapshot tests live under `tests/snapshots/`. After an
intentional output change:

```bash
INSTA_UPDATE=always cargo test --test reporter_snapshots
```

Review the diff with `cargo insta review` before committing.

## Adding a new rule

1. Pick the right module in `src/rules/` by category:
   `identity.rs`, `description.rs`, `schema.rs`, or `capability.rs`.
2. Implement the `Rule` trait on a zero-sized unit struct.
3. Register the struct in `src/rules/mod.rs::REGISTRY`. **Order matters**
   — findings are serialised in registry order.
4. Add at least one unit test in the same file that exercises a positive
   and a negative case.
5. If the rule emits new evidence fields, add a test that asserts the
   exact evidence string — downstream tools rely on these being stable.
6. Run `cargo test` + `cargo clippy --all-targets -- -D warnings`.

Rule IDs are part of the public contract. **Never rename a shipped rule
ID** — users track findings over time by that string. If a rule is
obsoleted, delete it and publish a major version bump.

## Pull request checklist

Before opening a PR, please make sure:

- [ ] `cargo fmt --check` is clean
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo test` passes
- [ ] Snapshot tests are either untouched or regenerated intentionally
- [ ] Any new rule ships with unit tests
- [ ] Any new CLI flag is documented in `README.md` and `action.yml`
- [ ] The PR description explains **why**, not just **what**

Small, focused PRs get reviewed faster than large ones. Splitting a
refactor from a feature change is always welcome.

## Commit messages

The project follows
[Conventional Commits](https://www.conventionalcommits.org/) loosely:

```
feat(rules): add dangerous_temp_file rule
fix(http): close SSE stream on session-id mismatch
docs: clarify --min-score exit codes
```

A clean commit history is appreciated but not required — the maintainer
may squash on merge.

## Release

Releases are cut by pushing a semver tag (`v1.0.1`, `v1.1.0`,
`v2.0.0-rc.1`, ...). The release workflow builds, packages, and publishes
the matrix of platform binaries automatically.

## License

By contributing you agree that your contributions are licensed under the
[MIT License](./LICENSE).
