# Security Policy

## Supported Versions

mcpunit follows semver. Only the current **major** line receives security
fixes. Older majors are best-effort.

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not file public GitHub issues for security-sensitive reports.**

Send a detailed report to <thecutcode@gmail.com> with:

1. **Affected version(s)** — `mcpunit --version` output or the release tag
   you downloaded.
2. **Reproduction steps** — the smallest MCP server / CLI invocation that
   triggers the issue.
3. **Impact** — what an attacker could achieve (RCE, DoS, information
   disclosure, bypassing a rule, etc.).
4. **Proof of concept** — optional but helpful. A minimal shell session or
   a small test case is ideal.

You should receive an acknowledgement within **72 hours**. If you do not,
please follow up — mail delivery is rarely perfect.

## Disclosure Timeline

The maintainer aims for coordinated disclosure:

1. You report the issue privately.
2. The maintainer confirms the issue and works on a fix.
3. A patched release is published with a CVE or GitHub advisory as
   appropriate.
4. The advisory credits the reporter unless they prefer to stay anonymous.

Target window from report to patched release is **30 days** for
high-severity issues and **90 days** for lower-severity issues, unless the
fix requires a larger refactor.

## Scope

In scope:

- The `mcpunit` binary, library crate, and the composite GitHub Action.
- The release pipeline (`.github/workflows/release.yml`) and published
  binary artefacts.
- The SARIF / JSON / Markdown / terminal reporters.

Out of scope:

- Vulnerabilities in the MCP servers you scan — report those upstream.
- Bugs that do not have a security impact (please open a normal issue).
- Third-party dependencies — report those to the respective projects.
  We track supply-chain risk via `cargo-audit` and `cargo-deny` in CI.

## Safe Harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction,
  and service interruption.
- Give us reasonable time to investigate and mitigate an issue before
  making it public.
- Only interact with accounts they own or have explicit permission to
  access.
