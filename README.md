<div align="center">

# mcpunit

### **The CI-grade quality audit for MCP servers.**

Catch bad tool names, weak schemas, dangerous capabilities, and hidden
footguns in your MCP server — **before your agents ever touch them**.

[![CI](https://github.com/lee-to/mcpunit/actions/workflows/ci.yml/badge.svg)](https://github.com/lee-to/mcpunit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lee-to/mcpunit?color=blue)](https://github.com/lee-to/mcpunit/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![MCP](https://img.shields.io/badge/MCP-2024--11--05%20%E2%86%92%202025--11--25-purple)](https://modelcontextprotocol.io)
[![Binary size](https://img.shields.io/badge/binary-%3C%205%20MB-brightgreen)](#-fast-and-tiny)
[![Written in Rust](https://img.shields.io/badge/built%20with-Rust-orange?logo=rust)](https://www.rust-lang.org)

**One command. Zero config. 17 deterministic rules. JSON + SARIF + Markdown.**

⚡ **Sub-second cold-start.** &nbsp;·&nbsp; 📦 **< 5 MB binary.**
&nbsp;·&nbsp; 🪶 **Zero runtime dependencies.**
&nbsp;·&nbsp; 🦀 **Built in Rust.**

[Quick start](#-quick-start) ·
[Why it matters](#-why-mcp-quality-matters) ·
[What it catches](#-what-mcpunit-catches) ·
[Fast & tiny](#-fast-and-tiny) ·
[GitHub Action](#-github-action) ·
[Reports](#-what-the-reports-look-like)

</div>

---

## 🔥 Why MCP quality matters

Your MCP server is **the contract your AI agents trust**. Every tool name,
every description, every input schema becomes a prompt the model reads
and decides to act on. Low-quality MCP servers don't just look sloppy —
they actively hurt agent behaviour:

- 🤯 **Generic tool names** (`do_it`, `helper`, `run`) make the model guess.
  Agents pick the wrong tool, retry, waste tokens, and produce wrong
  answers.
- 🧨 **Missing or vague descriptions** leave the model to invent semantics
  from the name alone. One production incident away from a very bad day.
- 🕳 **Weak input schemas** (`"additionalProperties": true`, generic
  `payload` objects) let malformed agent calls reach your backend.
  Guess what happens next.
- ⚠️ **Dangerous capabilities hidden in plain sight** — exec tools,
  filesystem writes, arbitrary HTTP — shipped without any scope
  hint. An over-eager agent plus a `write_file(path, content)` with no
  sandbox is a Monday-morning postmortem waiting to happen.
- 📏 **Response bloat.** A `tools/list` that dumps 2 MiB of schema into
  every context window is a tax on every single call.

You cannot fix what you cannot measure. **mcpunit measures.**

It's `cargo clippy` for MCP: deterministic, fast, CI-first, and boring
in exactly the way you want a quality gate to be.

## 🚀 Fast and tiny

mcpunit is written in Rust and ships as a **single statically-linked
binary**. No Python. No Node. No JVM. No Docker image. No `npm install`
waiting room. You download one file and you run it.

| Metric | mcpunit |
|---|---|
| **Download size** | **~1.5 MB** compressed (`tar.gz`) |
| **On-disk binary** | **~3.5 MB** (`x86_64-unknown-linux-gnu`, LTO + strip) |
| **Hard budget** | **< 5 MB** — asserted in `release.yml` on every tag |
| **Cold start** | **< 100 ms** to parse argv and print help |
| **Full test** | seconds — dominated by the target server's handshake latency, not mcpunit |
| **Runtime deps** | none (libc only) |
| **Memory footprint** | < 20 MB RSS for a typical test run |
| **CI install time** | **~1 second** — one `curl \| tar` and you're done |

Compare that with anything that needs `pip install`, `npm ci`, or a
whole container pull and you already know why mcpunit feels different
in CI. The release workflow asserts the binary size budget on every
tag, so it stays under 5 MB as the project evolves.

**Why it matters in CI:** faster install + faster start = faster PR
feedback. A quality gate that makes the build 30 seconds slower gets
disabled the first time someone is in a hurry. A quality gate that
adds two seconds stays on forever.

## ⚡ Quick start

### 1. Install

Pick one:

```bash
# Prebuilt binary — ~1.5 MB download, ready in 1 second
curl -L https://github.com/lee-to/mcpunit/releases/latest/download/mcpunit-x86_64-unknown-linux-gnu.tar.gz | tar -xz
./mcpunit --version

# Or build from source
cargo install --git https://github.com/lee-to/mcpunit --locked
```

Prebuilt binaries ship for Linux (x64 + arm64), macOS (Intel + Apple
Silicon), and Windows — all statically linked, all **under 5 MB on
disk**. See [releases](https://github.com/lee-to/mcpunit/releases).

### 2. Test your MCP server

Got a stdio server? One command:

```bash
mcpunit test --cmd node ./my-mcp-server.js
```

Even shorter — skip the subcommand entirely:

```bash
mcpunit ./my-mcp-server.js
```

The shorthand auto-detects the runtime from the file extension:
`.ts` → `npx tsx`, `.js` → `node`, `.py` → `python3`.

Need to set a working directory and environment? mcpunit auto-loads
`.env` from `--cwd`:

```bash
mcpunit test --cwd /path/to/project --cmd npx tsx src/index.ts
```

Override or add individual env vars with `--env` (repeatable):

```bash
mcpunit test --cwd /path/to/project \
  --env LOG_LEVEL=error \
  --cmd npx tsx src/index.ts
```

Got a Streamable HTTP server?

```bash
mcpunit test --transport http --url https://mcp.example.com/rpc
```

**That's it.** You get a score out of 100, a list of findings, and an
explanation of what to fix first. No configuration, no plugin
discovery, no YAML file, nothing to set up.

### 3. Want machine-readable output?

```bash
mcpunit test \
  --json-out audit.json \
  --sarif-out audit.sarif \
  --markdown-out audit.md \
  --cmd node ./my-mcp-server.js
```

- `audit.json` → full audit with every rule + finding
- `audit.sarif` → drop into GitHub Code Scanning
- `audit.md` → paste into a PR comment or step summary

### 4. Gate your CI on it

```bash
mcpunit test --min-score 80 --cmd node ./my-mcp-server.js
```

Exit codes you can trust:

| Exit | Meaning |
|------|---------|
| `0`  | ✅ Score ≥ `--min-score`. Ship it. |
| `2`  | 💥 Test blew up. Server crashed, timeout, bad flags. |
| `3`  | 📉 Test worked, score is below your threshold. Fix before merge. |

## 🚀 GitHub Action

If you're already using GitHub Actions, you don't even need to install
anything. Drop this into a workflow:

```yaml
name: MCP Quality
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npm ci

      - uses: lee-to/mcpunit@v1
        with:
          cmd: node ./my-mcp-server.js
          min-score: "80"
          upload-sarif: "true"
```

The action downloads the right prebuilt binary for the runner, caches
it, runs the test, and uploads a SARIF report to GitHub Code Scanning so
findings show up inline in your PR reviews.

Every input is documented in [`action.yml`](./action.yml).

## 🎯 What mcpunit catches

**17 rules across four categories.** Every rule ships with a stable
`rule_id`, deterministic evidence strings, and a fixed score penalty
— so you can diff two audits and get a sensible answer.

Severity levels and score penalty:

- `INFO` — `0` points. Surfaces a heads-up; does not affect score.
- `WARNING` — `-10` points. Worth fixing but won't break agents outright.
- `ERROR` — `-20` points. Expect broken agent behaviour or a security footgun.

Scores roll into four buckets: **conformance**, **security**,
**ergonomics**, **metadata**. Each bucket caps at 100; the total is
`max(100 - total_penalty, 0)`. No ML, no dark-magic heuristics — the
scoring is a pure function you can read top-to-bottom in
[`src/scoring.rs`](./src/scoring.rs).

Quick reference:

| # | Rule | Severity | Bucket |
|---|------|----------|--------|
| 1 | `duplicate_tool_names` | `ERROR` | conformance |
| 2 | `missing_tool_description` | `WARNING` | metadata |
| 3 | `overly_generic_tool_name` | `WARNING` | ergonomics |
| 4 | `vague_tool_description` | `WARNING` | ergonomics |
| 5 | `missing_schema_type` | `WARNING` | conformance |
| 6 | `schema_allows_arbitrary_properties` | `WARNING` | conformance |
| 7 | `weak_input_schema` | `WARNING` | ergonomics |
| 8 | `missing_required_for_critical_fields` | `WARNING` | conformance |
| 9 | `dangerous_exec_tool` | `ERROR` | security |
| 10 | `dangerous_shell_download_exec` | `ERROR` | security |
| 11 | `dangerous_fs_write_tool` | `ERROR` | security |
| 12 | `dangerous_fs_delete_tool` | `ERROR` | security |
| 13 | `dangerous_http_request_tool` | `ERROR` | security |
| 14 | `dangerous_network_tool` | `ERROR` | security |
| 15 | `write_tool_without_scope_hint` | `WARNING` | ergonomics |
| 16 | `tool_description_mentions_destructive_access` | `WARNING` | metadata |
| 17 | `response_too_large` | `WARNING` / `ERROR` | ergonomics |

Deep dive by category follows.

### 🧩 Identity — how tools name themselves

The tool name is the first thing the model reads. Noise here hurts
every single call.

#### `duplicate_tool_names` — `ERROR`

**What it catches.** Two tools in the same server published under the
same `name`.

**Why it matters.** The MCP client has to invoke tools by string name.
If there are two `search` tools, the model cannot target the one it
actually wants — the client library will either silently pick the
first one or fail with an ambiguity error. Either way the agent's
intent is lost.

**Example evidence:** `duplicate_count=2`, `tool_name=search`.

#### `overly_generic_tool_name` — `WARNING`

**What it catches.** Names that carry zero behavioural information:
`do_it`, `helper`, `tool`, `utility`, `misc`, `misc_tool`, `action`,
`process`, `handler`, `run`.

**Why it matters.** When the model has to choose between `send_invoice`
and `do_it`, it will retry, hallucinate, or pick wrong. Good tool
naming is a 30% quality win for free.

**How to fix:** rename to a verb-noun that says what the tool does —
`do_it` → `mark_task_complete`, `helper` → `format_phone_number`.

### 📝 Description — how tools explain themselves

Names get you in the door. Descriptions get the model to the right
row.

#### `missing_tool_description` — `WARNING`

**What it catches.** Tools where the `description` field is absent or
`null`.

**Why it matters.** Without a description the model has only the name
and the input schema to guess intent. That's enough for `add_two_numbers`
but not for `reconcile_ledger`. Any non-trivial tool **must** ship with
a description.

#### `vague_tool_description` — `WARNING`

**What it catches.** Descriptions matching a known vague phrase
(`"helps with stuff"`, `"does things"`, `"utility tool"`, `"misc helper"`)
or a three-word-or-less string containing a vague keyword (`stuff`,
`things`, `helper`, `misc`, `various`, `general`).

**Why it matters.** A vague description is *worse* than no description
— it makes the model overconfident. The tool ends up picked for cases
it does not handle, and the failure mode is often silent.

**How to fix:** describe the **inputs**, **outputs**, and **when to
use it** in 1–3 sentences.

### 📐 Schema — how tools constrain their inputs

The input schema is the contract the model has to conform to. Weak
schemas leak malformed payloads to your backend and burn tokens on
retries.

#### `missing_schema_type` — `WARNING`

**What it catches.** An input schema with no top-level `type` field
on a tool that clearly takes input (name or description contains
`input`, `payload`, `send`, `submit`, `query`, ...).

**Why it matters.** Without a top-level type the model does not know
whether to pass an object, an array, or a primitive. Most clients
default to `object`, which may or may not match what your server
expects.

#### `schema_allows_arbitrary_properties` — `WARNING`

**What it catches.** An `object` schema with
`additionalProperties: true` (explicit, not the JSON Schema default).

**Why it matters.** `additionalProperties: true` says "any extra key
is fine", which lets the model pass junk that the backend has to
either reject or silently drop. In both cases you pay in bad agent
behaviour. Set `additionalProperties: false` unless you really mean
"open-ended payload".

#### `weak_input_schema` — `WARNING`

**What it catches.** Two patterns:

1. An inputful tool (name/description implies free-form input) with an
   empty object schema.
2. An object schema that has a generic catch-all property (`payload`,
   `data`, `body`, `request`, `params`, `options`, ...) whose own type
   is missing or is an unconstrained `object`.

**Why it matters.** Generic `payload` / `data` objects are the
single largest source of "the model sent something the server did
not expect". Constraining them with real field definitions — even
partial — stops 80% of the retry loop.

#### `missing_required_for_critical_fields` — `WARNING`

**What it catches.** A field named `command`, `path`, `file_path`,
`filepath`, `url`, `uri`, or `endpoint` is declared in `properties`
but is **not** listed in `required`.

**Why it matters.** If a tool takes an optional `path` the model will
invoke it without one, get an error, retry with a guess, and you'll
see `undefined` or `""` land in production logs. Critical fields
should be required so the model knows it must supply them.

### 🔐 Capability — what tools can actually do

Rules 9–17 inspect the **semantics** of a tool, not just its shape.
This is where the security bucket lives.

mcpunit is not an exploit detector — it does not execute the tool or
reason about real security properties. It looks at the advertised
surface and flags the patterns most likely to turn into an incident
when combined with an over-eager LLM. Treat these as **signals that
humans must review**, not as exploit proofs.

#### `dangerous_exec_tool` — `ERROR`

**What it catches.** Tools whose name contains an exec marker
(`exec`, `shell`, `command`, `cmd`, `bash`, `powershell`, `terminal`)
AND whose description or inputs confirm command execution.

**Why it matters.** A tool that accepts an arbitrary command string
and runs it in a shell is the single riskiest thing an MCP server
can expose. Combined with an agent that "just wants to be helpful",
it's a `rm -rf /` vulnerability waiting to trigger. Scope these
tools ruthlessly or drop them.

#### `dangerous_shell_download_exec` — `ERROR`

**What it catches.** The classic "curl | sh" pattern — a tool that
both fetches a remote resource (`download`, `fetch`, `curl`, `wget`,
or accepts a `url` input) *and* exposes an exec surface.

**Why it matters.** Even a well-sandboxed exec tool becomes a
supply-chain hole the moment the agent can feed it a URL it fetched
from the open web. This rule specifically catches the combination —
the whole is strictly worse than the parts.

#### `dangerous_fs_write_tool` — `ERROR`

**What it catches.** Tools that combine write verbs (`write`, `save`,
`append`, `create`, `update`, `edit`) with filesystem vocabulary
(`file`, `disk`, `path`, `directory`) and accept a path input.

**Why it matters.** The model will absolutely use a `write_file` tool
to overwrite `/etc/hosts` if you let it. Scoping and sandboxing is
non-negotiable — see also `write_tool_without_scope_hint` below.

#### `dangerous_fs_delete_tool` — `ERROR`

**What it catches.** Same shape as `dangerous_fs_write_tool` but with
delete verbs (`delete`, `remove`, `rm`, `unlink`, `erase`, `truncate`).
Uses whole-word tokenisation so `undelete` does **not** trip the rule.

**Why it matters.** Delete is strictly worse than write — writes are
idempotent, deletes are not. A `delete_file(path)` tool plus an
agent loop is a production incident one hallucination away.

#### `dangerous_http_request_tool` — `ERROR`

**What it catches.** Tools that accept a `url` / `uri` / `endpoint`
field and have HTTP-ish names (`http`, `fetch`, `request`, `post`,
`get`, `webhook`, `download`, `upload`).

**Why it matters.** A generic "fetch any URL" tool is a SSRF vector —
the agent can be talked into hitting `http://169.254.169.254/latest/meta-data/`
(cloud metadata), `http://localhost:5432/` (internal databases), or
`file://` URLs. If you really need outbound HTTP, allowlist the
domains inside your server, not inside the model.

#### `dangerous_network_tool` — `ERROR`

**What it catches.** Lower-level networking primitives — tools whose
name contains `connect`, `socket`, `proxy`, `tunnel`, `forward`,
`listen`, `tcp`, `udp`, AND accept network metadata (`host`, `port`,
`address`, ...).

**Why it matters.** A "connect to arbitrary TCP host:port" tool is
effectively a reverse shell for the agent. Almost no legitimate MCP
server needs this — if you have it, you probably want a narrower
abstraction.

#### `write_tool_without_scope_hint` — `WARNING`

**What it catches.** A filesystem-mutating tool whose description
does **not** advertise any scope restriction (keywords:
`allowed directories`, `within allowed`, `working directory`,
`workspace`, `sandbox`, `project directory`, `scoped`).

**Why it matters.** A `write_file(path, content)` with a two-line
description like "write content to file" gives the user zero
signal about whether it's sandboxed. Even if your server *is*
sandboxed under the hood, **say so in the description** — the model
will read it and adjust behaviour.

#### `tool_description_mentions_destructive_access` — `WARNING`

**What it catches.** Descriptions that explicitly brag about broad
destructive power — combinations of destructive verbs (`delete`,
`remove`, `erase`, `overwrite`, `truncate`, `destroy`) with
broad-scope markers (`arbitrary`, `any file`, `any directory`,
`host machine`, `without validation`).

**Why it matters.** A description that says "deletes any file on
the host machine" is a social-engineering vector — some agents will
interpret broad capability claims as license to use them. Rephrase
to describe the **safe** subset: "deletes files inside the active
workspace".

#### `response_too_large` — `WARNING` / `ERROR`

**What it catches.** The size of the `tools/list` response observed
on the wire. **Warning** at ≥ 256 KiB, **error** at ≥ 1 MiB. Uses
the real byte count captured by the transport layer.

**Why it matters.** Every MCP call carries `tools/list` metadata in
the agent's context window. If your `tools/list` is a megabyte, the
agent spends its context budget reading you instead of doing work.
Worst case, the request exceeds the model's context and fails
outright. Trim long descriptions, flatten verbose schemas, split
servers by domain.

**How to fix:** if your `tools/list` is too large, you probably have
too many tools in one server. Split by bounded context.

## 📄 What the reports look like

A real audit of the bundled demo server lives in
[`.reports/`](./.reports). Highlights:

### Terminal

```
Generator: mcpunit (mcpunit 1.0.0)
Server: mcpunit demo server
Tools: 4
Finding Counts: total=7, error=2, warning=5, info=0
Total Score: 10/100
Why This Score: Score is driven mainly by security findings in command
execution and file system and ergonomics findings.

Category Scores:
- conformance: 90/100
- security:    60/100
- ergonomics:  60/100
- metadata:   100/100

Findings By Bucket:
- security: 2 findings, penalties: 40
  - ERROR dangerous_exec_tool    [exec_command]: Tool 'exec_command' appears
    to expose host command execution.
  - ERROR dangerous_fs_write_tool [write_file]: Tool 'write_file' appears
    to provide filesystem write access.
- ergonomics: 4 findings, penalties: 40
  - WARNING overly_generic_tool_name [do_it]: ...
  - WARNING vague_tool_description   [do_it]: ...
  ...
```

### JSON (excerpt)

```json
{
  "schema": {
    "id": "https://mcpunit.cutcode.dev/schema/audit/v1",
    "version": "1",
    "generator": { "name": "mcpunit", "version": "1.0.0" }
  },
  "audit": {
    "total_score": { "value": 10, "max": 100, "penalty_points": 90 },
    "category_scores": {
      "conformance": { "score": 90, "penalty_points": 10, "finding_count": 1 },
      "security":    { "score": 60, "penalty_points": 40, "finding_count": 2 },
      "ergonomics":  { "score": 60, "penalty_points": 40, "finding_count": 4 },
      "metadata":    { "score": 100, "penalty_points":  0, "finding_count": 0 }
    }
  },
  "findings": [ /* 7 findings with rule_id, severity, evidence, ... */ ]
}
```

Full examples:

- [`.reports/demo.txt`](./.reports/demo.txt) — terminal output
- [`.reports/demo.json`](./.reports/demo.json) — structured JSON
- [`.reports/demo.sarif`](./.reports/demo.sarif) — SARIF 2.1.0
- [`.reports/demo.md`](./.reports/demo.md) — markdown summary

## 🛠 CLI reference

```bash
mcpunit test --help
```

Most-used flags:

| Flag | Purpose |
|------|---------|
| `--cmd <ARGV>...`         | Launch an MCP server over stdio. Put this last. |
| `--url <URL>`             | Test a Streamable HTTP server. |
| `--transport <stdio\|http>` | Override transport detection. |
| `--cwd <PATH>`            | Working directory for the subprocess. |
| `--env <KEY=VALUE>`       | Extra env var for the subprocess (repeatable). |
| `--dotenv <PATH>`         | Path to dotenv file. Default: `.env` in `--cwd`. |
| `--header "K: V"`         | Extra HTTP header (repeatable). |
| `--timeout <SECONDS>`     | Per-request deadline. Default: 10. |
| `--min-score <0..100>`    | Fail with exit 3 when total score is lower. |
| `--max-response-bytes <N>`| Hard cap per JSON-RPC response. Default: 1 MiB. |
| `--json-out <PATH>`       | Write the full JSON audit here. |
| `--sarif-out <PATH>`      | Write the SARIF report here. |
| `--markdown-out <PATH>`   | Write the Markdown summary here. |
| `--log <FILTER>`          | `tracing`-style log filter. Default: `info`. |

Shorthand: `mcpunit ./server.ts` is equivalent to `mcpunit test --cmd npx tsx ./server.ts`.
Runtime is auto-detected from the file extension (`.ts` → `npx tsx`, `.js` → `node`, `.py` → `python3`).
The `.env` file in `--cwd` (or the current directory) is loaded automatically when present.
Non-JSON-RPC lines on stdout (e.g. logger output) are skipped with a warning.

## 🧪 Using mcpunit as a Rust library

```toml
[dependencies]
mcpunit = "1"
```

```rust
use mcpunit::scoring::scan;
use mcpunit::transport::{stdio::{StdioConfig, StdioTransport}, Transport};

let cfg = StdioConfig::new(vec!["node".into(), "my-server.js".into()]);
let mut transport = StdioTransport::spawn(cfg)?;
let server = transport.scan("stdio:my-server".into())?;

let report = scan(server, 100);
println!("score: {}/{}", report.score.total_score, report.score.max_score);
for finding in &report.findings {
    println!("- [{}] {}: {}", finding.level.as_str(), finding.rule_id, finding.message);
}
```

Public API:

- [`mcpunit::models`](./src/models.rs) — `Finding`, `Severity`, `ScoreBucket`
- [`mcpunit::rules`](./src/rules/mod.rs) — `trait Rule` + `REGISTRY`
- [`mcpunit::scoring`](./src/scoring.rs) — `scan()` + `Report`
- [`mcpunit::reporters`](./src/reporters/mod.rs) — JSON / SARIF / Markdown / Terminal
- [`mcpunit::transport`](./src/transport/mod.rs) — stdio + Streamable HTTP

## 🏗 Development

```bash
git clone https://github.com/lee-to/mcpunit
cd mcpunit
make check   # fmt-check + clippy + test — same as CI
make demo    # build release + test the bundled demo server
make reports # regenerate .reports/demo.*
```

All make targets are thin wrappers around `cargo`, so you can always
bypass `make` entirely. See `make help` for the full list.

Contributions are welcome — start with
[`CONTRIBUTING.md`](./CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

## 🔒 Security

Found a vulnerability? **Please do not file a public issue.** Read
[`SECURITY.md`](./SECURITY.md) and email <thecutcode@gmail.com>.

## 📜 License

MIT © 2026 [Danil Shutsky](https://cutcode.dev) · <thecutcode@gmail.com>

---

<div align="center">

**Built with ❤️ for the MCP ecosystem by [cutcode.dev](https://cutcode.dev)**

If mcpunit catches a bug in your server before your users do, a ⭐ on
GitHub is all the thanks needed.

</div>
