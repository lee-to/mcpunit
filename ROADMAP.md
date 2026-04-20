# Roadmap

mcpunit's release cadence is feature-driven: each minor version adds one
coherent slice of audit surface. Patch versions are bug fixes and
dependency bumps only. Everything listed here is a plan, not a promise —
priority reacts to user feedback.

## Shipped

### 1.0 — tool surface baseline

- 17 rules across identity / description / schema / capability buckets.
- Stdio and Streamable HTTP transports.
- JSON, SARIF, Markdown, terminal reporters.
- GitHub Action wrapper.

### 1.1 — prompt surface

- Discover prompts via `prompts/list` when the server advertises
  `capabilities.prompts`.
- 6 rules on prompt hygiene: duplicate name, duplicate argument,
  missing/too-short/name-matching description, undocumented arguments.
- `Finding.prompt_name` field; terminal and markdown reporters tag
  findings with `[tool:<name>]` or `[prompt:<name>]`.
- Alpine / musl static binaries in the release matrix.

## Next — 1.2: resources surface

**Goal:** make mcpunit useful for servers that expose
`capabilities.resources` (templates, read-only references, etc.).

Planned work:

- Extend the transport with `list_resources()` plus `list_resource_templates()`
  following the same cursor-pagination pattern as `list_tools`.
- Model `NormalizedResource` and `NormalizedResourceTemplate` on
  `NormalizedServer`; add `Finding.resource_name` / `template_name`
  subject fields.
- First-pass rule set, analogous in spirit to the prompt family:
  - `resource_duplicate_uri` — two resources at the same URI.
  - `resource_missing_description` — no description or empty.
  - `resource_description_too_short` — stub descriptions.
  - `resource_missing_mime_type` — clients that render by MIME need it.
  - `resource_template_missing_placeholder_description` — template
    declares `{placeholder}` but no description for it.

Gating criterion for shipping: at least one real prompts+resources
server in the wild scans clean under the combined rule set without
false positives.

## Then — 1.3: prompt-body injection signals

**Goal:** headline security feature — detect prompt templates that are
vulnerable to injection or silently change agent behaviour.

Planned work:

- New transport method `get_prompt(name, arguments)` that issues
  `prompts/get` with synthesised argument values. Required by every
  injection check since `prompts/list` does not carry the template body.
- `--skip-prompt-bodies` CLI flag for users who want to audit prompt
  metadata but keep the scan non-invasive (e.g. servers that rate-limit
  or have observable side effects on `prompts/get`).
- Rule candidates:
  - `prompt_placeholder_not_declared` — body references
    `{{placeholder}}` that is absent from the `arguments` list.
  - `prompt_argument_not_referenced` — opposite direction: an argument
    is declared but never referenced from the body.
  - `prompt_body_mentions_override` — body contains known injection
    markers (`ignore previous instructions`, `you are now`,
    `system:` prefix, role-override phrasing). Maintained as an
    explicit marker list that ships with mcpunit so findings are
    stable across versions.
  - `prompt_body_too_large` — body over a configurable byte budget;
    large prompt bodies are a context-window footgun, same shape as
    `response_too_large`.

Gating criterion for shipping: marker list pass-tested against a
corpus of known-good and known-bad prompts, false-positive rate
documented in the rule rationale.

## Later — candidate slices

These are under consideration; order is not fixed and the list is open
to contribution.

- **Live health checks.** Opt-in `--live` flag that actually invokes a
  chosen tool or prompt and asserts a schema-conformant response.
  Currently every rule reads metadata only; live checks would catch
  servers that advertise a schema the implementation does not honour.
- **Deny-list overrides.** Per-rule suppression file (`.mcpunit.toml`)
  so teams can shelve a warning class without patching the scanner.
- **Diff mode.** `mcpunit diff audit-a.json audit-b.json` that reports
  regressions and improvements between two scans, intended for CI
  summary comments on pull requests.
- **JSON-Schema conformance beyond Draft-07.** Current schema rules
  match the MCP spec as of writing. When the spec ratchets up the
  schema dialect (Draft 2020-12, etc.) the rules follow.

## Not planned

- **Runtime fuzzing.** Out of scope — mcpunit is a deterministic
  metadata audit; randomised input lives in `cargo fuzz` already.
- **Autofix.** Rules report, they do not rewrite. Fix-on-your-side is
  a deliberate product boundary: we will not silently edit third-party
  MCP servers.
