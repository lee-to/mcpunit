# Link a metadata audit to behavioral evidence

A score of 100/100 describes the advertised MCP metadata under mcpunit's
rules. It does not establish that a tool performs its promised operation.
Use a separate behavioral fixture to check observable effects, then link
the two reports to the same server revision and configuration.

This example runs entirely locally with Python 3.9+ and the existing
mcpunit CLI. It uses Python's standard library, no SDK, model, credentials,
live provider calls, or network service. Python is only a dependency of
this example; mcpunit's runtime requirements are unchanged.

## Run the negative control

From the repository root:

```bash
cargo build --locked --bin mcpunit
python3 examples/behavioral-evidence/run.py \
  --mcpunit target/debug/mcpunit \
  --out target/behavior-broken --mode broken
```

The runner exits **1**, with `audit=completed; behavior=failed`. This is
the expected result of the negative control:

1. mcpunit initializes the synthetic server and reads `tools/list`.
   `record_note` advertises a clear description and constrained input
   schema. The audit scores **100/100**, with no findings.
2. An independent fixture starts the same source revision with exactly
   the same command and working directory, then invokes `record_note`.
3. The tool returns `isError: false` and a success message, but broken mode
   does not record the note in its local fake backend.
4. The fixture reads `effects.jsonl` directly. The assertion that the
   expected note was recorded exactly once fails because the journal is
   empty. It does not trust the tool's success message as proof of an effect.

The audit itself must leave the journal empty; the runner checks this
before starting the behavioral fixture. Each invocation requires a new
output directory to prevent stale evidence from another run being reused.
Choose another `--out` path when repeating the example.

## Compare a working backend and a missing run

```bash
python3 examples/behavioral-evidence/run.py \
  --mcpunit target/debug/mcpunit \
  --out target/behavior-working --mode working

python3 examples/behavioral-evidence/run.py \
  --mcpunit target/debug/mcpunit \
  --out target/behavior-missing --mode working --skip-behavior
```

Working mode exits **0**: the metadata audit is still 100/100, and the
behavioral fixture passes after reading the expected journal entry.
Skipping behavior exits **2**, even though the metadata audit passes.

These are the **example runner's** exit codes, not additions to mcpunit's
CLI exit codes:

| Exit | Meaning |
| --- | --- |
| 0 | Metadata gate and all behavioral assertions passed. |
| 1 | Metadata gate passed; a completed behavioral assertion failed. |
| 2 | Evidence is unavailable or incomplete, or the metadata gate did not pass. |

## Inspect the separate reports

Each output directory contains:

| Artifact | Meaning |
| --- | --- |
| `audit.json`, `audit.sarif`, `audit.md`, `audit.txt` | Existing mcpunit reports, with their existing schemas and score semantics. |
| `behavior.json` | Independent fixture outcome, assertion results, tool response, and expected/observed effects; absent if behavior was skipped. |
| `effects.jsonl` | Fake backend journal, read independently of the tool response. |
| `manifest.json` | External composition record linking the audit and behavioral run. |

The generated manifest has the following structure (angle-bracket values
below are illustrative placeholders, not recorded evidence):

```json
{
  "schema": "mcpunit-behavior-composition-example/v1",
  "composition_id": "<unique composition UUID>",
  "created_at": "<UTC timestamp>",
  "subject": {
    "server": {
      "name": "synthetic-note-server",
      "version": "<server.py SHA-256>"
    },
    "revision": {"kind": "source-sha256", "value": "<server.py SHA-256>"},
    "configuration": {
      "command": ["<python>", "<server.py>", "--mode", "broken", "--journal", "<effects.jsonl>"],
      "cwd": "<output directory>"
    },
    "configuration_sha256": "<SHA-256 of the configuration object>"
  },
  "audit": {
    "status": "completed",
    "scope": "metadata-and-schema",
    "exit_code": 0,
    "total_score": 100,
    "report": {"path": "audit.json", "sha256": "<audit report SHA-256>"}
  },
  "behavior": {
    "status": "failed",
    "run_id": "<unique behavioral run UUID>",
    "report": {"path": "behavior.json", "sha256": "<behavior report SHA-256>"}
  }
}
```

`behavior.json` repeats the full `subject` and the behavioral `run_id`,
records a SHA-256 of the fixture code, and references the journal with its
SHA-256. Paths in artifact references are relative to the manifest's
directory. The server advertises its source digest as its version; the
runner verifies that identity in both sessions and checks that the source
has not changed. Configuration digests use UTF-8 encoded
`json.dumps(configuration, sort_keys=True)` with Python's default separators.
The configuration includes the mode and absolute journal path; different
output directories therefore intentionally have different digests.

The behavioral status is explicit:

| Status | Meaning |
| --- | --- |
| `passed` | The fixture completed and every assertion passed. |
| `failed` | The fixture completed and at least one assertion failed. |
| `missing` | The fixture was not started; `run_id` and `report` are null. |
| `incomplete` | The fixture started but did not complete reliably, for example because of a timeout, process error, malformed response, or changed server revision. |

The runner writes `incomplete` before invoking the tool, then finalizes
the outcome. A timeout kills and reaps the child process; a hard
interruption leaves the initial incomplete record. That initial manifest
reference has a path but no digest until the report is finalized. A
missing report, digest mismatch, subject mismatch, or unfinished record
must never be interpreted as a pass. The audit status similarly stays
`incomplete` if its invocation or identity checks fail.

The manifest is an **external example format**, not an extension of
mcpunit's JSON or SARIF contract. Behavioral failures do not change rule
IDs, findings, or audit scores. No external evidence becomes a scoring
rule. SHA-256 links identify artifacts and detect changes; they do not
authenticate an external producer or prove the evidence is trustworthy.

## Apply the recipe in CI

For your own server, pin both jobs to the same immutable server build or
source revision and the same relevant configuration. Record the image or
build digest, configuration fingerprint, behavioral run ID, and report
references in a separate manifest. Server name/version alone may not
identify an exact build. Redact credentials rather than copying secret
values into a manifest.

Run behavioral tests explicitly against a disposable backend with an
independent observable effect, such as a fake database, journal, or local
filesystem fixture. Keep the metadata gate and behavioral gate distinct.
Upload the manifest and both reports even when the behavioral job fails;
require `passed` plus matching identities and completed reports for the
behavioral gate. A successful metadata gate alone cannot satisfy it.

This single-note fixture only establishes its one assertion for its one
configuration. It is not proof that every tool or production scenario
works. The example does not add automatic mutating tool calls to audits
or implement the roadmap's optional live-check feature.

## Verify the example

```bash
cargo build --locked --bin mcpunit
python3 -m unittest discover -s examples/behavioral-evidence -v
```

The checks cover the negative control, working backend, missing behavior,
an actual child-process timeout and malformed response producing incomplete
evidence, an audit startup failure, artifact links, and refusal to overwrite
earlier runs.
