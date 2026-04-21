# mcpunit Audit — mcpunit demo server

**Total score:** `10 / 100`  
**Findings:** 9 (error: 2, warning: 5, info: 2)  
**Tools discovered:** 4

## Category Scores

| Bucket | Score | Findings | Penalty |
| --- | --- | --- | --- |
| conformance | 90/100 | 1 | 10 |
| security | 60/100 | 2 | 40 |
| ergonomics | 60/100 | 4 | 40 |
| metadata | 100/100 | 2 | 0 |

## Findings By Bucket

### security (2 findings, penalty: 40)

- **ERROR** `dangerous_exec_tool` `[tool:exec_command]`: Tool 'exec_command' appears to expose host command execution.
- **ERROR** `dangerous_fs_write_tool` `[tool:write_file]`: Tool 'write_file' appears to provide filesystem write access.

### ergonomics (4 findings, penalty: 40)

- **WARNING** `weak_input_schema` `[tool:debug_payload]`: Tool 'debug_payload' exposes a weak input schema that leaves free-form input underconstrained.
- **WARNING** `overly_generic_tool_name` `[tool:do_it]`: Tool 'do_it' uses an overly generic name that hides its behavior.
- **WARNING** `vague_tool_description` `[tool:do_it]`: Tool 'do_it' uses a vague description that does not explain its behavior clearly.
- **WARNING** `write_tool_without_scope_hint` `[tool:write_file]`: Tool 'write_file' modifies the filesystem without any visible scope hint.

### conformance (1 finding, penalty: 10)

- **WARNING** `schema_allows_arbitrary_properties` `[tool:debug_payload]`: Tool 'debug_payload' allows arbitrary additional input properties.

### metadata (2 findings, penalty: 0)

- **INFO** `prompt_missing_description` `[prompt:summarize]`: Prompt 'summarize' has no description.
- **INFO** `prompt_argument_missing_description` `[prompt:translate]`: Prompt 'translate' has 1 argument(s) without description.

## Limitations

- Low score means more deterministic findings or higher-risk exposed surface, not malicious intent.
- High score means fewer deterministic findings, not a guarantee of safety.
