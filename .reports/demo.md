# mcpunit Audit — mcpunit demo server

**Total score:** `10 / 100`  
**Findings:** 7 (error: 2, warning: 5, info: 0)  
**Tools discovered:** 4

## Category Scores

| Bucket | Score | Findings | Penalty |
| --- | --- | --- | --- |
| conformance | 90/100 | 1 | 10 |
| security | 60/100 | 2 | 40 |
| ergonomics | 60/100 | 4 | 40 |
| metadata | 100/100 | 0 | 0 |

## Findings By Bucket

### security (2 findings, penalty: 40)

- **ERROR** `dangerous_exec_tool` `[exec_command]`: Tool 'exec_command' appears to expose host command execution.
- **ERROR** `dangerous_fs_write_tool` `[write_file]`: Tool 'write_file' appears to provide filesystem write access.

### ergonomics (4 findings, penalty: 40)

- **WARNING** `weak_input_schema` `[debug_payload]`: Tool 'debug_payload' exposes a weak input schema that leaves free-form input underconstrained.
- **WARNING** `overly_generic_tool_name` `[do_it]`: Tool 'do_it' uses an overly generic name that hides its behavior.
- **WARNING** `vague_tool_description` `[do_it]`: Tool 'do_it' uses a vague description that does not explain its behavior clearly.
- **WARNING** `write_tool_without_scope_hint` `[write_file]`: Tool 'write_file' modifies the filesystem without any visible scope hint.

### conformance (1 finding, penalty: 10)

- **WARNING** `schema_allows_arbitrary_properties` `[debug_payload]`: Tool 'debug_payload' allows arbitrary additional input properties.

## Limitations

- Low score means more deterministic findings or higher-risk exposed surface, not malicious intent.
- High score means fewer deterministic findings, not a guarantee of safety.
