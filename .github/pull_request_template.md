<!--
Thanks for the PR! A few questions before you open it:

- Is this PR tied to an existing issue? If yes, link it below.
- Is this a bug fix, a new feature, or a refactor?
- Have you regenerated `.reports/` and the insta snapshots if your
  change affects output?
-->

## Summary

<!-- What does this PR do? One or two sentences is usually enough. -->

## Motivation

<!-- Why is this change needed? What problem does it solve? -->

## Changes

<!-- Bullet list of the concrete changes. -->

-
-
-

## Checklist

- [ ] `cargo fmt --check` is clean
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo test` passes locally
- [ ] Snapshot tests (`tests/snapshots/`) are either untouched or
      regenerated intentionally (`cargo insta review`)
- [ ] `.reports/` regenerated if rule / reporter / scoring changed
- [ ] New CLI flags / action inputs documented in `README.md` and
      `action.yml`
- [ ] New rules ship with unit tests and a stable `rule_id`

## Related issues

<!-- Closes #123, relates to #456, ... -->

## AI assistance

<!--
Honesty helps review. Tell us whether you used an AI assistant while
preparing this PR, and if so — which one. You stay responsible for the
correctness of the change either way; this is purely informational and
has no effect on review outcome.

Examples of a good answer:
- "No AI used — hand-written."
- "Claude Sonnet 4.5 for the rule evaluator, then manually reviewed every line."
- "GitHub Copilot inline suggestions for the test file only."
- "ChatGPT (GPT-5) to draft the docstring, then rewrote it myself."
-->

- [ ] I did **not** use an AI assistant for this PR.
- [ ] I used an AI assistant — model / tool: `<e.g. Claude Sonnet 4.5, GitHub Copilot, ChatGPT GPT-5>`
  - Scope: `<what the AI touched — whole PR, tests only, docstrings, ...>`
  - I reviewed every AI-generated line before committing it.
