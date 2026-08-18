<!--
Read CONTRIBUTING.md first. Keep the PR narrowly scoped: bulky diffs across
many files may be closed without review. Delete sections that do not apply.
-->

## Summary

<!-- What changes, and why. One paragraph is usually enough. -->

## What changed

<!-- The reviewer-facing shape of the diff: which modules, which behavior. -->

-

## Verification

<!--
How you know it works, beyond "CI is green". For behavior changes, the
before/after output. For bug fixes, the failing case and that it now passes.
-->

```
```

## Checklist

- [ ] `uv run pytest` passes locally.
- [ ] `uv run prek run --all-files` passes locally.
- [ ] New or changed behavior is covered by tests with non-vacuous assertions.
- [ ] Public functions have numpy-style docstrings with the applicable `Parameters`/`Returns`/`Raises` sections.
- [ ] No new `noqa`, `type: ignore`, `Any`, or `object` (or I explain below why there is no alternative).
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]` (skip for internal-only changes).

<!-- Only if the PR touches these areas: -->

- [ ] **Report models changed:** `liveness-primer schema export` re-run and the regenerated `liveness_primer/schemas/` committed; `schema_version` bumped if a payload changed.
- [ ] **Corpus changed:** `corpus validate` and `corpus license-check` pass; new entries are GitHub-hosted, allowlisted, and pinned to a full commit SHA.
- [ ] **Explorer changed:** the `explorer/` gate chain passes locally, including regenerated Ajv validators if a schema moved.

## AI assistance

<!--
Per CONTRIBUTING.md: assistance is allowed, unreviewed output is not. A single
line is enough, and disclosure is not held against you. Delete this section if
only assistive uses (spelling, formatting, lookups) were involved.
-->

Details:

## Notes for the reviewer

<!-- Anything you are unsure about, deliberate trade-offs, or follow-up work. -->
