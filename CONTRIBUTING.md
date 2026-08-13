# Contributing

Thanks for your interest. This is a small project with deliberately strict gates —
reading this first will save you a review round.

Please open an issue before starting anything substantial.

## Development setup

```bash
uv sync --extra dev
```

Run the suite and the hooks before pushing:

```bash
uv run pytest
```

```bash
uv run prek run --all-files
```

The `prek` hooks include `ruff check --fix --preview`, `ruff format`, `ssort`,
`pyrefly`, and `actionlint`. CI additionally runs `mypy --strict`, `pyright`,
`pydoclint`, a `skylos` dead-code job, and a coverage job.

## House rules

These are enforced by CI, so they are not stylistic preferences:

- **Strict typing.** Use the narrowest type that fits. Avoid `Any` and `object`
  unless the function genuinely accepts anything. Do not add `type: ignore`
  without asking first.
- **No `noqa`.** `ruff` runs with `ALL` rules selected. If a rule fires,
  restructure the code rather than silencing it.
- **Docstrings.** Very brief, numpy style, checked by `pydoclint`. Public
  functions need `Parameters`/`Returns`/`Raises` sections where applicable.
- **Tests.** `pytest` style, aiming at full line and branch coverage with
  non-vacuous assertions. A test that only asserts a function returns without
  raising will be sent back.
- **Licensing.** New source files carry the SPDX header used throughout
  `liveness_primer/`. Contributions are accepted under Apache-2.0.

Corpus changes have their own gate: `corpus validate` and a GitHub license
check run on PRs touching
[liveness_primer/data/corpus.yaml](liveness_primer/data/corpus.yaml). New
entries must be GitHub-hosted, permissively licensed per the §6 allowlist, and
pinned to a full commit SHA.

## Use of AI tools

AI assistance is allowed. Unreviewed AI output is not. The bar is unchanged
whatever produced the diff: correctness, and a contributor who understands what
they submitted.

1. **You own the contribution.** Whatever generated it, you are the author of
   record and responsible for it being correct.
2. **Disclose material assistance.** If an AI tool meaningfully produced the
   code, tests, issue report, or review, say so in the pull request. A single
   line is enough. Disclosure is not held against you; undisclosed AI output
   that turns out to be wrong is.
3. **Be able to explain it.** Do not submit anything you cannot walk through
   and defend — why this approach, what the edge cases are, why the tests cover
   them.
4. **Expect to be asked.** For contributions that look machine-generated, the
   maintainer may ask for an explanation, a reproduction, or evidence the tests
   actually exercise the change before reviewing further. Unanswered, such a PR
   will be closed.

Assistive uses — spelling, formatting, looking things up, tightening prose —
need no disclosure.

PRs should be narrowly scoped for reviewability; bulky PRs against many files
at once or with many lines of churn may be closed without review.

## Reporting bugs

Include the version or commit, the exact command, the relevant corpus entry,
and the actual versus expected output. For anything security-relevant, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.
