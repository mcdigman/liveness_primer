# Implementation contract for `liveness_primer`

`liveness_primer` is a `mypy_primer`-style tool for dead-code detectors. It runs a Python
dead-code detector at two revisions — the base and head of a PR to the *detector* — against a
fixed corpus of open-source projects, and reports the *blast radius*: the structured diff of
the detector's findings, for human or LLM review.

## 1. Scope and non-goals

v1 non-goals:

- Adjudicating whether a diff is *correct*. A new finding may be a false positive or a
  recovered false negative; a dropped finding may be either. The core reports the diff;
  judgment belongs to reviewers and optional triage hooks.
- Auto-fixing dead code.
- Project-under-test mode (fixed detector, varying corpus revision). A possible future
  extension; the corpus pin design must not preclude it, but v1 does not implement it.

## 2. Terminology

*Detector*: the dead-code tool under test. *Corpus project*: a repository the detector runs
against. *Finding*: one normalized detector report item. *Finding identity*: the stable hash
naming a finding across runs (§7). *Diff class*: `new`, `dropped`, or `confidence-changed`.
*Run manifest*: the record of resolved refs, versions, and settings for one run. *Blast
radius*: all finding diffs plus summary totals. *Hook binding point*: pre-triage, triage, or
post-triage (§10).

## 3. Operating model

- The detector is obtained by cloning its repository and installing the base and head refs
  into two isolated cached virtualenvs (`uv pip` when on `PATH`, stdlib `venv` + `pip`
  fallback). Escape hatch: `--old-cmd`/`--new-cmd` point at pre-built executables.
- Determinism: corpus refs are resolved once per run and then pinned (including
  latest-on-branch mode); both detector revisions analyze byte-identical checkouts; resolved
  SHAs are recorded in the run manifest; the analysis phase performs no network access
  (network only during acquisition).
- Cache: virtualenvs and checkouts live under the `platformdirs` cache directory, keyed by
  (repository, resolved SHA), guarded by `filelock`.
- Concurrency: `asyncio` orchestrates per-project subprocesses with a configurable
  parallelism limit and a per-(project, tool) timeout.

## 4. Supported detectors

- v1 adapters: `vulture`, `skylos`, `culler`, `mollify` (permissively licensed,
  uv-installable, Python-focused, actively developed).
- Adapters implement a typed `Protocol`: raw invocation output → `list[Finding]`, declaring
  capabilities (e.g. has-confidence, output format). The interface is not Python-specific
  (paths plus optional symbol), leaving room for tools such as `knip`.
- Future candidates (non-normative): `pydeadcode`, `dangle`, `deadpy`, `uncalled`, and
  subset-capability tools (ruff, mypy, pyright, CodeQL).
- Licensing rule: GPL/AGPL detectors (e.g. `deadcode` AGPL-3.0, pylint GPL-2.0) may only
  ever be invoked as separate subprocesses with parsed output — never vendored, linked, or
  listed as dependencies (including optional). v1 ships no adapter for them.

## 5. Corpus specification

- The corpus is a human-authored TOML file parsed with `tomllib` and validated into pydantic
  models (the source of truth); JSON Schema is exported from the models (§7).
- Per-project fields: `name` (unique key; the same repository may appear under distinct
  names to allow multiple pins), `repo` URL, `license` (SPDX ID), exactly one of `pin`
  (commit SHA) or `branch` (latest-on-branch), and per-tool tables with command/argument
  overrides, target paths, `expected_clean: bool`, declared `cost` in CPU-seconds
  (approximate, reference runner; measured actuals are recorded in the report), and
  include/exclude tool lists.
- Ad-hoc mode: a single target repository given on the CLI with default settings.
- Selection: by name (`-k`), `--all`, or `--max-cost SECONDS` (greedy under declared cost
  for the chosen tool).
- The initial corpus list is deferred to a Phase 1 task (~5–10 permissively licensed,
  actively maintained, moderate-size projects).

## 6. License verification

- Corpus allowlist (SPDX): MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, PSF-2.0.
  Copyleft (GPL/AGPL/LGPL/MPL) or missing license: hard fail. Unrecognized: human review.
- A CI job on PRs touching the corpus file queries the GitHub license API per repository and
  compares against the declared SPDX ID; mismatches fail the check. Detection is
  advisory-strength (licensee is imperfect) but the check is binding in CI. Implemented with
  `httpx` (the `[license]` extra) and runnable locally via `corpus license-check`.

## 7. Schemas and finding identity

- Models: `Finding`, `FindingOccurrence`, `RunManifest`, `Report`, `FindingDiff`,
  `HookEnvelope`, `Annotation` (§13). Pydantic models are the source of truth; JSON Schema
  files are exported into `liveness_primer/schemas/`; `schema export` regenerates them and a
  CI check enforces that the files match the models.
- A single package-wide `SCHEMA_VERSION` (semver) is embedded in every serialized payload.
  Minor versions are additive-only; breaking changes require a major bump.
- `Finding` fields: tool, project, path (repo-relative POSIX), symbol (nullable), kind,
  message, line span, `confidence: int | None`, raw excerpt reference.
- Finding identity: a stable hash over (tool, project name, path, symbol, kind) — excluding
  line and confidence — with an ordinal disambiguating identical tuples. Identity is what
  diffing matches on and what `bisect` accepts.

## 8. Diff engine

- Both revisions see identical files, so matching is exact (identity, line) first, then
  identity-only; results classify as `new`, `dropped`, or `confidence-changed` (the latter
  only for tools declaring the confidence capability).
- Caps on maximum results and excerpt lines are configurable; the report always states
  totals before truncation (new/dropped/changed counts, per project and overall) and notes
  any truncation.

## 9. Reporting

- Output modes: CLI text, JSON (the full `Report`), and GitHub step summary (markdown).
  PR-comment posting is out of core (requires a writable token); the JSON artifact is the
  CI-consumable product.
- Excerpts are untrusted data: length caps, control-character stripping, and fenced/escaped
  quoting so downstream LLM consumers structurally see them as data. Sanitization is
  mandatory and not hook-removable.
- Exit codes: 0 for any successful run regardless of diff size; opt-in
  `--fail-on {new,dropped,any}` gating; distinct nonzero codes for run failure vs. gate
  failure.

## 10. Hook system

- Three binding points: **pre-triage** (normalization, security veto), **triage** (ranking —
  algorithmic or LLM, fully user-supplied), **post-triage** (filtering, final
  normalization). The default pipeline is all no-ops and still yields the full report.
- Hooks are typed callables satisfying `@runtime_checkable` `Protocol`s, registered by
  dotted path in configuration; payloads are the versioned schema models.
- Failure semantics: pre-triage hooks fail closed (an exception vetoes the affected
  repository or findings and is recorded). Triage and post-triage hooks fail open by default
  (warning recorded in the report), unless they raise `TriageSafetyError`, which forces
  fail-closed.
- Shipped hooks: a subprocess bridge speaking the versioned JSON envelope over stdin/stdout
  (language-agnostic hooks without making subprocess plumbing the primary API), and the
  mandatory pre-triage excerpt sanitizer (§9).

## 11. Security posture

Defense-in-depth, not injection *detection*: excerpts are untrusted, sanitization is
mandatory, and an optional deny-pattern pre-triage hook may veto ingesting an entire
repository. All of this is documented as best-effort; no component claims to detect prompt
injection reliably.

## 12. CLI surface

`argparse`. Commands:

- `run --tool T --repo URL --old REF --new REF [-k SEL | --all | --max-cost S]
  [--max-results N] [--excerpt-lines N] [--output text|json|github] [--fail-on ...]
  [--old-cmd CMD --new-cmd CMD] [--project URL]`
- `corpus validate` — parse and validate the corpus TOML.
- `corpus license-check` — §6, locally or in CI.
- `bisect --finding ID --tool T --good REF --bad REF` — binary search over detector commits,
  building virtualenvs per step and running only the affected project.
- `schema export` — regenerate `liveness_primer/schemas/`.

## 13. Internal corpus

- An in-repo annotated corpus with sidecar annotations. `Annotation` fields: target
  (path/symbol/line), `verdict: live | dead | no-coverage | unknown`,
  `evidence: coverage | manual | llm-assisted | runner`, provenance (source project, commit,
  extraction date), and an optional runner link — a repo-relative path to a runner file
  (e.g. `corpus_runners/<name>.py`) that executably demonstrates the evidence in ambiguous
  cases.
- Rule: coverage evidence can only support `live`; absence of coverage yields `no-coverage`,
  never `dead`.

## 14. Distillation (experimental)

Phase 4. Only the schemas are contractually fixed now: §13 annotations plus provenance
tracing every distilled entry to an approved corpus project. Workflows (tool-disagreement
mining, finding-oscillation mining, interactive or LLM-assisted adversarial reproducers) are
explicitly experimental and non-normative.

## 15. Testing strategy (binding)

- Testability by construction: no module-level side effects; git operations exercised
  against `git init` throwaway repositories; no network in unit tests.
- Shipped test utilities: a fake detector able to produce any required output/diff
  characteristic between fake pinned "commits", and a fake project factory producing small
  synthetic projects with injected characteristics.
- Adapters are tested against recorded raw-output fixtures; the diff engine and reports
  against golden files; hooks as pure functions.
- All repository QA rules in AGENTS.md apply: full branch and line coverage with non-vacuous
  tests, enforced by the existing coverage.py CI gate.

## 16. Platform support

POSIX-first; Linux CI is the reference platform. Windows is best-effort: nothing in the
design intentionally blocks it, but it is not gated in CI initially.

## 17. Dependencies

- Runtime: `pydantic>=2`, `platformdirs>=4`, `filelock>=3`, `packaging>=24`.
- Extras: `[license]` → `httpx` (license verification only).
- Stdlib elsewhere: `tomllib`, `argparse`, `subprocess`/`venv`, `asyncio`. Git via
  subprocess; `uv` used opportunistically, never required. Detectors are never dependencies
  of this package.

## 18. Package layout (informative)

`cli.py`, `config.py` (corpus models), `corpus.py` (checkout and pin resolution),
`envcache.py`, `runner.py`, `tools/` (adapter protocol plus one module per adapter),
`findings.py`, `diffing.py`, `report/`, `hooks/` (protocols, `TriageSafetyError`, sanitizer,
subprocess bridge), `schemas/`, `bisect.py`, `testing/` (fake detector, fake project
factory), `internal_corpus/`.

## 19. Phases and acceptance criteria

1. **Core.** Corpus TOML and validation, the four v1 adapters, two-revision runner with
   caching, diff engine, all three report modes, `corpus validate` and `license-check` CI,
   schemas exported and sync-checked, initial corpus list chosen. Acceptance: an end-to-end
   run against a real detector PR produces the expected structured diff, with full coverage.
2. **Hooks and bisect.** The three binding points, subprocess bridge, sanitizer, and
   `bisect`.
3. **Internal corpus.** Annotation schema, initial manually annotated entries, runner-file
   evidence support.
4. **Distillation (experimental).** §14 tooling.
