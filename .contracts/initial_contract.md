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
naming a finding across runs (§7). *Finding locator*: a reference to one occurrence in a
specific report — report reference, identity, line (§7). *Diff class*: `new`, `dropped`, or
`changed` (§8). *Run manifest*: the record of resolved refs, versions, environments, and
settings for one run. *Blast radius*: all finding diffs plus summary totals. *Hook binding
point*: pre-triage, triage, or post-triage (§10).

## 3. Operating model

- The detector is obtained by cloning its repository and installing the base and head refs
  into two isolated cached virtualenvs (`uv pip` when on `PATH`, stdlib `venv` + `pip`
  fallback). Escape hatch: `--old-cmd`/`--new-cmd` point at pre-built executables.
- Three-step runs: a **fetch** step (network permitted; git clones plus dependency prefetch
  into a local wheel cache, wheels preferred; no code from the detector refs executes;
  every fetch is recorded in the run manifest — URLs, resolved SHAs, installed versions),
  then a **build** step (networking disabled; the detector installs from the local cache,
  e.g. `--no-index --find-links`, so build-backend hooks run sandboxed; Rust detectors
  prefetch crates during fetch and build `--offline`), then an **analysis** step
  (networking disabled, §11). Corpus refs are resolved once per run and then pinned
  (including latest-on-branch mode); both detector revisions analyze byte-identical
  checkouts.
- Trust model: detector refs and corpus content are untrusted and execute only with
  networking disabled and no credentials; third-party dependencies fetched from package
  indexes are supply-chain-trusted like any development dependency. As in all CI, running a
  primer on a PR executes that PR's code — the guarantee is isolation, not avoidance.
- Environment integrity: virtualenv cache entries under the `platformdirs` cache directory
  are keyed by the full fingerprint (repository, resolved SHA, adapter build-recipe hash,
  Python version and ABI, platform tag, installer name and version) and guarded by
  `filelock`; checkout caches are keyed by (repository, SHA). The manifest records the
  resolved dependency freeze of both environments. A base/head pair is **comparable** iff
  the non-detector dependency delta is empty; any non-empty delta triggers an automatic
  paired same-run rebuild, and only a delta that survives same-run paired resolution is
  ref-attributable (reported as context). Attribution is temporal, never textual:
  declared-requirement differences between the refs do not excuse a cached pair. The
  manifest records a `comparable` flag; `--fail-on` gating and `bisect` refuse to act on
  non-comparable runs. `--fresh` forces same-run rebuilds of both environments.
- Concurrency: `asyncio` orchestrates per-project subprocesses with a configurable
  parallelism limit and a per-(project, tool) timeout.

## 4. Supported detectors

- v1 adapters: `vulture` and `skylos` (pure Python, generic source-install path) in
  Phase 1; `culler` and `mollify` (Rust/maturin builds requiring a declared toolchain) in
  Phase 2. All four are permissively licensed, uv-installable, and actively developed.
- Adapters implement a typed `Protocol`: raw invocation output → `list[Finding]`, declaring
  capabilities (e.g. has-confidence, output format) and a **build recipe** — build backend
  plus toolchain prerequisites with minimum versions (e.g. Rust and maturin for `culler`
  and `mollify`) — which the runner verifies before building and CI provisions for gated
  detectors. The interface is not Python-specific (paths plus optional symbol), leaving
  room for tools such as `knip`.
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
- Finding identity: a stable hash over (tool, project name, path, symbol, kind), excluding
  line and confidence. Identity carries no positional ordinal; a report holds a *multiset*
  of occurrences (line span, message, confidence) per identity. Persistent references — the
  `bisect` input in particular — use a *finding locator* (report reference, identity, line),
  never a position-dependent key.

## 8. Diff engine

- Both revisions see identical files. Matching is deterministic and order-independent. The
  **canonical occurrence key** is the complete normalized occurrence tuple in fixed field
  order (start line, end line, message, confidence, plus any observable field added later);
  it governs all sorting below and the report ordering that `--occurrence` indexes (§12).
  Stages: (1) full-field-equal occurrences are removed by multiset intersection;
  (2) remaining occurrences sharing (identity, start line) are paired in canonical-key
  order as `changed`; (3) remaining occurrences sharing identity are paired across lines
  in canonical-key order as `changed`; (4) leftovers classify as `new` or `dropped`. After
  stage 1, canonical-key ties occur only between fully identical, interchangeable
  occurrences. `changed` carries a `changed_fields ⊆ {line-span, message, confidence}` set
  (confidence only for tools declaring that capability). Every normalized observable field
  participates in the comparison; no identity-stable behavior change may go silently
  unclassified.
- Caps on maximum results and excerpt lines are configurable; the report always states
  totals before truncation (new/dropped/changed counts, with confidence changes broken out,
  per project and overall) and notes any truncation. Rendered reports cap message-only
  changes to a count plus bounded examples; the JSON report retains full detail.

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

- Trust boundary: user-authored configuration, hooks, and `--old-cmd`/`--new-cmd` are
  trusted user code; corpus content — files, paths, and detector output derived from them —
  is always untrusted.
- Injection: defense-in-depth, not *detection* — excerpts are untrusted, sanitization is
  mandatory, and an optional deny-pattern pre-triage hook may veto ingesting an entire
  repository. All best-effort; no component claims to detect prompt injection reliably.
- Subprocess hygiene: all subprocess launches go through a single audited launcher module
  that accepts only typed argv lists and exposes no shell parameter; every argv element
  originates from typed, validated models; per-tool corpus commands are argv lists, never
  shell strings; corpus content is never interpolated into any command; no `eval`/`exec`
  of dynamic content anywhere. Enforcement (verified against the pinned ruff): the raw
  APIs (`subprocess.*`, `os.system`/`os.popen`, `asyncio.create_subprocess_shell`/`_exec`)
  are banned repo-wide via `TID251` banned-api in `ruff.toml` with a per-file exemption
  for the launcher, and an AST-walking unit test asserts that no call in the package
  passes a `shell` keyword. (The bandit S rules alone are insufficient: S603 flags every
  `subprocess` call, safe or not, and no S rule flags `asyncio.create_subprocess_shell`.)
  This guards against accident; in-repo code is trusted (§11 trust boundary).
- Network isolation: analysis-phase subprocesses run with networking disabled (Linux network
  namespaces or a container with `--network=none`), enforced on the Linux reference platform
  and in CI, best-effort elsewhere. The manifest records whether isolation was enforced, and
  reports flag unenforced runs. This also limits the blast radius of a malicious corpus
  repository exploiting a detector parser bug.
- Corpus code execution: the core (Phases 1–2) never executes corpus code — detectors only
  parse it. Any workflow that executes corpus code (coverage evidence, runner files,
  distillation; Phases 3–4) runs only inside an isolated container: no network, read-only
  source mount, non-root, CPU/memory/time limits. The sole output channel is declared
  artifact paths (e.g. coverage data), re-ingested as untrusted, schema-validated input.
  Without a container runtime these features hard-fail; there is no host-execution
  fallback.

## 12. CLI surface

`argparse`. Every command accepts `-h`/`--help`; the root parser accepts `--version`,
printing the package version and `SCHEMA_VERSION`. Commands:

- `run --tool T --repo URL --old REF --new REF [-k SEL | --all | --max-cost S]
  [--max-results N] [--excerpt-lines N] [--output text|json|github] [--fail-on ...]
  [--fresh] [--old-cmd CMD --new-cmd CMD] [--project URL]`
- `corpus validate` — parse and validate the corpus TOML.
- `corpus license-check` — §6, locally or in CI.
- `bisect --report REPORT.json --finding ID [--line N] [--occurrence N] --good REF
  --bad REF [--repo URL] [--predicate P]` — binary search over detector commits. The prior
  report supplies the manifest (detector repository, corpus pins), so every step reproduces
  the identical checkout; the affected project is the only project run. The locator
  resolves to a full occurrence on the diff class's **reference side** — head for `new`,
  base for `dropped` and `changed` — and `--occurrence` indexes that side's canonical
  ordering (§8) when several occurrences share (identity, line). Default predicate by diff
  class: `new` → first commit where the head occurrence is present; `dropped` → first
  where the base occurrence is absent; `changed` → first where the occurrence deviates
  from its base-side values in any of the finding's `changed_fields`. `--predicate`
  overrides.
- `schema export` — regenerate `liveness_primer/schemas/`.

## 13. Internal corpus

- An in-repo annotated corpus with sidecar annotations. `Annotation` fields: target
  (path/symbol/line), `verdict: live | dead | no-coverage | unknown`,
  `evidence: coverage | manual | llm-assisted | runner`, provenance (source project, commit,
  extraction date), and an optional runner link — a repo-relative path to a runner file
  (e.g. `corpus_runners/<name>.py`) that executably demonstrates the evidence in ambiguous
  cases. Runner files execute only under the §11 container-isolation rules.
- Rule: coverage evidence can only support `live`; absence of coverage yields `no-coverage`,
  never `dead`.

## 14. Distillation (experimental)

Phase 4. Only the schemas are contractually fixed now: §13 annotations plus provenance
tracing every distilled entry to an approved corpus project. Workflows (tool-disagreement
mining, finding-oscillation mining, interactive or LLM-assisted adversarial reproducers) are
explicitly experimental and non-normative. All corpus-code execution in distillation is
subject to the §11 container-isolation rule.

## 15. Testing strategy (binding)

- Testability by construction: no module-level side effects; git operations exercised
  against `git init` throwaway repositories; no network in unit tests; sandbox and
  container launchers are injectable so isolation logic is testable without real
  containers.
- Shipped test utilities: a fake detector able to produce any required output/diff
  characteristic between fake pinned "commits", and a fake project factory producing small
  synthetic projects with injected characteristics.
- Adapters are tested against recorded raw-output fixtures; the diff engine and reports
  against golden files; hooks as pure functions.
- An AST-walking test enforces the §11 launcher rule: no call anywhere in the package
  passes a `shell` keyword, and no module outside the launcher reaches the raw subprocess
  APIs (backstopping the `TID251` ban in `ruff.toml`).
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
`envcache.py`, `runner.py`, `launcher.py` (the audited subprocess launcher, §11), `tools/`
(adapter protocol plus one module per adapter), `findings.py`, `diffing.py`, `report/`,
`hooks/` (protocols, `TriageSafetyError`, sanitizer, subprocess bridge), `schemas/`,
`bisect.py`, `testing/` (fake detector, fake project factory), `internal_corpus/`.

## 19. Phases and acceptance criteria

1. **Core.** Corpus TOML and validation, the `vulture` and `skylos` adapters, two-revision
   runner with fingerprint-keyed caching and enforced network isolation, diff engine, all
   three report modes, `corpus validate` and `license-check` CI, schemas exported and
   sync-checked, initial corpus list chosen. Acceptance: an end-to-end run against a real
   detector PR produces the expected structured diff, with full coverage.
2. **Hooks, bisect, native-build detectors.** The three binding points, subprocess bridge,
   sanitizer, `bisect`, and the `culler` and `mollify` adapters via the build-recipe
   mechanism with CI toolchain provisioning.
3. **Internal corpus.** Annotation schema, initial manually annotated entries, runner-file
   evidence support.
4. **Distillation (experimental).** §14 tooling.
