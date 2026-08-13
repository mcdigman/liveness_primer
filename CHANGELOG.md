# Changelog

All notable changes to `liveness_primer` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Report and manifest payloads carry their own `schema_version`, versioned
independently of the package version; `liveness-primer --version` prints both.

## [Unreleased]

This is the first release version of `liveness_primer`, so everything is new.

### Added

- **CLI** — `run`, `corpus validate`, `corpus license-check`, and
  `schema export`, with `--version` reporting the package and schema versions.
  Exit codes: 0 success, 1 run/configuration failure, 2 usage error, 3 `--fail-on`
  gate failure.
- **Detector adapters** — `vulture` and `skylos`, behind a registry and a
  common adapter base. `skylos` supports opt-in analyses selected per corpus entry
  or overridden per run with `--analyses`, and runs against a neutral pinned config
  so a target repository's own `.skylos/config.yaml` cannot alter the comparison.
- **Two-revision runner** — builds the detector at a base and a head ref,
  runs both over each selected project, and records measured cost. Detector
  environments are cached by fingerprint and rebuilt on `--fresh`.
- **Isolation** — detector subprocesses run with network access denied and
  path traversal out of the checkout blocked; symlink loops and unreadable files
  degrade to warnings rather than aborting collection.
- **Diff engine** - classifies findings as new, dropped, or changed against a
  finding identity that folds in rule ID and line span, with a `severity` field and
  a canonical ordering for occurrences sharing an identity.
- **Reporting** — `text`, `json`, and `github` modes sharing one sanitizer,
  plus pinned-source evidence excerpts, permalinks, terminal colour and hyperlink
  control, and golden-file coverage of every renderer.
- **Static report explorer** — a self-contained offline React + Tabulator
  workbench over an exported report: faceted filtering, sorting, finding context,
  review records, permalinks, and Markdown/JSON export. Validated in-browser
  against Ajv standalone validators generated from the shipped schemas.
- **Corpus** — a `corpus.yaml` validated into pydantic models,
  with per-tool overrides, `expected_clean` corpus-integrity warnings, and
  selection by `-k`, `--all`, or `--max-cost`. Seeded with permissively licensed,
  pinned projects. The corpus ships inside the package
  (`liveness_primer/data/corpus.yaml`) and is the `--corpus` default, so an
  installed `liveness-primer` works from any directory.
- **License verification** — `corpus license-check` confirms each entry's
  declared SPDX ID against the GitHub API, and runs credential-free on pull
  requests.
- **Schemas** — JSON Schema exported from the pydantic models for findings,
  occurrences, diffs, reports, run manifests, hook envelopes, annotations, and the
  explorer export/review payloads, with CI enforcing that the committed copies
  match a fresh export.
- **Shipped testing utilities** — `liveness_primer.testing` provides a fake
  detector and fake project builder so downstream adapters can be tested without a
  real detector.
- **CI** — lint (`ruff --preview`, rules `ALL`), `mypy`, `pyright`, `pydoclint`,
  `skylos` dead-code detection, 100% line and branch coverage against `main`,
  CodeQL, dependency floor and Python 3.12–3.14 matrix runs, schema sync, corpus
  validation, and the explorer's format/lint/typecheck/coverage/build/license and
  Playwright suites.
