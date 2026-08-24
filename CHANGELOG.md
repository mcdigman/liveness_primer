# Changelog

All notable changes to `liveness_primer` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Report and manifest payloads carry their own `schema_version`, versioned
independently of the package version; `liveness-primer --version` prints both.

## [Unreleased]

### Added

- **Container mode** — `run --container` builds both detector revisions into
  fingerprint-cached Docker images (offline `docker build --network none` fed
  from a fetch-step prefetch inside the base image) and executes each side of
  the comparison in its own ephemeral, network-less, hardened container
  (invoking-user PID 1, all capabilities dropped, `no-new-privileges`, PID
  limit, read-only root filesystem, per-side workspace mounts). The two
  revisions are fetched into separate per-side wheelhouses — base first, then
  head reusing the base wheelhouse read-only via `--find-links` so the shared
  closure downloads once — and the base image builds from the base wheelhouse
  alone, so an untrusted head-side build hook cannot forge a wheel under a
  base dependency's name. Prefetched distributions are staged and validated as
  regular files (base-owned names excluded) before entering a side's
  wheelhouse, and helper containers are named and tracked so a client-side
  timeout cannot leak one. Both analysis containers are
  force-removed when the analysis finishes, before the report or any
  `--json-out` artifact is written; an unconfirmed removal fails the run.
  `--container-image IMAGE` overrides the `python:3.12-slim` default base
  image. The `docker` CLI is a host requirement of this mode only, driven
  through the audited launcher; it is never a Python dependency (contract
  §3, §11, §17).

## [0.1.1] - 2026-08-21

### Added

- **Corpus selection** — `--ignore-include-tools` lets `--all` and `--max-cost`
  consider projects their `include_tools` omits, so a one-off comparison needs no
  corpus edit. `--max-cost` still selects a project only if it declares a cost for
  the tool being run.
- **Vulture corpus** — Add xarray, meltano-sdk, fluids, todo, copyparty,
  elementary, beartype, strawberry, scrapy, and bokeh.

### Changed

- **Corpus selection** — `-k` now selects a matching project even when the
  project's `include_tools` omits the tool being run. `exclude_tools` remains a
  hard exclusion under every selector.
### Fixed

- The Skylos adapter now ingests `unused_files` (`SKY-E002` and `SKY-E003`)
  findings instead of silently omitting file-level dead-code changes from
  comparisons. The bucket is multi-rule and every supported Skylos revision
  stamps each entry's rule ID explicitly, so the adapter requires the
  explicit `rule_id` rather than defaulting one rule's code onto the
  other's entries.
- A finding in the normalized unused-file shape — kind `file`, no symbol,
  a point span at line 1 — on a file with zero source lines (e.g.
  `SKY-E002`) is intentionally source-less: it no longer spends the
  bounded source-warning budget on the expected emptiness, keeping the
  budget for genuine source anomalies. Any other occurrence claiming
  source in an empty file still warns.

## [0.1.0] - 2026-08-14

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
  An adapter may also declare native helper executables the operator supplies by
  environment variable — `skylos` declares `SKYLOS_GO_BIN` for its prebuilt Go
  engine, without which a project containing Go sources (skylos itself included)
  is analyzed incompletely. The runner validates and hashes the path, hands the
  same binary to both sides, and records it in the manifest as `native_tools`.
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
