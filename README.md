# liveness_primer

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Coverage: 100%](https://img.shields.io/github/actions/workflow/status/mcdigman/liveness_primer/coverage.yml?branch=main&event=push&label=coverage%3A%20100%25)](https://github.com/mcdigman/liveness_primer/actions/workflows/coverage.yml)
[![Test](https://github.com/mcdigman/liveness_primer/actions/workflows/test.yml/badge.svg?branch=main&event=push)](https://github.com/mcdigman/liveness_primer/actions/workflows/test.yml)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)

`liveness_primer` is a differential testing harness for Python dead-code
detectors and static linters. It runs two revisions of a detector against the
same pinned open-source projects and reports the **blast radius**: which
findings appeared, disappeared, changed, or could not be produced at all.

[Open the static report explorer](https://mcdigman.github.io/liveness_primer/).

## Why use it?

A detector's own test suite can prove that selected examples behave correctly.
It is much harder to see how a change affects real projects outside that suite.
`liveness_primer` makes that impact reviewable before a release or merge.

Use it to:

- validate that an internal refactor preserves the detector's findings;
- assess whether a new analysis finds the intended cases without producing a
  wave of unrelated false positives;
- verify that a bug fix removes or adds the expected findings without creating
  new false negatives elsewhere;
- catch parser, packaging, dependency, timeout, and execution failures that
  only appear on some projects;
- compare releases and review changes to locations, messages, confidence, or
  rule attribution; and
- publish a human-readable PR summary and a complete machine-readable report
  from CI.

The comparison uses byte-identical, commit-pinned target projects for both
detector revisions. Managed runs resolve the requested detector refs, prepare
separate fingerprint-keyed environments, run the same configured targets, and
normalize detector-specific output into one deterministic report model.

## Installation

`liveness_primer` requires Python 3.12 or newer.

```bash
pip install liveness_primer
```

The built-in adapters support [Vulture](https://github.com/jendrikseipp/vulture)
and [Skylos](https://github.com/duriantaco/skylos).

License verification (`corpus license-check`) requires the `[license]` extra.

## Quick start

Compare two Vulture refs on the pinned `pluggy` corpus project:

```bash
liveness-primer run --tool vulture \
  --repo https://github.com/jendrikseipp/vulture \
  --old v2.15 \
  --new v2.16 \
  -k pluggy \
  --output text
```

Project selection is explicit:

- `-k NAME` selects matching projects from the packaged, commit-pinned corpus;
- `--all` selects every corpus project supported by the adapter;
- `--max-cost SECONDS` selects a useful subset within an estimated runtime
  budget; and
- `--project URL` compares against one ad-hoc target repository instead of the
  packaged corpus.

### Reading the result

| Result | Meaning | What to investigate |
| --- | --- | --- |
| `+` new | Present only at the head revision | Intended new coverage or a new false positive |
| `-` dropped | Present only at the base revision | Intended removal or a new false negative |
| `~` changed | A matched finding has different recorded details | Location, message, confidence, or rule-attribution drift |
| error | A detector invocation did not produce a valid result | Crash, timeout, or unparseable output |

Reports also record the exact detector revisions, corpus pins, environment and
dependency differences, requested refs or commands, timing, and isolation
status needed to interpret or reproduce the comparison.

## Explore a report in the browser

Write the complete JSON report alongside the terminal output:

```bash
liveness-primer run --tool vulture \
  --repo https://github.com/jendrikseipp/vulture \
  --old v2.15 \
  --new v2.16 \
  --all \
  --output text \
  --json-out liveness-primer-report.json
```

Then open the [static report explorer](https://mcdigman.github.io/liveness_primer/)
and choose `liveness-primer-report.json`. The report is processed locally in
the browser rather than uploaded to an application server. The explorer can:

- search, filter, group, and sort findings;
- compare base and head analyzer output with pinned source evidence;
- select or hide findings while reviewing a large change;
- preserve review state in a versioned JSON record; and
- export a focused Markdown or JSON handoff.

To build and serve the explorer locally:

```bash
cd explorer
npm ci
npm run build
npm run serve
```

Open <http://127.0.0.1:4173/liveness-primer/explorer/>. See
[`explorer/README.md`](explorer/README.md) for development and verification
commands.

## GitHub Actions

The following workflow runs on detector pull requests. It writes a compact
human report to the GitHub step summary and uploads the complete JSON report
for the explorer, automation, or later review.

```yaml
name: Liveness primer

on:
  pull_request:

permissions:
  contents: read

jobs:
  blast-radius:
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - name: Set up Python
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0
        with:
          python-version: "3.13"

      - name: Install liveness_primer
        run: python -m pip install "liveness_primer==0.0.1"

      - name: Compare detector revisions
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          DETECTOR_REPO: ${{ github.server_url }}/${{ github.repository }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          liveness-primer run \
            --tool vulture \
            --repo "$DETECTOR_REPO" \
            --old "$BASE_SHA" \
            --new "$HEAD_SHA" \
            --all \
            --output github \
            --json-out liveness-primer-report.json \
            --fail-on corpus-integrity \
            >> "$GITHUB_STEP_SUMMARY"

      - name: Upload complete report
        if: ${{ always() }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: liveness-primer-report
          path: liveness-primer-report.json
          if-no-files-found: warn
```

Detector crashes, timeouts, and unparseable output fail the run without an
extra gate. `--fail-on` adds project-specific regression policy and is
repeatable:

- `--fail-on new`, `dropped`, or `changed` rejects that diff class;
- `--fail-on any` requires the normalized finding set to remain unchanged; and
- `--fail-on corpus-integrity` rejects corpus-integrity warnings.

For a new feature, leaving finding-diff gates off makes CI an evidence-producing
review job. For a semantics-preserving refactor, `--fail-on any` turns the same
workflow into a strict regression gate.

## Pre-built detector commands

The escape hatch compares commands you have already built:

```bash
liveness-primer run --tool vulture \
  --project https://github.com/pytest-dev/pluggy \
  --old-cmd 'vulture-old' \
  --new-cmd 'vulture-new'
```

Because the primer did not construct and verify these detector environments,
the report marks the run as non-comparable and records that isolation was not
enforced. `--fail-on` refuses to gate an escape-hatch run; use this mode for
trusted local investigation, not as a managed CI substitute.

## Output and exit codes

`--output text` produces terminal-oriented output, `--output github` produces
GitHub-flavored Markdown, and `--output json` writes the report to standard
output. `--json-out PATH` archives the complete JSON report alongside any of
those display modes.

Exit codes are:

- `0`: comparison completed and no enabled gate fired;
- `1`: run or configuration failure, including detector invocation failures;
- `2`: command-line usage error; and
- `3`: an enabled `--fail-on` gate fired.

## Corpus and schema maintenance

```bash
liveness-primer corpus validate
liveness-primer corpus license-check
liveness-primer schema export
```
