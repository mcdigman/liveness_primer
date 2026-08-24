# liveness_primer

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![PyPI](https://img.shields.io/pypi/v/liveness-primer.svg)](https://pypi.org/project/liveness-primer/)
[![Coverage Status](https://coveralls.io/repos/github/mcdigman/liveness_primer/badge.svg?branch=main)](https://coveralls.io/github/mcdigman/liveness_primer?branch=main)
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
  rule attribution;
- publish a human-readable PR summary and a complete machine-readable report
  from CI; and
- feed the JSON report into deterministic automation or LLM-assisted triage.

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

With `--all` or `--max-cost`, `--ignore-include-tools` also considers projects
omitted by `include_tools`. An `exclude_tools` entry still prevents the tool
from running, and `--max-cost` selects a project only if it declares a cost for
the tool being run, including the projects this flag admits.

### Reading the result

| Result | Meaning | What to investigate |
| --- | --- | --- |
| `+` new | Present only at the head revision | Intended new coverage or a new false positive |
| `-` dropped | Present only at the base revision | Intended removal or a new false negative |
| `~` changed | A matched finding has different recorded details | Message, confidence, or severity drift |
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

[![Static report explorer showing filters, finding diffs, source context, and export controls](https://raw.githubusercontent.com/mcdigman/liveness_primer/main/design/report_explorer_demo.png)](https://mcdigman.github.io/liveness_primer/)

To build and serve the explorer locally:

```bash
cd explorer
npm ci
npm run build
npm run serve
```

Open <http://127.0.0.1:4173/liveness-primer/explorer/>. See
[`explorer/README.md`](https://github.com/mcdigman/liveness_primer/blob/main/explorer/README.md)
for development and verification commands.

## GitHub Actions

The following workflow runs on detector pull requests. It writes a compact
human report to the GitHub step summary and uploads the complete JSON report
for the explorer, automation, or later review.

```yaml
name: Liveness Primer

on:
  pull_request:

concurrency:
  group: liveness-primer-${{ github.event.pull_request.number }}
  cancel-in-progress: true

env:
  LIVENESS_PRIMER_REF: main
  PYTHON_VERSION: "3.13"

permissions:
  contents: read

jobs:
  skylos:
    name: Skylos blast radius
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - name: Check out liveness_primer
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
        with:
          repository: mcdigman/liveness_primer
          ref: ${{ env.LIVENESS_PRIMER_REF }}
          path: _liveness_primer
          persist-credentials: false

      - name: Install uv
        uses: astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78  # v7.6.0
        with:
          enable-cache: true
          python-version: ${{ env.PYTHON_VERSION }}
          cache-dependency-glob: _liveness_primer/pyproject.toml

      - name: Compare Skylos revisions across the corpus
        run: |
          set -o pipefail
          uvx --from ./_liveness_primer \
            liveness-primer run \
            --tool skylos \
            --repo "${{ github.server_url }}/${{ github.repository }}" \
            --old "${{ github.event.pull_request.base.sha }}" \
            --new "${{ github.event.pull_request.head.sha }}" \
            --all \
            --output github \
            --json-out liveness-primer-report.json \
            --jobs 2 \
            --timeout 300 \
            | tee liveness-primer-report.md >> "$GITHUB_STEP_SUMMARY"

      - name: Upload liveness_primer report
        if: ${{ always() }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1
        with:
          name: liveness-primer-report
          path: |
            liveness-primer-report.md
            liveness-primer-report.json
          if-no-files-found: error
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

Instead of or in addition to the step summary, a workflow can post a compact
digest as a pull-request comment and link reviewers to the complete report and
JSON artifact:

![Example GitHub Actions comment summarizing a liveness_primer comparison](https://raw.githubusercontent.com/mcdigman/liveness_primer/main/design/liveness_primer_ci_application.png)

### LLM-assisted triage

The complete JSON report is also suitable as input to an LLM-assisted review
step. A downstream job can group changes by project or rule, highlight large or
surprising clusters, call out detector failures, suggest which changes need
human attention, and post an advisory digest as a pull-request comment.

Keep the versioned JSON artifact as the source of truth and link every digest
back to it. Finding messages and source excerpts originate in detector output
and analyzed repositories, so treat them as untrusted content: run the model
step without release credentials or unnecessary write permissions, and do not
let generated prose replace deterministic gates or human review.

<details>
<summary>Example simulated LLM-assisted triage digest</summary>
<br>
<img
  src="https://raw.githubusercontent.com/mcdigman/liveness_primer/main/design/llm_review_example.png"
  alt="Simulated LLM pull-request review clustering new findings, identifying likely false positives, and recommending follow-up validation"
  width="900"
>
</details>

## Run inside Docker containers

`--container` moves the build and execution of both detector revisions into
ephemeral Docker containers:

```bash
liveness-primer run --tool vulture \
  --repo https://github.com/jendrikseipp/vulture \
  --old v2.15 \
  --new v2.16 \
  -k pluggy \
  --container
```

Each revision is installed into a fingerprint-cached environment image built
offline (`docker build --network none`) with digest-pinned Chainguard Python
images: `latest-dev` fetches dependencies and builds a virtual environment,
then that environment, its captured package freeze, and a digest-verified
static ripgrep binary enter the minimal `latest` runtime. Ripgrep preserves
Skylos's safe grep-verification pass; its architecture-specific official
release archive and extracted executable are both SHA-256 checked during the
network-enabled fetch phase. `pip` is removed before the copy, and the runtime
contains no shell or package manager from the builder. The two revisions are
fetched into separate wheelhouses — base first, then head reusing the base
wheelhouse read-only so the shared dependencies download only once — and the
base image is built from the base wheelhouse alone, so an untrusted head-side
build hook cannot slip a forged wheel into the base build. Every detector
invocation then executes in its own named, hardened container — networking
disabled, running as the invoking user with all capabilities dropped, a PID
limit, and a read-only root filesystem, with only its side's workspaces
mounted. Its container is force-removed before the writable workspace is
deleted, including on timeout; the run also reaps any leftover before the
report or `--json-out` artifact is written. A removal Docker cannot confirm
fails the run rather than allowing output. Because the container runtime
enforces the sandbox on every platform, container runs record enforced
isolation even on hosts where the default host-venv path is best-effort (for
example macOS).

The mode requires a running Docker daemon, probed at run start; the `docker`
CLI is a host requirement of this mode only, never a Python dependency.
`--container-builder-image IMAGE` and `--container-image IMAGE` override the
builder and runtime respectively; custom images must provide matching Python
and platform ABIs. The runtime platform must be `x86_64` or `aarch64`, for
which pinned static ripgrep release artifacts are available. `--fresh` forces
image rebuilds, and `--old-cmd`/`--new-cmd` cannot combine with `--container`.
Operator-supplied native helper executables (such as `SKYLOS_GO_BIN`) are not
supported in this mode: a host binary cannot run inside the container.

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
