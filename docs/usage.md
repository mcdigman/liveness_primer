# Run comparisons

The built-in adapters support [Vulture](https://github.com/jendrikseipp/vulture)
and [Skylos](https://github.com/duriantaco/skylos). A managed run installs the
two requested detector revisions into separate environments and evaluates both
against the same target-project commits.

## Installation

`liveness_primer` requires Python 3.12 or newer.

```bash
pip install liveness_primer
```

License verification with `corpus license-check` requires the `[license]`
extra:

```bash
pip install "liveness_primer[license]"
```

## Compare detector revisions

Provide the detector adapter, repository, and two refs to compare:

```bash
liveness-primer run --tool vulture \
  --repo https://github.com/jendrikseipp/vulture \
  --old v2.15 \
  --new v2.16 \
  -k pluggy \
  --output text
```

The refs may be tags, branches, or commits accepted by Git. For reproducible
review, prefer immutable commits or release tags.

## Select target projects

Every run requires exactly one target-selection mode:

- one or more `-k NAME` options select matching projects from the packaged,
  commit-pinned corpus;
- `--all` selects every corpus project supported by the adapter;
- `--max-cost SECONDS` selects a useful subset within an estimated runtime
  budget; and
- `--project URL` uses one ad-hoc target repository instead of the packaged
  corpus.

Repeated `-k` options are combined into one selection. Do not combine that
mode with `--all` or `--max-cost`, and do not combine `--project` with any
corpus selector. With `--all` or `--max-cost`, add `--ignore-include-tools`
to also consider projects omitted by `include_tools`; `exclude_tools` still
prevents a tool from running. Budgeted selection continues to skip any project
that declares no cost for the tool being run, including the projects
`--ignore-include-tools` admits.

## Interpret the result

| Result | Meaning | What to investigate |
| --- | --- | --- |
| `+` new | Present only at the head revision | Intended new coverage or a new false positive |
| `-` dropped | Present only at the base revision | Intended removal or a new false negative |
| `~` changed | A matched finding has different recorded details | Message, confidence, or severity drift |
| error | A detector invocation failed | Failure details; usable partial findings may still be displayed |

An error does not always mean that findings are absent. If a failed invocation
emits parseable structured output, the report retains those findings and can
still generate diffs while also recording the invocation error. Review both;
the run still exits with a failure status.

Path, symbol, kind, rule ID, and line span are part of finding identity. If one
of those fields changes, the report contains one dropped and one new finding
rather than a changed finding.

Reports also record the exact detector revisions, corpus pins, environment and
dependency differences, requested refs or commands, timing, and isolation
status needed to interpret or reproduce the comparison.

## Save and render reports

`--output` controls the display written to standard output:

- `--output text` produces terminal-oriented output;
- `--output github` produces GitHub-flavored Markdown; and
- `--output json` produces the complete report as JSON.

Use `--json-out PATH` to archive the complete JSON report alongside text or
GitHub output:

```bash
liveness-primer run --tool vulture \
  --repo https://github.com/jendrikseipp/vulture \
  --old v2.15 \
  --new v2.16 \
  --all \
  --output text \
  --json-out liveness-primer-report.json
```

Open that JSON file in the {doc}`explorer`, attach it to CI, or pass it to
downstream automation.

## Add regression gates

Detector crashes, timeouts, and unparseable output fail the run without an
extra gate. Repeat `--fail-on` to add project-specific regression policy:

- `--fail-on new`, `dropped`, or `changed` rejects that diff class;
- `--fail-on any` requires the normalized finding set to remain unchanged; and
- `--fail-on corpus-integrity` rejects corpus-integrity warnings.

For a new feature, leaving finding-diff gates off makes the run an
evidence-producing review job. For a semantics-preserving refactor,
`--fail-on any` turns it into a strict regression gate.

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

Each revision installs into a fingerprint-cached environment image built
offline (`docker build --network none`) from dependencies prefetched during
the fetch step. The two revisions are fetched into separate wheelhouses —
base first, then head reusing the base wheelhouse read-only so the shared
dependencies download only once — and the base image builds from the base
wheelhouse alone, so an untrusted head-side build hook cannot forge a wheel
into the base build. Every detector invocation then executes in its own named,
hardened container — networking disabled, running as the invoking user with
all capabilities dropped, a PID limit, and a read-only root filesystem, with
only its side's workspaces mounted. Its container is force-removed before the
writable workspace is deleted, including on timeout; the run reaps any
leftover before report output. A removal Docker cannot confirm fails the run,
and container isolation is recorded as enforced on every host platform.

The mode requires a running Docker daemon, probed at run start.
`--container-image IMAGE` overrides the default `python:3.14-slim` base
image and requires `--container`; `--fresh` forces image rebuilds. The mode
cannot combine with `--old-cmd`/`--new-cmd`, and operator-supplied native
helper executables (such as `SKYLOS_GO_BIN`) are refused: a host binary
cannot run inside the container.

## Use pre-built detector commands

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

## Exit codes

- `0`: comparison completed and no enabled gate fired;
- `1`: run or configuration failure, including detector invocation failures;
- `2`: command-line usage error; and
- `3`: an enabled `--fail-on` gate fired.

## Maintain the corpus and schemas

```bash
liveness-primer corpus validate
liveness-primer corpus license-check
liveness-primer schema export
```
