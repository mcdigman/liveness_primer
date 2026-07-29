# liveness_primer

A `mypy_primer`-style tool for Python dead-code detectors. It runs a detector
at two revisions — the base and head of a PR to the *detector* — against a
fixed corpus of open-source projects and reports the **blast radius**: the
structured diff of the detector's findings, for human or LLM review.

The full design is specified in
[.contracts/initial_contract.md](.contracts/initial_contract.md). Phase 1
ships the corpus specification, the `vulture` and `skylos` adapters, the
two-revision runner with fingerprint-keyed environment caching and network
isolation, the deterministic diff engine, and text/JSON/GitHub reports.

## Usage

Compare two refs of a detector across the corpus:

```bash
liveness-primer run --tool vulture \
  --repo https://github.com/jendrikseipp/vulture --old v2.15 --new v2.16 \
  -k pluggy --output text
```

Point the escape hatch at pre-built detector commands (unmanaged, so the
run is marked non-comparable and `--fail-on` gating refuses to act):

```bash
liveness-primer run --tool vulture --project https://github.com/pytest-dev/pluggy \
  --old-cmd 'vulture-old' --new-cmd 'vulture-new'
```

Corpus and schema maintenance:

```bash
liveness-primer corpus validate
liveness-primer corpus license-check
liveness-primer schema export
```

Exit codes: `0` for any successful run regardless of diff size, `1` for run
or configuration failures, `2` for usage errors, `3` when an opt-in
`--fail-on` gate fires.

## Installation

```bash
pip install liveness_primer
```

License verification (`corpus license-check`) needs the `[license]` extra.
