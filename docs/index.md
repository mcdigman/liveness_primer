# liveness_primer

`liveness_primer` is a differential testing harness for Python dead-code
detectors and static linters. It runs two revisions of a detector against the
same pinned open-source projects and reports the **blast radius**: which
findings appeared, disappeared, changed, or could not be produced at all.

[Open the static report explorer](https://mcdigman.github.io/liveness_primer/).

```{toctree}
:hidden:
:maxdepth: 2

usage
explorer
ci
```

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
- compare releases and review changes to messages, confidence, or severity;
- publish a human-readable PR summary and a complete machine-readable report
  from CI; and
- feed the JSON report into deterministic automation or LLM-assisted triage.

Managed comparisons use byte-identical, commit-pinned target projects for both
detector revisions. The primer resolves the requested detector refs, prepares
separate fingerprint-keyed environments, runs the same configured targets, and
normalizes detector-specific output into one deterministic report model.

## Quick start

Install `liveness_primer` with Python 3.12 or newer:

```bash
pip install liveness_primer
```

Compare two Vulture refs on the pinned `pluggy` corpus project:

```bash
liveness-primer run --tool vulture \
  --repo https://github.com/jendrikseipp/vulture \
  --old v2.15 \
  --new v2.16 \
  -k pluggy \
  --output text
```

Continue with:

- {doc}`usage` for project selection, output formats, gates, and exit codes;
- {doc}`explorer` for interactive review and focused exports; and
- {doc}`ci` for a complete GitHub Actions workflow and automated triage ideas.
