---
name: Bug report
about: liveness_primer crashed, produced a wrong report, or behaved differently than documented.
title: '[bug] '
labels: bug
---

<!--
Thanks for the report. A bug in liveness_primer is typically reproducible from
a single command plus the two detector refs, so the details below are what a
maintainer needs to see it happen. Delete anything that does not apply.

Security issues should go through SECURITY.md, not a public issue:
https://github.com/mcdigman/liveness_primer/blob/main/SECURITY.md
-->

## Environment

- **liveness_primer version:** <!-- `liveness-primer --version`, which includes the schema version, e.g. liveness-primer 0.1.0 (schema 2.2.0) -->
- **Python version:** <!-- `python --version` -->
- **Operating system:** <!-- macOS 14.5 (arm64) / Ubuntu 24.04 (x86_64) / ubuntu-latest GitHub runner -->
- **Detector and revisions:** <!-- the `--tool` name, repo, and the versions or full pinned hashes of the two commits that reproduce it, e.g. skylos https://github.com/duriantaco/skylos a27bd86223a948fe292677e71bd84e19c1ab24fa e25b12eba4a2f80ad031b388ec81049d46be8f90 -->
- **Corpus projects involved:** <!-- the `-k` selections, `--all`, or the `--project` URL. If only some projects fail, say which: -k pluggy (also fails on attrs; passes on click) -->

## Description

<!-- What is wrong. -->

## Reproduction

<!-- If possible, a minimal example and the exact command needed to run it. -->

```console
$
```

## Expected behavior

<!-- What you expected, and where that expectation comes from (docs, `--help`, a prior version). -->

## Actual behavior

<!--
What happened instead. Paste the terminal output or traceback — the whole
thing, not just the last line. Redact paths or tokens if you need to.
-->

```console
```

## Report excerpt

<!--
If the bug is about report content rather than a crash, attach the JSON report
(`--json-out report.json`) or paste the relevant entry. Drag-and-drop works for
files.
-->

## Anything else

<!-- Additional context, screenshots, link to a failing CI run, etc. -->
