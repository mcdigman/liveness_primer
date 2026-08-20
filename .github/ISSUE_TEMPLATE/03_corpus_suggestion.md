---
name: Corpus suggestion
about: Propose a project for the pinned corpus, or a change to an existing entry.
title: '[corpus] '
labels: corpus
---

<!--
Corpus entries are the targets every comparison runs against, so each one must
be GitHub-hosted, permissively licensed, moderate in size, and pinned to a full
commit SHA — both detector revisions have to analyze byte-identical checkouts.

The gate on liveness_primer/data/corpus.yaml runs `corpus validate` and a
GitHub license check on every PR, so an entry that fails these fields will fail
CI too.
-->

## What is this?

<!-- Delete all but one. -->

- Add a new project
- Re-pin an existing project
- Additional pin for an existing project
- Change targets or cost for an existing project
- Remove a project

## Entry

- **Project name:** <!-- the corpus key: short, lowercase, unique, e.g. pluggy -->
- **Repository URL:** <!-- must be GitHub-hosted, e.g. https://github.com/pytest-dev/pluggy -->
- **License (SPDX):** <!-- MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, or PSF-2.0. Anything outside the allowlist needs human review — explain below. -->
- **Proposed pin:** <!-- a full 40-character commit SHA, not a tag or branch, e.g. f06ceaafbe5bdbdafad8a0c01a2daabb89386a42 -->

## What does it cover that the current corpus does not?

## Size and maintenance

<!--
Rough source size, recent commit or release activity, and how long a detector
takes on it. Very large projects may be too expensive for per-PR tool runs.
Example: about 3k lines under src/, released last month, ~5s under skylos.
-->

## Anything else

<!--
For a re-pin, why now. For an additional pin, why it adds additional value.
For a removal, what changed. For an unusual license, the reasoning.
-->
