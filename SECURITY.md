# Security Policy

## Supported versions

`liveness_primer` is pre-1.0 and under active development. Only the latest
release on PyPI and the current `main` branch receive security fixes; there are
no backports to earlier versions.

## Reporting a vulnerability

Report privately through GitHub's **[private vulnerability
reporting](https://github.com/mcdigman/liveness_primer/security/advisories/new)**
(the "Report a vulnerability" button on the repository's Security tab). This
opens a draft advisory visible only to you and the maintainer.

Please do **not** open a public issue for a suspected vulnerability.

Include what you have: the affected version or commit, the command line and
corpus entry that triggers it, and what an attacker gains. A proof of concept
helps but is not required to file.

This is a single-maintainer hobby-scale project. Expect an acknowledgement
within about two weeks. There is no bug bounty.

## Scope

`liveness_primer` deliberately clones third-party repositories, installs
detector revisions from arbitrary refs, and executes those detectors as
subprocesses. **Running it means running other people's code.** Reports about
that design are in scope only where the tool fails to hold a boundary it claims
to hold — for example:

- Detector or corpus code escaping the network isolation the runner asserts
  (`liveness_primer/isolation.py`), or the run being reported as isolated when
  it was not.
- Path traversal in `liveness_primer`'s own cache management that causes a
  checkout or detector environment to be created outside the configured cache
  root (`liveness_primer/corpus.py`, `envcache.py`). This is not a general
  filesystem sandbox: detector build hooks and subprocesses retain the current
  user's access to host-visible paths.
- Corpus or report input causing code execution during parsing — the corpus is
  loaded with PyYAML's safe loader and validated by pydantic, so anything that
  reaches `eval`/`exec`/arbitrary constructors is a bug.
- Secrets (tokens, environment contents) leaking into reports, logs, or
  subprocess environments.

Out of scope:

- Vulnerabilities in the detectors themselves (`vulture`, `skylos`) or in
  corpus projects — report those to their maintainers.
- Wrong, missing, or noisy detector findings. That is a correctness bug; open a
  normal issue.
- Running detector refs you do not trust without external filesystem and
  resource isolation. The built-in isolation removes network access and
  credentials but does not restrict filesystem access; run such comparisons in
  a disposable container.
