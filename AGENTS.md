`liveness_primer` is a tool for examining the blast radius of PRs to dead code search utilities.
The module is strictly typed: always use the narrowest type possible when creating functions and variables,
avoiding vague generics and `Any` or `object` unless the function legitimately must accept anything.
Do not add `type: ignore` comments without express permission.
The module uses a strict linting configuration, running `ruff` with rules `ALL`. Do not add `noqa:` statements.
The module uses pre-commit hooks which are run before commit with `prek run --all-files`.
The pre-commit hooks will run `ruff format`.
Additionally `mypy` and `pyright` are run as CI workflows, with settings in pyproject.toml.
Write very briefy, numpy style docstrings, which checked by the `pydoclint` CI workflow.
A `skylos` CI workflow is used for dead code detection.
Unit tests are `pytest` style. Unit tests should aim for full branch and line coverage with non-vacuous tests.
A ``coverage.py` CI workflow enforces thorough testing coverage.
