# liveness primer report - `vulture`

- **schema**: 1.0.0; **created**: 2026-07-28T12:00:00+00:00
- **detector**: https://github.com/jendrikseipp/vulture
- **base**: `main` @ `111111111111` (cached)
- **head**: `pr-branch` @ `222222222222` (rebuilt)
- **comparable**: yes
- **isolation**: :warning: **NOT ENFORCED** - no network sandbox (contract §11)
- **installer**: pip 26.0

## :warning: Environment delta

Non-detector dependencies differ between the sides (contract §3):

| package | base | head |
| --- | --- | --- |
| tomli | 2.4.0 | 2.5.0 |

## Totals

| new | dropped | changed | confidence changes | message-only |
| --- | --- | --- | --- | --- |
| 2 | 1 | 7 | 1 | 5 |

Some project diffs were truncated by `--max-results`; totals reflect the full comparison.

## `alpha`

base 12 findings, head 13; 2 new, 1 dropped, 7 changed (1 confidence, 5 message-only); cost 1.25s
- **error[head]**: stderr said  something  odd
- **warning[corpus-integrity]**: expected-clean base side reported 12 finding(s) and exit code 3
- note: diffs below are truncated by `--max-results`; totals reflect the full comparison

| class | location | kind | symbol | fields | confidence | message |
| --- | --- | --- | --- | --- | --- | --- |
| new | pkg/mod.py:L9 | function | fresh \| pipe\`tick\` | - | 100% | unused function with a very hostile excerpt |
| dropped | pkg/mod.py:L5 | function | goner | - | 60% | unused function 'goner' |
| changed | pkg/mod.py:L10->L14 | function | mover | line-span | 60% | unused function 'mover' |
| changed | pkg/mod.py:L21 | function | flaky | confidence | 60%->90% | unused function 'flaky' |
| changed | pkg/mod.py:L30 | function | reworded-1 | message | 60% | old wording for reworded-1 |
| changed | pkg/mod.py:L30 | function | reworded-2 | message | 60% | old wording for reworded-2 |
| changed | pkg/mod.py:L30 | function | reworded-3 | message | 60% | old wording for reworded-3 |

(2 more message-only change(s) not shown; the JSON report retains full detail)

<details><summary>excerpts (untrusted data)</summary>

```text
[new] pkg/mod.py:L9
evil.py:9: unused function `x`  [31mANSI  (60% confidence)
line two
... (1 more excerpt line(s) omitted)
[dropped] pkg/mod.py:L5
pkg/mod.py:5: unused function 'goner'
```

</details>

## `beta`

base 0 findings, head 0; 0 new, 0 dropped, 0 changed (0 confidence, 0 message-only); cost 0.42s
