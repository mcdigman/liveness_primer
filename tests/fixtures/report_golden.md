# liveness primer report - `vulture`

- **schema**: 1.1.0; **created**: 2026-07-28T12:00:00+00:00
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

base findings 13, head findings 15

| new | dropped | changed | confidence changes | message-only |
| --- | --- | --- | --- | --- |
| 3 | 2 | 9 | 1 | 5 |

- **rollup**: new 3: SKY-U001 2, kind:function 1
- **rollup**: dropped 2: kind:function 2
- **rollup**: changed 9: kind:function 9
- **cost**: 1.67s
- **errors**: 1
- **corpus-integrity warnings**: 1
- **source warnings**: 1

Some project diffs were truncated by `--max-results`; totals reflect the full comparison.

legend: + new; - dropped; ~ changed

## `alpha`

base 12 findings, head 13; 2 new, 2 dropped, 8 changed (1 confidence, 5 message-only); cost 1.25s
- **corpus**: [https://github.com/example/alpha @ 333333333333](https://github.com/example/alpha/tree/3333333333333333333333333333333333333333)
- **rollup**: new 2: SKY-U001 2
- **rollup**: dropped 2: kind:function 2
- **rollup**: changed 8: kind:function 8
- **error[head]**: stderr said  something  odd
- **warning[corpus-integrity]**: expected-clean base side reported 12 finding(s) and exit code 3
- **warning[source]**: pkg/gone.py: not a regular non-symlink file
- note: showing 11 of 12 finding diffs (truncated by `--max-results`)

|  | rule | % | location | symbol | message |
| --- | --- | --- | --- | --- | --- |
| 🟢 + | SKY-U001 | 100% | [pkg/mod.py:L9](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L9) | fresh \| pipe\`tick\` | unused function with a very hostile excerpt<br>9 \| `def fresh(request):`<br>\[...\] |
| 🔴 - | - | 60% | [pkg/mod.py:L5](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L5) | goner | unused function 'goner'<br>5 \| `def goner():` |
| 🟡 ~ | - | 60% | [pkg/mod.py:L10->L14](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L10) | mover | unused function 'mover'<br>line: L10 -> L14<br>[base](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L10):<br>10 \| `def mover():`<br>[head](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L14):<br>14 \| `def mover():  # moved` |
| 🟡 ~ | - | 60%->90% | [pkg/mod.py:L21](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L21) | flaky | unused function 'flaky'<br>%: 60% -> 90%<br>21 \| `def flaky():` |
| 🟡 ~ | SKY-U001 | 60% | [pkg/mod.py:L40](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L40) | renumbered | renumbered rule<br>rule: SKY-U001 -> SKY-U003<br>40 \| `def renumbered():` |
| 🔴 - | - | NA | [pkg/mod.py:L50-57](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L50-L57) | span | multi-line span with an omitted tail<br>50 \| `class Span:`<br>\[...\] |
| 🟡 ~ | - | 60% | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | reworded-1 | old wording for reworded-1<br>message: old wording for reworded-1 -> new wording for reworded-1 |
| 🟡 ~ | - | 60% | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | reworded-2 | old wording for reworded-2<br>message: old wording for reworded-2 -> new wording for reworded-2 |
| 🟡 ~ | - | 60% | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | reworded-3 | old wording for reworded-3<br>message: old wording for reworded-3 -> new wording for reworded-3 |

(2 more message-only change(s) not shown; the JSON report retains full detail)

## `beta`

base 1 findings, head 2; 1 new, 0 dropped, 1 changed (0 confidence, 0 message-only); cost 0.42s
- **corpus**: ssh://git@internal.invalid/beta.git @ 444444444444
- **rollup**: new 1: kind:function 1
- **rollup**: changed 1: kind:function 1

|  | rule | % | location | symbol | message |
| --- | --- | --- | --- | --- | --- |
| 🟢 + | - | NA | lib/util.py:L3 | unlinked | no permalink for ad-hoc hosts<br>3 \| `x = 1` |
| 🟡 ~ | - | NA | lib/move.py:L7->L11 | wanderer | moved without a permalink<br>line: L7 -> L11<br>base:<br>7 \| `old = 7`<br>head:<br>11 \| `new = 11` |

## `gamma`

base 0 findings, head 0; 0 new, 0 dropped, 0 changed (0 confidence, 0 message-only); cost n/a
