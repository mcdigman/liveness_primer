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

|  | rule | % | kind | location | message | symbol | fields |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 🟢 + | SKY-U001 | 100% | function | [pkg/mod.py:L9](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L9) | unused function with a very hostile excerpt<br>9 \| def fresh(request):<br>(+1 more retained line(s); see the JSON report) | fresh \| pipe\`tick\` | - |
| 🔴 - | - | 60% | function | [pkg/mod.py:L5](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L5) | unused function 'goner'<br>5 \| def goner(): | goner | - |
| 🟡 ~ | - | 60% | function | [pkg/mod.py:L10->L14](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L10) | unused function 'mover'<br>line: L10 -> L14<br>[base](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L10):<br>10 \| def mover():<br>[head](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L14):<br>14 \| def mover():  # moved | mover | line |
| 🟡 ~ | - | 60%->90% | function | [pkg/mod.py:L21](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L21) | unused function 'flaky'<br>%: 60% -> 90%<br>21 \| def flaky(): | flaky | % |
| 🟡 ~ | SKY-U001 | 60% | function | [pkg/mod.py:L40](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L40) | renumbered rule<br>rule: SKY-U001 -> SKY-U003<br>40 \| def renumbered(): | renumbered | rule |
| 🔴 - | - | NA | function | [pkg/mod.py:L50-57](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L50-L57) | multi-line span with an omitted tail<br>50 \| class Span:<br>(+1 more retained line(s); 6 reported-span line(s) omitted; see the JSON report) | span | - |
| 🟡 ~ | - | 60% | function | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | old wording for reworded-1<br>message: old wording for reworded-1 -> new wording for reworded-1 | reworded-1 | message |
| 🟡 ~ | - | 60% | function | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | old wording for reworded-2<br>message: old wording for reworded-2 -> new wording for reworded-2 | reworded-2 | message |
| 🟡 ~ | - | 60% | function | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | old wording for reworded-3<br>message: old wording for reworded-3 -> new wording for reworded-3 | reworded-3 | message |

(2 more message-only change(s) not shown; the JSON report retains full detail)

## `beta`

base 1 findings, head 2; 1 new, 0 dropped, 1 changed (0 confidence, 0 message-only); cost 0.42s
- **corpus**: ssh://git@internal.invalid/beta.git @ 444444444444
- **rollup**: new 1: kind:function 1
- **rollup**: changed 1: kind:function 1

|  | rule | % | kind | location | message | symbol | fields |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 🟢 + | - | NA | function | lib/util.py:L3 | no permalink for ad-hoc hosts<br>3 \| x = 1 | unlinked | - |
| 🟡 ~ | - | NA | function | lib/move.py:L7->L11 | moved without a permalink<br>line: L7 -> L11<br>base:<br>7 \| old = 7<br>head:<br>11 \| new = 11 | wanderer | line |

## `gamma`

base 0 findings, head 0; 0 new, 0 dropped, 0 changed (0 confidence, 0 message-only); cost n/a
