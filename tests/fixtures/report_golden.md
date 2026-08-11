# liveness primer report - `vulture`

- **schema**: 2.0.0; **created**: 2026-07-28T12:00:00+00:00
- **detector**: https://github.com/jendrikseipp/vulture
- **base**: `main` @ `111111111111` (cached)
- **head**: `pr-branch` @ `222222222222` (rebuilt)
- **comparable**: yes
- **isolation**: :warning: **NOT ENFORCED** - no network sandbox
- **installer**: pip 26.0

## :warning: Environment delta

Non-detector dependencies differ between the sides:

| package | base | head |
| --- | --- | --- |
| tomli | 2.4.0 | 2.5.0 |

## Totals

base findings 13, head findings 15

| new | dropped | changed | confidence-only | message-only | severity-only | multiple |
| --- | --- | --- | --- | --- | --- | --- |
| 4 | 4 | 8 | 1 | 6 | 0 | 1 |

- **rollup**: new 4: kind:function 2, SKY-U001 1, SKY-U003 1
- **rollup**: dropped 4: kind:function 3, SKY-U001 1
- **rollup**: changed 8: kind:function 8
- **cost**: 1.67s
- **errors**: 1
- **corpus-integrity warnings**: 1
- **source warnings**: 1

Some project diffs were truncated by `--max-results`; totals reflect the full comparison.

legend: + new; - dropped; ~ changed

## `alpha`

base 12 findings, head 13; 3 new, 4 dropped, 7 changed (1 confidence-only, 5 message-only, 0 severity-only, 1 multiple); cost 1.25s
- **corpus**: [https://github.com/example/alpha @ 333333333333](https://github.com/example/alpha/tree/3333333333333333333333333333333333333333)
- **rollup**: new 3: SKY-U001 1, SKY-U003 1, kind:function 1
- **rollup**: dropped 4: kind:function 3, SKY-U001 1
- **rollup**: changed 7: kind:function 7
- **error[head]**: stderr said  something  odd
- **warning[corpus-integrity]**: expected-clean base side reported 12 finding(s) and exit code 3
- **warning[source]**: pkg/gone.py: not a regular non-symlink file
- note: showing 13 of 14 finding diffs (truncated by `--max-results`)

|  | rule | % | location | message |
| --- | --- | --- | --- | --- |
| 🔴 - | - | 60% | [pkg/mod.py:L5](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L5) | unused function 'goner'<br>5 \| `def goner():` |
| 🟢 + | SKY-U001 | 100% | [pkg/mod.py:L9](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L9) | unused function with a very hostile excerpt<br>9 \| `def fresh(request):`<br>\[...\] |
| 🔴 - | - | 60% | [pkg/mod.py:L10](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L10) | unused function 'mover'<br>10 \| `def mover():` |
| 🟢 + | - | 60% | [pkg/mod.py:L14](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L14) | unused function 'mover'<br>14 \| `def mover():  # moved` |
| 🟡 ~ | - | 60%->90% | [pkg/mod.py:L21](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L21) | unused function 'flaky'<br>%: 60% -> 90%<br>21 \| `def flaky():` |
| 🟡 ~ | - | 60% | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | old wording for reworded-1<br>message: old wording for reworded-1 -> new wording for reworded-1 |
| 🟡 ~ | - | 60% | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | old wording for reworded-2<br>message: old wording for reworded-2 -> new wording for reworded-2 |
| 🟡 ~ | - | 60% | [pkg/mod.py:L30](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L30) | old wording for reworded-3<br>message: old wording for reworded-3 -> new wording for reworded-3 |
| 🔴 - | SKY-U001 | 60% | [pkg/mod.py:L40](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L40) | renumbered rule<br>40 \| `def renumbered():` |
| 🟢 + | SKY-U003 | 60% | [pkg/mod.py:L40](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L40) | renumbered rule |
| 🔴 - | - | NA | [pkg/mod.py:L50-57](https://github.com/example/alpha/blob/3333333333333333333333333333333333333333/pkg/mod.py#L50-L57) | multi-line span with an omitted tail<br>50 \| `class Span:`<br>\[...\] |

(2 more message-only change(s) not shown; the JSON report retains full detail)

## `beta`

base 1 findings, head 2; 1 new, 0 dropped, 1 changed (0 confidence-only, 1 message-only, 0 severity-only); cost 0.42s
- **corpus**: ssh://git@internal.invalid/beta.git @ 444444444444
- **rollup**: new 1: kind:function 1
- **rollup**: changed 1: kind:function 1

|  | rule | % | location | message |
| --- | --- | --- | --- | --- |
| 🟢 + | - | NA | lib/util.py:L3 | no permalink for ad-hoc hosts<br>3 \| `x = 1` |
| 🟡 ~ | - | NA | lib/move.py:L7 | old wording without a permalink<br>message: old wording without a permalink -> new wording without a permalink<br>7 \| `old = 7` |

## `gamma`

base 0 findings, head 0; 0 new, 0 dropped, 0 changed (0 confidence-only, 0 message-only, 0 severity-only); cost n/a
