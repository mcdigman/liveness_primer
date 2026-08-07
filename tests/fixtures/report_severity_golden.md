# liveness primer report - `skylos`

- **schema**: 2.0.0; **created**: 2026-07-28T12:00:00+00:00
- **detector**: https://github.com/duriantaco/skylos
- **base**: `main` @ `111111111111` (cached)
- **head**: `pr-branch` @ `222222222222` (rebuilt)
- **comparable**: yes
- **isolation**: :warning: **NOT ENFORCED** - no network sandbox
- **installer**: pip 26.0

## Totals

base findings 2, head findings 3

| new | dropped | changed | confidence changes | message-only | severity-only |
| --- | --- | --- | --- | --- | --- |
| 2 | 1 | 1 | 0 | 0 | 1 |

- **rollup**: new 2: SKY-D205 1, SKY-U001 1
- **rollup**: dropped 1: SKY-D401 1
- **rollup**: changed 1: SKY-D203 1
- **cost**: 0.90s

legend: + new; - dropped; ~ changed

## `sec`

base 2 findings, head 3; 2 new, 1 dropped, 1 changed (0 confidence, 0 message-only, 1 severity-only); cost 0.90s
- **corpus**: [https://github.com/example/sec @ 555555555555](https://github.com/example/sec/tree/5555555555555555555555555555555555555555)
- **rollup**: new 2: SKY-D205 1, SKY-U001 1
- **rollup**: dropped 1: SKY-D401 1
- **rollup**: changed 1: SKY-D203 1

|  | rule | % | severity | location | message |
| --- | --- | --- | --- | --- | --- |
| 🟢 + | SKY-D205 | NA | CRITICAL | [app/load.py:L6](https://github.com/example/sec/blob/5555555555555555555555555555555555555555/app/load.py#L6) | Untrusted deserialization via pickle.loads<br>6 \| `    return pickle.loads(data)` |
| 🟡 ~ | SKY-D203 | NA | MEDIUM->HIGH | [app/exec.py:L9](https://github.com/example/sec/blob/5555555555555555555555555555555555555555/app/exec.py#L9) | Use of os.system()<br>severity: MEDIUM -> HIGH<br>9 \| `    os.system(cmd)` |
| 🔴 - | SKY-D401 | NA | MEDIUM | [app/hash.py:L12](https://github.com/example/sec/blob/5555555555555555555555555555555555555555/app/hash.py#L12) | Weak hash algorithm md5<br>12 \| `digest = hashlib.md5(blob)` |
| 🟢 + | SKY-U001 | 80% | - | [app/load.py:L20](https://github.com/example/sec/blob/5555555555555555555555555555555555555555/app/load.py#L20) | unused function 'unused'<br>20 \| `def unused():` |
