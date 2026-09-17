#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly DEFAULT_REPETITIONS=5
readonly DEFAULT_MAX_CONSECUTIVE_FAILURES=3
readonly ALL_ANALYSES='quality,danger,secrets,ai-defects'
readonly NO_MEASUREMENT_STATUS=20

usage() {
    cat <<'EOF'
Usage: benchmark_skylos_analyses.sh [LIVENESS-PRIMER-RUN-ARG ...]

Run a liveness-primer comparison repeatedly for the default analysis selection,
each Skylos opt-in analysis, and all four analyses together. Every run prints
its own per-project timing block as soon as it finishes, and the script reports
the minimum, median, and maximum measured cost for every project and for the
sum of all project costs in each run.

Detector failures do not stop the benchmark: a project whose invocation failed
contributes no measurement for that run, the remaining projects are still
recorded, and the summary reports how many measurements each project has. A run
that produces no report at all is skipped too, but the benchmark aborts once
that happens in several consecutive runs, which usually means a broken
invocation rather than a flaky project.

With no arguments, the benchmark uses the pinned mcdigman/skylos comparison
defined in this script. To benchmark another comparison, pass arguments starting
with "run"; do not include the liveness-primer executable, --analyses,
--json-out, or --output.

Environment variables:
  BENCHMARK_REPETITIONS  Number of runs per scenario (default: 5)
  BENCHMARK_RESULTS_DIR  Empty directory in which to save reports and summaries
  BENCHMARK_MAX_CONSECUTIVE_FAILURES
                         Consecutive runs without any measurement tolerated
                         before aborting (default: 3)
  LIVENESS_PRIMER_BIN    liveness-primer executable name or path
  PYTHON_BIN             Python executable name or path used to aggregate JSON
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

resolve_command() {
    local requested=$1
    local fallback=$2

    if [[ -n "$requested" ]]; then
        if [[ "$requested" == */* ]]; then
            [[ -x "$requested" ]] || die "executable not found: $requested"
        else
            command -v "$requested" >/dev/null 2>&1 || die "executable not found on PATH: $requested"
        fi
        printf '%s\n' "$requested"
        return
    fi

    if command -v "$fallback" >/dev/null 2>&1; then
        printf '%s\n' "$fallback"
        return
    fi

    return 1
}

if [[ ${1:-} == '-h' || ${1:-} == '--help' ]]; then
    usage
    exit 0
fi

readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly REPOSITORY_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)

repetitions=${BENCHMARK_REPETITIONS:-$DEFAULT_REPETITIONS}
[[ "$repetitions" =~ ^[1-9][0-9]*$ ]] || die 'BENCHMARK_REPETITIONS must be a positive integer'

max_consecutive_failures=${BENCHMARK_MAX_CONSECUTIVE_FAILURES:-$DEFAULT_MAX_CONSECUTIVE_FAILURES}
[[ "$max_consecutive_failures" =~ ^[1-9][0-9]*$ ]] ||
    die 'BENCHMARK_MAX_CONSECUTIVE_FAILURES must be a positive integer'

primer_bin=${LIVENESS_PRIMER_BIN:-}
if [[ -z "$primer_bin" ]]; then
    if primer_bin=$(resolve_command '' 'liveness-primer'); then
        :
    elif [[ -x "$REPOSITORY_ROOT/.venv/bin/liveness-primer" ]]; then
        primer_bin="$REPOSITORY_ROOT/.venv/bin/liveness-primer"
    else
        die 'liveness-primer is neither on PATH nor available in .venv/bin'
    fi
else
    primer_bin=$(resolve_command "$primer_bin" 'liveness-primer')
fi

python_bin=${PYTHON_BIN:-}
if [[ -z "$python_bin" ]]; then
    if python_bin=$(resolve_command '' 'python3'); then
        :
    elif [[ -x "$REPOSITORY_ROOT/.venv/bin/python" ]]; then
        python_bin="$REPOSITORY_ROOT/.venv/bin/python"
    else
        die 'python3 is neither on PATH nor available in .venv/bin'
    fi
else
    python_bin=$(resolve_command "$python_bin" 'python3')
fi

if (( $# )); then
    base_args=("$@")
    [[ ${base_args[0]} == 'run' ]] || die 'custom arguments must start with the run subcommand'
    for argument in "${base_args[@]}"; do
        case "$argument" in
            --analyses | --analyses=* | --json-out | --json-out=* | --output | --output=*)
                die 'the script manages --analyses, --json-out, and --output'
                ;;
        esac
    done
else
    base_args=(
        run
        --tool skylos
        --repo https://github.com/mcdigman/skylos
        --old 00e3a04d2bb6e5d7f127d7db4b4ceedf8ff2a05e
        --new 00e3a04d2bb6e5d7f127d7db4b4ceedf8ff2a05e
        --all
        --max-results 200
        --excerpt-lines 5
        --jobs 1
        --timeout 600
        --ignore-include-tools
    )
fi

if [[ -n ${BENCHMARK_RESULTS_DIR:-} ]]; then
    results_dir=$BENCHMARK_RESULTS_DIR
    mkdir -p -- "$results_dir"
    if [[ -n $(find "$results_dir" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
        die "BENCHMARK_RESULTS_DIR must be empty: $results_dir"
    fi
else
    temporary_parent=${TMPDIR:-/tmp}
    temporary_parent=${temporary_parent%/}
    results_dir=$(mktemp -d "$temporary_parent/liveness-primer-analysis-costs.XXXXXX")
fi
readonly results_dir
readonly records_path="$results_dir/records.jsonl"
readonly blocks_path="$results_dir/run-costs.txt"

scenario_names=('default' 'quality' 'danger' 'secrets' 'ai-defects' 'all')
analysis_selections=('' 'quality' 'danger' 'secrets' 'ai-defects' "$ALL_ANALYSES")

printf 'Results directory: %s\n' "$results_dir" >&2
printf 'Runs per scenario: %s (%s total runs)\n' "$repetitions" "$((repetitions * ${#scenario_names[@]}))" >&2

{
    printf 'Executable:'
    printf ' %q' "$primer_bin"
    printf '\nBase arguments:'
    printf ' %q' "${base_args[@]}"
    printf '\nRepetitions: %s\n' "$repetitions"
} >"$results_dir/benchmark-command.txt"

consecutive_failures=0

for scenario_index in "${!scenario_names[@]}"; do
    scenario=${scenario_names[$scenario_index]}
    selection=${analysis_selections[$scenario_index]}
    scenario_dir="$results_dir/$scenario"
    mkdir -p -- "$scenario_dir"

    for ((run_number = 1; run_number <= repetitions; run_number += 1)); do
        stem=$(printf 'run-%02d' "$run_number")
        json_report="$scenario_dir/$stem.json"
        text_report="$scenario_dir/$stem.txt"
        stderr_log="$scenario_dir/$stem.stderr.txt"
        command_args=("${base_args[@]}" --output text --color never --hyperlinks never --json-out "$json_report")
        if [[ -n "$selection" ]]; then
            command_args+=(--analyses "$selection")
        fi

        printf '[%s/%s] %s, run %s/%s\n' \
            "$((scenario_index * repetitions + run_number))" \
            "$((repetitions * ${#scenario_names[@]}))" \
            "$scenario" \
            "$run_number" \
            "$repetitions" >&2

        if "$primer_bin" "${command_args[@]}" >"$text_report" 2>"$stderr_log"; then
            run_status=0
        else
            run_status=$?
            printf 'warning: %s run %s exited with status %s; see %s and %s\n' \
                "$scenario" "$run_number" "$run_status" "$text_report" "$stderr_log" >&2
        fi

        # Records the run, prints its timing block, and reports through its own
        # exit status whether the run yielded any measurement at all.
        if "$python_bin" - \
            "$json_report" "$records_path" "$blocks_path" \
            "$scenario" "$run_number" "$repetitions" "$run_status" "$NO_MEASUREMENT_STATUS" <<'PY'
import json
import math
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
records_path = Path(sys.argv[2])
blocks_path = Path(sys.argv[3])
scenario = sys.argv[4]
run_number = int(sys.argv[5])
repetitions = int(sys.argv[6])
run_status = int(sys.argv[7])
no_measurement_status = int(sys.argv[8])

header = f'--- {scenario} run {run_number}/{repetitions} ---'


def emit(record, lines):
    """Append the run record and print its timing block."""
    with records_path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')
    text = '\n'.join((header, *lines)) + '\n'
    with blocks_path.open('a', encoding='utf-8') as stream:
        stream.write(text)
    sys.stderr.write(text)


def unusable(detail):
    """Record a run that produced no usable report and stop."""
    emit(
        {
            'scenario': scenario,
            'run': run_number,
            'exit_status': run_status,
            'costs': {},
            'failures': {},
            'detail': detail,
        },
        [f'  no measurements: {detail}'],
    )
    raise SystemExit(no_measurement_status)


try:
    with report_path.open(encoding='utf-8') as stream:
        report = json.load(stream)
except (OSError, ValueError) as exc:
    unusable(f'unreadable report (run exit status {run_status}): {exc}')

projects = report.get('projects')
if not isinstance(projects, list) or not projects:
    unusable(f'report contains no projects (run exit status {run_status})')

costs = {}
failures = {}
for project in projects:
    name = project.get('project')
    if not isinstance(name, str) or not name:
        unusable('report contains a project without a valid name')
    cost = project.get('measured_cost_seconds')
    if isinstance(cost, (int, float)) and not isinstance(cost, bool) and math.isfinite(cost) and cost >= 0:
        costs[name] = float(cost)
        continue
    errors = project.get('errors')
    details = [
        error['detail']
        for error in (errors if isinstance(errors, list) else ())
        if isinstance(error, dict) and isinstance(error.get('detail'), str)
    ]
    failures[name] = '; '.join(details) if details else 'no measured cost recorded'

complete = not failures
record = {
    'scenario': scenario,
    'run': run_number,
    'exit_status': run_status,
    'costs': costs,
    'failures': failures,
    'detail': '' if complete else f'{len(failures)} project(s) without a measurement',
}

names = sorted((*costs, *failures))
width = max(len(name) for name in names)
lines = [
    f'  {name.ljust(width)}  {costs[name]:10.3f}'
    if name in costs
    else f'  {name.ljust(width)}  {"FAILED".rjust(10)}  {failures[name]}'
    for name in names
]
total_label = 'TOTAL'.ljust(width)
if complete:
    lines.append(f'  {total_label}  {sum(costs.values()):10.3f}')
else:
    lines.append(f'  {total_label}  {sum(costs.values()):10.3f}  (partial: {len(failures)} project(s) failed)')

emit(record, lines)
if not costs:
    raise SystemExit(no_measurement_status)
PY
        then
            consecutive_failures=0
        else
            recorder_status=$?
            if (( recorder_status != NO_MEASUREMENT_STATUS )); then
                die "recording $scenario run $run_number failed with status $recorder_status"
            fi
            consecutive_failures=$((consecutive_failures + 1))
            printf 'warning: %s run %s produced no measurement (%s consecutive)\n' \
                "$scenario" "$run_number" "$consecutive_failures" >&2
            if (( consecutive_failures >= max_consecutive_failures )); then
                die "aborting after $consecutive_failures consecutive runs without any measurement; see $results_dir"
            fi
        fi
    done
done

"$python_bin" - "$records_path" "$results_dir" "$repetitions" <<'PY'
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

records_path = Path(sys.argv[1])
results_dir = Path(sys.argv[2])
repetitions = int(sys.argv[3])
scenario_names = ('default', 'quality', 'danger', 'secrets', 'ai-defects', 'all')

records = []
if records_path.exists():
    with records_path.open(encoding='utf-8') as stream:
        records = [json.loads(line) for line in stream if line.strip()]

measurements = []
samples = defaultdict(list)
incomplete_runs = []
empty_runs = []
project_names = set()

for record in records:
    scenario = record['scenario']
    run_number = record['run']
    costs = record['costs']
    project_names.update(costs)
    project_names.update(record['failures'])

    if not costs:
        empty_runs.append((scenario, run_number, record['detail']))
        continue

    for project, cost in sorted(costs.items()):
        measurements.append((scenario, run_number, project, f'{cost:.9f}'))
        samples[(scenario, project)].append(cost)
    for project in sorted(record['failures']):
        measurements.append((scenario, run_number, project, ''))

    if record['failures']:
        # A partial run's total covers fewer projects, so it is never
        # comparable with a complete one and is left out of TOTAL.
        incomplete_runs.append((scenario, run_number, sorted(record['failures'])))
        measurements.append((scenario, run_number, 'TOTAL', ''))
        continue
    total = sum(costs.values())
    measurements.append((scenario, run_number, 'TOTAL', f'{total:.9f}'))
    samples[(scenario, 'TOTAL')].append(total)

if not samples:
    sys.stderr.write('error: no run produced a measurement; nothing to summarize\n')
    raise SystemExit(1)

with (results_dir / 'measurements.csv').open('w', encoding='utf-8', newline='') as stream:
    writer = csv.writer(stream)
    writer.writerow(('scenario', 'run', 'project', 'cost_seconds'))
    writer.writerows(measurements)

summary_rows = []
for scenario in scenario_names:
    for project in (*sorted(project_names), 'TOTAL'):
        costs = samples.get((scenario, project), [])
        # Every scenario runs the same number of times, so whatever is not
        # measured is missing — a failed project, or a run without a report.
        missing = repetitions - len(costs)
        if not costs:
            summary_rows.append((scenario, project, len(costs), missing, None, None, None))
            continue
        summary_rows.append(
            (scenario, project, len(costs), missing, min(costs), statistics.median(costs), max(costs))
        )

with (results_dir / 'summary.csv').open('w', encoding='utf-8', newline='') as stream:
    writer = csv.writer(stream)
    writer.writerow(('scenario', 'project', 'runs', 'missing_runs', 'min_seconds', 'median_seconds', 'max_seconds'))
    writer.writerows(
        (*row[:4], *('' if value is None else f'{value:.9f}' for value in row[4:])) for row in summary_rows
    )

headers = ('scenario', 'project', 'runs', 'missing', 'min (s)', 'median (s)', 'max (s)')
display_rows = [
    (*row[:2], str(row[2]), str(row[3]), *('n/a' if value is None else f'{value:.3f}' for value in row[4:]))
    for row in summary_rows
]
widths = [max(len(headers[index]), *(len(row[index]) for row in display_rows)) for index in range(len(headers))]
lines = [
    '  '.join(header.ljust(widths[index]) for index, header in enumerate(headers)),
    '  '.join('-' * width for width in widths),
]
for row in display_rows:
    lines.append(
        '  '.join(
            value.ljust(widths[index]) if index < 2 else value.rjust(widths[index])
            for index, value in enumerate(row)
        )
    )

if incomplete_runs or empty_runs:
    lines.append('')
    lines.append('Runs excluded from TOTAL:')
    for scenario, run_number, projects in incomplete_runs:
        lines.append(f'  {scenario} run {run_number}: failed projects {", ".join(projects)}')
    for scenario, run_number, detail in empty_runs:
        lines.append(f'  {scenario} run {run_number}: no measurements ({detail})')

summary_text = '\n'.join(lines) + '\n'
(results_dir / 'summary.txt').write_text(summary_text, encoding='utf-8')
sys.stdout.write(summary_text)
PY

printf '\nRaw reports, per-run timing blocks, and CSV data: %s\n' "$results_dir" >&2
