#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repository_root"

overall_min=${PALISADE_GO_COVERAGE_MIN:-70.0}
critical_min=${PALISADE_GO_CRITICAL_COVERAGE_MIN:-70.0}
coverage_root=$(mktemp -d "${TMPDIR:-/tmp}/palisade-coverage.XXXXXX")
trap 'rm -rf "$coverage_root"' EXIT HUP INT TERM

profile="$coverage_root/coverage.out"
log="$coverage_root/go-test.log"

if ! go test -coverprofile="$profile" ./... >"$log" 2>&1; then
	cat "$log" >&2
	exit 1
fi
cat "$log"

overall=$(go tool cover -func="$profile" | awk '$1 == "total:" { value = $NF; sub(/%$/, "", value); print value }')

valid_number() {
	awk -v value="$1" 'BEGIN { exit !(value ~ /^[0-9]+([.][0-9]+)?$/) }'
}

meets_minimum() {
	awk -v actual="$1" -v minimum="$2" 'BEGIN { exit !(actual + 0 >= minimum + 0) }'
}

if ! valid_number "$overall" || ! valid_number "$overall_min" || ! valid_number "$critical_min"; then
	echo "coverage-check: invalid coverage value or threshold" >&2
	exit 1
fi
if ! meets_minimum "$overall" "$overall_min"; then
	echo "coverage-check: total ${overall}% is below ${overall_min}%" >&2
	exit 1
fi

module=github.com/palisade-bot-defense/palisade
critical_packages='
internal/analysisfeed
internal/challenge
internal/detector
internal/engine
internal/events
internal/fusion
internal/httpapi
internal/localsequence
internal/offlineimport
internal/policy
internal/replay
internal/rollout
internal/session
internal/sessioncookie
internal/shadowanalysis
internal/shadowlog
internal/token
pkg/palisadecontract
pkg/palisadehttp
'

for package in $critical_packages; do
	coverage=$(awk -v wanted="$module/$package" '
		$2 == wanted {
			for (field = 1; field <= NF; field++) {
				if ($field == "coverage:") {
					value = $(field + 1)
					sub(/%$/, "", value)
					print value
					exit
				}
			}
		}
	' "$log")
	if ! valid_number "$coverage"; then
		echo "coverage-check: missing coverage for $package" >&2
		exit 1
	fi
	if ! meets_minimum "$coverage" "$critical_min"; then
		echo "coverage-check: $package ${coverage}% is below ${critical_min}%" >&2
		exit 1
	fi
done

echo "coverage-check: total ${overall}% and critical packages >= ${critical_min}%"
