#!/bin/sh
set -eu

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/palisade-operator-shadow-drill.XXXXXX")
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM

go build -trimpath -o "$temporary_root/palisade" ./cmd/palisade
python3 scripts/operator_shadow_drill.py --binary "$temporary_root/palisade"
