#!/bin/sh
set -eu

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

test -f LICENSE
test -f LICENSING.md
test -f sensor/LICENSE
test -f verifier/LICENSE
test ! -e LICENSE-PENDING.md

grep -q 'GNU AFFERO GENERAL PUBLIC LICENSE' LICENSE
grep -q 'Apache License' sensor/LICENSE
grep -q 'Apache License' verifier/LICENSE
grep -q 'AGPL-3.0-only' LICENSING.md
grep -q 'Apache-2.0' LICENSING.md
grep -q 'AGPL-3.0-only' docs/github-org/profile/README.md
grep -q 'Apache-2.0' docs/github-org/profile/README.md

node - <<'NODE'
const fs = require('fs');
const root = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const dashboard = JSON.parse(fs.readFileSync('dashboard/package.json', 'utf8'));
const sensor = JSON.parse(fs.readFileSync('sensor/package.json', 'utf8'));
const verifier = JSON.parse(fs.readFileSync('verifier/package.json', 'utf8'));
if (root.license !== 'AGPL-3.0-only') throw new Error('root license mismatch');
if (dashboard.license !== 'AGPL-3.0-only') throw new Error('dashboard license mismatch');
if (sensor.license !== 'Apache-2.0') throw new Error('sensor license mismatch');
if (verifier.license !== 'Apache-2.0') throw new Error('verifier license mismatch');
NODE

if git grep -I -i -E 'PolyForm Shield|license pending|LICENSE-PENDING|"license"[[:space:]]*:[[:space:]]*"UNLICENSED"' -- ':!LICENSE' ':!sensor/LICENSE' ':!verifier/LICENSE' ':!scripts/license-check.sh'; then
	echo "license-check: stale license wording found" >&2
	exit 1
fi

echo "license-check: AGPL core and Apache sensor/verifier boundary passed"
