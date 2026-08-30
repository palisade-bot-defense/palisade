#!/bin/sh
set -eu

repository_root=$(git rev-parse --show-toplevel)
cd "$repository_root"

for command_name in go node pnpm python3 git; do
	command -v "$command_name" >/dev/null 2>&1 || {
		echo "verify-local: required command not found: $command_name" >&2
		exit 1
	}
done

case "$(go env GOVERSION)" in
	go1.27.*) ;;
	*) echo "verify-local: Go 1.27.x is required" >&2; exit 1 ;;
esac
case "$(node --version)" in
	v24.*) ;;
	*) echo "verify-local: Node.js 24.x is required" >&2; exit 1 ;;
esac
case "$(pnpm --version)" in
	11.24.*) ;;
	*) echo "verify-local: pnpm 11.24.x is required" >&2; exit 1 ;;
esac

echo "verify-local: restoring locked JavaScript dependencies"
pnpm install --frozen-lockfile

echo "verify-local: Go tests, race detector, coverage and static analysis"
go test -race ./...
./scripts/check-go-coverage.sh
go vet ./...

echo "verify-local: offline evaluator and synthetic protocol runners"
python3 -m unittest scripts/test_evaluate_offline.py scripts/test_operator_shadow_drill.py scripts/test_run_red_team.py scripts/test_red_team_findings.py scripts/test_benchmark_local.py scripts/test_compatibility_freeze.py
python3 scripts/benchmark_local.py --verify benchmarks/synthetic-baseline-afc23a3.json
python3 scripts/red_team_findings.py --verify reports/red-team/synthetic-findings-25aaba7.json
python3 scripts/check_compatibility_freeze.py

echo "verify-local: synthetic red-team baseline with module downloads disabled"
python3 scripts/run_red_team.py

echo "verify-local: production-configured synthetic operator shadow drill"
./scripts/operator-shadow-drill.sh

echo "verify-local: TypeScript tests, types and reproducible assets"
pnpm test
pnpm typecheck
pnpm build
git diff --exit-code -- internal/adminui/dist

echo "verify-local: licensing and staged-index privacy boundaries"
./scripts/license-check.sh
./scripts/privacy-check.sh
./scripts/privacy-check_test.sh

echo "verify-local: offline release signing and tamper detection"
./scripts/release-signing_test.sh

echo "verify-local: all local gates passed"
