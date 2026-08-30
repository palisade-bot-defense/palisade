.PHONY: build test check verify browser-e2e browser-e2e-check deployment-tls-test release-plan release release-compare release-reproduction-verify release-sign release-verify release-signing-check operator-shadow-drill load-test-plan load-test-local red-team red-team-plan red-team-report red-team-verify benchmark-plan benchmark-local benchmark-verify compatibility-check migration-check coverage-check privacy-check license-check adapter-conformance normalized-contract artifact-contract replay dev demo docker

build:
	pnpm build
	go build -trimpath -o bin/palisade ./cmd/palisade

test:
	go test -race ./...
	python3 -m unittest scripts/test_operator_shadow_drill.py scripts/test_load_test_local.py scripts/test_run_red_team.py scripts/test_red_team_findings.py scripts/test_benchmark_local.py scripts/test_compare_release_reproduction.py scripts/test_compatibility_freeze.py scripts/test_migration_matrix.py
	pnpm test

check: coverage-check privacy-check license-check compatibility-check migration-check browser-e2e-check
	go vet ./...
	pnpm typecheck

verify:
	./scripts/verify-local.sh

browser-e2e:
	node scripts/browser-e2e.mjs

browser-e2e-check:
	node --check scripts/browser-e2e.mjs

deployment-tls-test:
	go test -race ./pkg/palisadehttp ./pkg/palisadeproxy -run 'Test.*TLS.*Deployment' -count=1

release-plan:
	@test -n "$(VERSION)" || (echo "VERSION is required" >&2; exit 2)
	./scripts/release-local.sh --plan "$(VERSION)"

release:
	@test -n "$(VERSION)" || (echo "VERSION is required" >&2; exit 2)
	./scripts/release-local.sh "$(VERSION)"

release-compare:
	@test -n "$(VERSION)" || (echo "VERSION is required" >&2; exit 2)
	@test -n "$(PREPARER)" || (echo "PREPARER is required" >&2; exit 2)
	@test -n "$(REPRODUCER)" || (echo "REPRODUCER is required" >&2; exit 2)
	@test -n "$(OUTPUT)" || (echo "OUTPUT is required" >&2; exit 2)
	python3 scripts/compare_release_reproduction.py --version "$(VERSION)" --preparer "$(PREPARER)" --reproducer "$(REPRODUCER)" --output "$(OUTPUT)"

release-reproduction-verify:
	@test -n "$(REPORT)" || (echo "REPORT is required" >&2; exit 2)
	python3 scripts/compare_release_reproduction.py --verify "$(REPORT)"

release-sign:
	@test -n "$(VERSION)" || (echo "VERSION is required" >&2; exit 2)
	@test -n "$(SIGNER)" || (echo "SIGNER is required" >&2; exit 2)
	@test -n "$(KEY_FILE)" || (echo "KEY_FILE is required" >&2; exit 2)
	./scripts/sign-release-checksums.sh "$(SIGNER)" "$(KEY_FILE)" "dist/release/$(VERSION)"

release-verify:
	@test -n "$(VERSION)" || (echo "VERSION is required" >&2; exit 2)
	./scripts/verify-release.sh "$(VERSION)" "dist/release/$(VERSION)" "maintainers/release-allowed-signers"

release-signing-check:
	./scripts/release-signing_test.sh

operator-shadow-drill:
	./scripts/operator-shadow-drill.sh

load-test-plan:
	python3 scripts/load_test_local.py --plan

load-test-local:
	@test -n "$(BINARY)" || (echo "BINARY is required" >&2; exit 2)
	python3 scripts/load_test_local.py --binary "$(BINARY)"

red-team:
	python3 scripts/run_red_team.py

red-team-plan:
	python3 scripts/run_red_team.py --list

red-team-report:
	@test -n "$(OUTPUT)" || (echo "OUTPUT is required" >&2; exit 2)
	python3 scripts/red_team_findings.py --output "$(OUTPUT)"

red-team-verify:
	@test -n "$(REPORT)" || (echo "REPORT is required" >&2; exit 2)
	python3 scripts/red_team_findings.py --verify "$(REPORT)"

benchmark-plan:
	python3 scripts/benchmark_local.py --plan

benchmark-local:
	@test -n "$(OUTPUT)" || (echo "OUTPUT is required" >&2; exit 2)
	python3 scripts/benchmark_local.py --output "$(OUTPUT)"

benchmark-verify:
	@test -n "$(REPORT)" || (echo "REPORT is required" >&2; exit 2)
	python3 scripts/benchmark_local.py --verify "$(REPORT)"

compatibility-check:
	python3 scripts/check_compatibility_freeze.py

migration-check:
	python3 scripts/check_migration_matrix.py

coverage-check:
	./scripts/check-go-coverage.sh

privacy-check:
	./scripts/privacy-check.sh
	./scripts/privacy-check_test.sh

license-check:
	./scripts/license-check.sh

adapter-conformance:
	go test ./pkg/palisadehttp ./pkg/palisadeproxy -run TestOriginAdapterConformanceSuiteV1 -count=1

normalized-contract:
	go test ./pkg/palisadecontract -count=1

artifact-contract:
	go test ./internal/localartifact ./internal/policy ./internal/detector ./internal/engine -count=1

replay:
	go run ./cmd/palisade replay --file examples/replay/synthetic.jsonl

dev:
	go run ./cmd/palisade serve --dev

demo:
	docker compose up --build

docker:
	docker build -t palisade:dev .
