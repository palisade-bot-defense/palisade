.PHONY: build test check verify release-plan release release-compare release-reproduction-verify release-sign release-verify release-signing-check operator-shadow-drill red-team red-team-plan red-team-report red-team-verify benchmark-plan benchmark-local benchmark-verify compatibility-check coverage-check privacy-check license-check adapter-conformance normalized-contract artifact-contract offline-eval-test replay dev demo docker

build:
	pnpm build
	go build -trimpath -o bin/palisade ./cmd/palisade

test:
	go test -race ./...
	python3 -m unittest scripts/test_evaluate_offline.py scripts/test_operator_shadow_drill.py scripts/test_run_red_team.py scripts/test_red_team_findings.py scripts/test_benchmark_local.py scripts/test_compare_release_reproduction.py scripts/test_compatibility_freeze.py
	pnpm test

check: coverage-check privacy-check license-check compatibility-check
	go vet ./...
	pnpm typecheck

verify:
	./scripts/verify-local.sh

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

offline-eval-test:
	python3 -m unittest scripts/test_evaluate_offline.py

replay:
	go run ./cmd/palisade replay --file examples/replay/synthetic.jsonl

dev:
	go run ./cmd/palisade serve --dev

demo:
	docker compose up --build

docker:
	docker build -t palisade:dev .
