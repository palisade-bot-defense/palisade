.PHONY: build test check verify release-plan release release-sign release-verify release-signing-check red-team red-team-plan benchmark-plan benchmark-local coverage-check privacy-check license-check adapter-conformance normalized-contract artifact-contract offline-eval-test replay dev demo docker

build:
	pnpm build
	go build -trimpath -o bin/palisade ./cmd/palisade

test:
	go test -race ./...
	python3 -m unittest scripts/test_evaluate_offline.py scripts/test_run_red_team.py scripts/test_benchmark_local.py
	pnpm test

check: coverage-check privacy-check license-check
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

red-team:
	python3 scripts/run_red_team.py

red-team-plan:
	python3 scripts/run_red_team.py --list

benchmark-plan:
	python3 scripts/benchmark_local.py --plan

benchmark-local:
	@test -n "$(OUTPUT)" || (echo "OUTPUT is required" >&2; exit 2)
	python3 scripts/benchmark_local.py --output "$(OUTPUT)"

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
