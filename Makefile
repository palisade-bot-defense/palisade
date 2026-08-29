.PHONY: build test check verify release-plan release coverage-check privacy-check license-check adapter-conformance normalized-contract artifact-contract offline-eval-test replay dev demo docker

build:
	pnpm build
	go build -trimpath -o bin/palisade ./cmd/palisade

test:
	go test -race ./...
	python3 -m unittest scripts/test_evaluate_offline.py
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

coverage-check:
	./scripts/check-go-coverage.sh

privacy-check:
	./scripts/privacy-check.sh
	./scripts/privacy-check_test.sh

license-check:
	./scripts/license-check.sh

adapter-conformance:
	go test ./pkg/palisadehttp -run TestOriginAdapterConformanceSuiteV1 -count=1

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
