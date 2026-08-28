.PHONY: build test check coverage-check privacy-check license-check offline-eval-test replay dev demo docker

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

coverage-check:
	./scripts/check-go-coverage.sh

privacy-check:
	./scripts/privacy-check.sh
	./scripts/privacy-check_test.sh

license-check:
	./scripts/license-check.sh

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
