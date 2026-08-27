.PHONY: build test check privacy-check license-check offline-eval-test replay dev docker

build:
	pnpm build
	go build -trimpath -o bin/palisade ./cmd/palisade

test:
	go test -race ./...
	python3 -m unittest scripts/test_evaluate_offline.py
	pnpm test

check: privacy-check license-check
	go vet ./...
	pnpm typecheck

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

docker:
	docker build -t palisade:dev .
