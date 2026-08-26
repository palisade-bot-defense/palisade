.PHONY: build test check replay dev docker

build:
	pnpm build
	go build -trimpath -o bin/palisade ./cmd/palisade

test:
	go test -race ./...
	pnpm test

check:
	go vet ./...
	pnpm typecheck

replay:
	go run ./cmd/palisade replay --file examples/replay/synthetic.jsonl

dev:
	go run ./cmd/palisade serve --dev

docker:
	docker build -t palisade:dev .
