.PHONY: build fetch seed-kev test lint up down

build:
	cargo build --release --workspace
	mkdir -p go/bin
	cd go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/patch-diff-mcp ./cmd/patch-diff-mcp
	cd go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/scope-guard-mcp ./cmd/scope-guard-mcp

fetch:
	./target/release/nexus-sync fetch

seed-kev:
	./target/release/nexus-sync seed-kev

test:
	cargo test --workspace
	cd go && go test -race -v ./...

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cd go && go vet ./...

up:
	docker compose up -d --build

down:
	docker compose down
