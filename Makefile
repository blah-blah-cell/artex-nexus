.PHONY: build fetch seed-kev serve scan test lint up down

build:
	cargo build --release --workspace
	mkdir -p go/bin
	cd go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/patch-diff-mcp ./cmd/patch-diff-mcp
	cd go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/scope-guard-mcp ./cmd/scope-guard-mcp
	cd go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/attack-surface-mcp ./cmd/attack-surface-mcp

fetch:
	./target/release/nexus-sync fetch

seed-kev:
	./target/release/nexus-sync seed-kev

serve:
	./target/release/nexus-sync serve --host 127.0.0.1 --port 8088

scan:
	./target/release/nexus-sync scan --path .

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
