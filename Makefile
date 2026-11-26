.PHONY: install build fetch doctor seed-kev serve scan mcp-config ui test lint up down

install:
	./scripts/install.sh

build:
	cargo build --release --locked --workspace
	mkdir -p go/bin
	cd go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/patch-diff-mcp ./cmd/patch-diff-mcp
	cd go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/scope-guard-mcp ./cmd/scope-guard-mcp
	cd go && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/attack-surface-mcp ./cmd/attack-surface-mcp

fetch:
	./target/release/nexus-sync fetch

doctor:
	./target/release/nexus-sync doctor

seed-kev:
	./target/release/nexus-sync seed-kev

serve:
	./target/release/nexus-sync serve --host 127.0.0.1 --port 8088

scan:
	./target/release/nexus-sync scan --path .

mcp-config:
	./target/release/nexus-sync init-mcp --client claude

ui:
	./scripts/build-artex-ui.sh

test:
	cargo test --workspace --locked
	cd go && go test -race -v ./...

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings
	cd go && go vet ./...

up:
	docker compose up -d --build

down:
	docker compose down
