#!/usr/bin/env bash
set -euo pipefail
TARGET_OS="${1:-linux}"
TARGET_ARCH="${2:-amd64}"
RAW_OUTPUT="${3:-./dist/artex-nexus-server}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "$RAW_OUTPUT" = /* ]]; then
  OUTPUT="$RAW_OUTPUT"
else
  OUTPUT="$REPO_ROOT/${RAW_OUTPUT#./}"
fi

ARTEX_DIR="$REPO_ROOT/vendor/ARTEX"
OVERLAY_SRC="$REPO_ROOT/ui-overlay/src"
WEB_DIR="$ARTEX_DIR/web"
DIST_DIR="$ARTEX_DIR/server/webui/dist"

cleanup() {
  git -C "$ARTEX_DIR" checkout -- web/src/config/app-config.ts web/src/navigation/sidebar/sidebar-items.ts 2>/dev/null || true
  rm -rf "$WEB_DIR/src/app/(main)/nexus"
  git -C "$ARTEX_DIR" clean -fd server/webui/dist 2>/dev/null || true
  git -C "$ARTEX_DIR" checkout -- server/webui/dist 2>/dev/null || true
}
trap cleanup EXIT

cp -R "$OVERLAY_SRC"/* "$WEB_DIR/src/"
(
  cd "$WEB_DIR"
  [ -d node_modules ] || npm ci --ignore-scripts
  NEXT_EXPORT=1 NEXT_TELEMETRY_DISABLED=1 npx next build
)
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"
cp -R "$WEB_DIR/out/"* "$DIST_DIR/"
mkdir -p "$(dirname "$OUTPUT")"
(
  cd "$ARTEX_DIR"
  GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" CGO_ENABLED=0 go build -tags embedui -trimpath -o "$OUTPUT" ./cmd/artex
)
echo "[+] Built ARTEX-Nexus UI-embedded binary: $OUTPUT"
