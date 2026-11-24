package pathguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfined(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "ok.yaml")
	outside := filepath.Join(tmp, "secret.yaml")
	if err := os.WriteFile(inside, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveConfined(root, "ok.yaml", false); err != nil {
		t.Fatalf("expected relative path inside root to pass: %v", err)
	}
	if _, err := ResolveConfined(root, inside, false); err == nil {
		t.Fatal("expected absolute path to be rejected when allowAbsInside=false")
	}
	if _, err := ResolveConfined(root, inside, true); err != nil {
		t.Fatalf("expected absolute path inside root to pass when allowAbsInside=true: %v", err)
	}
	if _, err := ResolveConfined(root, "../secret.yaml", true); err == nil {
		t.Fatal("expected relative traversal outside root to fail")
	}
	if _, err := ResolveConfined(root, outside, true); err == nil {
		t.Fatal("expected absolute path outside root to fail")
	}
}
