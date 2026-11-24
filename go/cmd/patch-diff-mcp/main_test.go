package main

import (
	"net"
	"testing"
)

func TestResolveSafePatchEndpointHardening(t *testing.T) {
	u, accept, err := resolveSafePatchEndpoint("https://github.com/org/repo/commit/deadbeef1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u != "https://api.github.com/repos/org/repo/commits/deadbeef1234" || accept != "application/vnd.github.diff" {
		t.Fatalf("unexpected rewrite: %s (%s)", u, accept)
	}

	blockedCases := []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://evil.example.com/commit/1234567",
		"https://user:pass@github.com/org/repo/commit/deadbeef",
		"https://github.com/org/repo/raw/main/secret.txt",
		"http://github.com/org/repo/commit/deadbeef",
	}
	for _, tc := range blockedCases {
		if _, _, err := resolveSafePatchEndpoint(tc); err == nil {
			t.Fatalf("expected URL to be blocked: %s", tc)
		}
	}
}

func TestIsBlockedIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.5", "100.64.0.1", "::1", "fe80::1"} {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("expected IP %s to be blocked", s)
		}
	}
	if isBlockedIP(net.ParseIP("140.82.114.4")) {
		t.Fatalf("expected public GitHub IP to be allowed")
	}
}

func TestExtractDiffHunks(t *testing.T) {
	diff := `diff --git a/auth/check.go b/auth/check.go
@@ -10,3 +10,5 @@ func check(p string)
- if strings.HasPrefix(p, "/admin") {
+ clean := filepath.Clean(p)
+ if strings.HasPrefix(clean, "/admin") && verifyAuthToken() {`
	res := extractDiffHunks(diff)
	if res["files_changed"].(int) != 1 {
		t.Fatalf("expected 1 changed file, got %v", res["files_changed"])
	}
	sigs := res["security_signals"].([]securitySignal)
	if len(sigs) == 0 {
		t.Fatalf("expected security signal on verifyAuthToken")
	}
}
