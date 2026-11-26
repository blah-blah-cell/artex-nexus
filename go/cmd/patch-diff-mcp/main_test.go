package main

import (
	"net"
	"testing"
)

func TestResolveSafePatchEndpointHardening(t *testing.T) {
	u, accept, isGH, err := resolveSafePatchEndpoint("https://github.com/org/repo/commit/deadbeef1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isGH || u != "https://api.github.com/repos/org/repo/commits/deadbeef1234" || accept != "application/vnd.github.diff" {
		t.Fatalf("unexpected rewrite: %s (%s, isGH=%v)", u, accept, isGH)
	}

	// A GitLab repo whose path contains "github.com" must NOT set isGitHub=true.
	glURL, glAccept, glIsGH, err := resolveSafePatchEndpoint("https://gitlab.com/org/github.com/-/commit/deadbeef1234")
	if err != nil {
		t.Fatalf("unexpected gitlab error: %v", err)
	}
	if glIsGH || glURL != "https://gitlab.com/org/github.com/-/commit/deadbeef1234.diff" || glAccept != "text/plain" {
		t.Fatalf("unexpected gitlab result: %s (%s, isGH=%v)", glURL, glAccept, glIsGH)
	}

	apiURL, _, apiIsGH, err := resolveSafePatchEndpoint("https://api.github.com/repos/org/repo/pulls/42")
	if err != nil || !apiIsGH || apiURL != "https://api.github.com/repos/org/repo/pulls/42" {
		t.Fatalf("expected valid api.github.com pull URL, got %s (isGH=%v, err=%v)", apiURL, apiIsGH, err)
	}

	blockedCases := []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://evil.example.com/commit/1234567",
		"https://user:pass@github.com/org/repo/commit/deadbeef",
		"https://github.com/org/repo/raw/main/secret.txt",
		"http://github.com/org/repo/commit/deadbeef",
		"https://api.github.com/repos/../../user",
		"https://api.github.com/repos/org/repo/issues/1",
		"https://gitlab.com/org/../../etc/-/commit/deadbeef",
		"https://github.com/octocat/repo%3Ffoo=bar/commit/deadbeef1",
		"https://gitlab.com/api/v4/projects%3Fmembership=true/-/commit/deadbeef1",
	}
	for _, tc := range blockedCases {
		if _, _, _, err := resolveSafePatchEndpoint(tc); err == nil {
			t.Fatalf("expected URL to be blocked: %s", tc)
		}
	}
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.5",
		"100.64.0.1", "::1", "fe80::1",
		"64:ff9b::127.0.0.1", "2002:7f00:1::1", "198.18.0.1",
		"192.0.0.1", "240.0.0.1", "255.255.255.255",
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Fatalf("expected IP %s to be blocked", s)
		}
	}
	if isBlockedIP(net.ParseIP("140.82.114.4")) {
		t.Fatalf("expected public GitHub IP to be allowed")
	}
}

func TestExtractDiffHunksSpacesAndPrefixOperators(t *testing.T) {
	diff := `diff --git a/my dir/auth check.sql b/my dir/auth check.sql
--- a/my dir/auth check.sql
+++ b/my dir/auth check.sql
@@ -10,3 +10,5 @@
--- old SQL comment removed
+++count
+clean := filepath.Clean(p)
+if verifyAuthToken(tok) {
+author := "bob"
`
	res := extractDiffHunks(diff)
	if res["files_changed"].(int) != 1 {
		t.Fatalf("expected 1 changed file, got %v", res["files_changed"])
	}
	files := res["files"].([]fileDiffSummary)
	if files[0].File != "my dir/auth check.sql" {
		t.Fatalf("filename with spaces broken: %q", files[0].File)
	}
	// Removed SQL comment (---) and added ++count (+++) inside hunk must be counted!
	if files[0].Removed != 1 || files[0].Added != 4 {
		t.Fatalf("expected 1 removed and 4 added lines, got removed=%d added=%d", files[0].Removed, files[0].Added)
	}
	sigs := res["security_signals"].([]securitySignal)
	if len(sigs) != 2 {
		t.Fatalf("expected exactly 2 security signals (filepath.Clean + verifyAuthToken), not noisy 'author': got %+v", sigs)
	}
}
