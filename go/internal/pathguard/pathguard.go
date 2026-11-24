package pathguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveConfined resolves target inside rootDir, chasing symlinks on both ends
// so neither ".." traversal nor a symlink pointing outside rootDir can escape.
// When allowAbsInside is false, absolute user paths are rejected upfront.
func ResolveConfined(rootDir, target string, allowAbsInside bool) (string, error) {
	cleaned := strings.TrimSpace(target)
	if cleaned == "" {
		return "", errors.New("path is required")
	}
	if !allowAbsInside && filepath.IsAbs(cleaned) {
		return "", errors.New("absolute paths are not allowed here; pass a path relative to the configured root")
	}

	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		return "", fmt.Errorf("resolve root %q: %w", rootDir, err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("root directory %q is unavailable: %w", rootDir, err)
	}

	candidate := cleaned
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(rootReal, candidate)
	}
	candReal, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", errors.New("path not found or outside configured root directory")
	}

	rel, err := filepath.Rel(rootReal, candReal)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", errors.New("path not found or outside configured root directory")
	}
	return candReal, nil
}
