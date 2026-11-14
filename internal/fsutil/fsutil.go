// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 fuzzfw contributors

// Package fsutil contains deterministic JSON, hashing, path, and file helpers.
package fsutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// CanonicalJSON serializes a value with sorted map keys and no HTML escaping.
// Go's encoding/json sorts string map keys, which makes this stable across runs.
func CanonicalJSON(value any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	return []byte(out), nil
}

// PrettyJSON returns deterministic indented JSON with a trailing newline.
func PrettyJSON(value any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// WriteJSON atomically writes canonical or pretty JSON.
func WriteJSON(path string, value any, pretty bool) error {
	var (
		data []byte
		err  error
	)
	if pretty {
		data, err = PrettyJSON(value)
	} else {
		data, err = CanonicalJSON(value)
		if err == nil {
			data = append(data, '\n')
		}
	}
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, data, 0o644)
}

// ReadJSON reads and decodes a JSON file.
func ReadJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// WriteFileAtomic writes via a temp file in the same directory and renames it.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// HashBytes returns a lowercase SHA-256 hex digest.
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HashString hashes UTF-8 text.
func HashString(text string) string { return HashBytes([]byte(text)) }

// HashFile hashes a file's bytes.
func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// HashJSON hashes canonical JSON.
func HashJSON(value any) (string, error) {
	data, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return HashBytes(data), nil
}

// HashFiles hashes a set of files by relative name and content.
func HashFiles(root string, paths []string) (string, error) {
	hash := sha256.New()
	sorted := append([]string(nil), paths...)
	sortStrings(sorted)
	for _, path := range sorted {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		fileHash, err := HashFile(path)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, rel+"\x00"+fileHash+"\n")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Resolve returns an absolute, cleaned path relative to base when needed.
func Resolve(base, value string) string {
	value = os.ExpandEnv(value)
	if strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			value = filepath.Join(home, value[2:])
		}
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(base, value)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return filepath.Clean(value)
	}
	return filepath.Clean(abs)
}

// Rel returns a project-relative slash path when possible.
func Rel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// Within reports whether path is inside root.
func Within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

// SafeName converts a target/symbol into a safe file name component.
func SafeName(value, fallback string) string {
	cleaned := strings.Trim(unsafeName.ReplaceAllString(value, "_"), "._-")
	if cleaned == "" {
		return fallback
	}
	return cleaned
}

// EnsureDir creates a directory tree.
func EnsureDir(path string) error { return os.MkdirAll(path, 0o755) }

// Exists reports whether a path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// CopyFile copies a file preserving mode.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
