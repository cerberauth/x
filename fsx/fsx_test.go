package fsx_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/x/fsx"
)

func TestReadFile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	data, err := fsx.ReadFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("expected %q, got %q", "hello", string(data))
	}
}

func TestReadFile_NotFound(t *testing.T) {
	_, err := fsx.ReadFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, fsx.ErrPermission) || errors.Is(err, fsx.ErrSnapPermission) {
		t.Errorf("expected a not-found error, got permission error: %v", err)
	}
}

func TestReadFile_PermissionDenied_Generic(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test: running as root")
	}

	t.Setenv("SNAP", "")
	t.Setenv("SNAP_NAME", "")
	t.Setenv("SNAP_USER_DATA", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "noaccess.txt")
	if err := os.WriteFile(path, []byte("secret"), 0000); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, err := fsx.ReadFile(path)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, fsx.ErrPermission) {
		t.Errorf("expected ErrPermission, got: %v", err)
	}
}

func TestReadFile_PermissionDenied_Snap(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test: running as root")
	}

	t.Setenv("SNAP", "/snap/myapp/current")
	t.Setenv("SNAP_NAME", "myapp")
	t.Setenv("SNAP_USER_DATA", "")

	dir := t.TempDir()
	path := filepath.Join(dir, "noaccess.txt")
	if err := os.WriteFile(path, []byte("secret"), 0000); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, err := fsx.ReadFile(path)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, fsx.ErrSnapPermission) {
		t.Errorf("expected ErrSnapPermission, got: %v", err)
	}
}
