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

func TestFileExists_Exists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	exists, err := fsx.FileExists(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected file to exist")
	}
}

func TestFileExists_NotExists(t *testing.T) {
	exists, err := fsx.FileExists("/nonexistent/path/file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected file to not exist")
	}
}

func TestFileExists_PermissionDenied_Generic(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test: running as root")
	}

	t.Setenv("SNAP", "")
	t.Setenv("SNAP_NAME", "")
	t.Setenv("SNAP_USER_DATA", "")

	dir := t.TempDir()
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatalf("failed to chmod dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	path := filepath.Join(dir, "file.txt")
	_, err := fsx.FileExists(path)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, fsx.ErrPermission) {
		t.Errorf("expected ErrPermission, got: %v", err)
	}
}

func TestFileExists_PermissionDenied_Snap(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test: running as root")
	}

	t.Setenv("SNAP", "/snap/myapp/current")
	t.Setenv("SNAP_NAME", "myapp")
	t.Setenv("SNAP_USER_DATA", "")

	dir := t.TempDir()
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatalf("failed to chmod dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	path := filepath.Join(dir, "file.txt")
	_, err := fsx.FileExists(path)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, fsx.ErrSnapPermission) {
		t.Errorf("expected ErrSnapPermission, got: %v", err)
	}
}

func TestWriteFile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := fsx.WriteFile(path, []byte("world"), 0600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read back file: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("expected %q, got %q", "world", string(data))
	}
}

func TestWriteFile_PermissionDenied_Generic(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test: running as root")
	}

	t.Setenv("SNAP", "")
	t.Setenv("SNAP_NAME", "")
	t.Setenv("SNAP_USER_DATA", "")

	dir := t.TempDir()
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatalf("failed to chmod dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	path := filepath.Join(dir, "out.txt")
	err := fsx.WriteFile(path, []byte("data"), 0600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, fsx.ErrPermission) {
		t.Errorf("expected ErrPermission, got: %v", err)
	}
}

func TestWriteFile_PermissionDenied_Snap(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test: running as root")
	}

	t.Setenv("SNAP", "/snap/myapp/current")
	t.Setenv("SNAP_NAME", "myapp")
	t.Setenv("SNAP_USER_DATA", "")

	dir := t.TempDir()
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatalf("failed to chmod dir: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	path := filepath.Join(dir, "out.txt")
	err := fsx.WriteFile(path, []byte("data"), 0600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, fsx.ErrSnapPermission) {
		t.Errorf("expected ErrSnapPermission, got: %v", err)
	}
}
