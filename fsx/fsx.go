package fsx

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var ErrSnapPermission = errors.New("permission denied: this binary was installed via snap which restricts filesystem access; please install using a different method (e.g. direct binary, docker, or package manager)")

var ErrPermission = errors.New("permission denied: the process does not have access to read this file")

func isSnapProcess() bool {
	return os.Getenv("SNAP") != "" || os.Getenv("SNAP_NAME") != "" || strings.HasPrefix(os.Getenv("SNAP_USER_DATA"), "/home/")
}

func ReadFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return data, nil
	}

	if errors.Is(err, os.ErrPermission) {
		if isSnapProcess() {
			return nil, fmt.Errorf("%w: %s", ErrSnapPermission, path)
		}

		return nil, fmt.Errorf("%w: %s", ErrPermission, path)
	}

	return nil, err
}
