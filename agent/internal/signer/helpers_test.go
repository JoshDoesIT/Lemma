package signer

import "os"

// Tiny stdlib wrappers so the main test file doesn't need the path/os
// imports inline (keeps the parity oracle visible at the top).
func writeFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

func mkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}
