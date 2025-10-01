//go:build linux

package atomicdir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSync(t *testing.T) {
	newRealFS := func() *fileSystem {
		fs := realFS
		return &fs
	}

	type testCase struct {
		name string
		// newFS is the main mocking factory for the test run.
		newFS func() *fileSystem
		// existingFiles is used to populate the target directory state before testing.
		// An empty map will cause the directory to be created, a nil map will cause no directory to be created.
		existingFiles map[string][]byte
		// filesToSync will be synchronized into the target directory.
		filesToSync map[string][]byte
		// expectDirectorySynchronized set to true will check the target directory contains filesToSync only.
		// When unset, existingFiles are expected to be there.
		expectDirectorySynchronized bool
		// expectSyncError check the return value from Sync.
		expectSyncError bool
		// expectLingeringTemporaryDirectory can be set to true to expect the temporary directory not to be removed.
		expectLingeringTemporaryDirectory bool
	}

	errorTestCase := func(name string, newFS func() *fileSystem) testCase {
		return testCase{
			name:  name,
			newFS: newFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			expectSyncError: true,
		}
	}

	testCases := []testCase{
		{
			name:          "target directory does not exist",
			newFS:         newRealFS,
			existingFiles: nil,
			filesToSync: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:          "target directory is empty",
			newFS:         newRealFS,
			existingFiles: map[string][]byte{},
			filesToSync: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "target directory already synchronized",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "change file contents preserving the filenames",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"tls.crt": []byte("rotated TLS cert"),
				"tls.key": []byte("rotated TLS key"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "change filenames preserving the file contents",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"api.crt": []byte("TLS cert"),
				"api.key": []byte("TLS key"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "change filenames and file contents",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "replace a single file content",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("3"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "replace a single file",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync: map[string][]byte{
				"1.txt": []byte("1"),
				"3.txt": []byte("3"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "rename a single file",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync: map[string][]byte{
				"1.txt": []byte("1"),
				"3.txt": []byte("2"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "add new files",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"tls.crt":         []byte("TLS cert"),
				"tls.key":         []byte("TLS key"),
				"another_tls.crt": []byte("another TLS cert"),
				"another_tls.key": []byte("another TLS key"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "delete a single file",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync: map[string][]byte{
				"1.txt": []byte("1"),
			},
			expectDirectorySynchronized: true,
		},
		{
			name:  "delete all files",
			newFS: newRealFS,
			existingFiles: map[string][]byte{
				"1.txt": []byte("1"),
				"2.txt": []byte("2"),
			},
			filesToSync:                 map[string][]byte{},
			expectDirectorySynchronized: true,
		},
		errorTestCase("directory unchanged on failed to create object directory", func() *fileSystem {
			fs := newRealFS()
			fs.MkdirAll = func(path string, perm os.FileMode) error {
				return errors.New("nuked")
			}
			return fs
		}),
		errorTestCase("directory unchanged on failed to create temporary directory", func() *fileSystem {
			fs := newRealFS()
			fs.MkdirTemp = func(dir, pattern string) (string, error) {
				return "", errors.New("nuked")
			}
			return fs
		}),
		errorTestCase("directory unchanged on failed to write the first file", func() *fileSystem {
			fs := newRealFS()
			fs.WriteFile = failToWriteNth(fs.WriteFile, 0)
			return fs
		}),
		errorTestCase("directory unchanged on failed to write the second file", func() *fileSystem {
			fs := newRealFS()
			fs.WriteFile = failToWriteNth(fs.WriteFile, 1)
			return fs
		}),
		errorTestCase("directory unchanged on failed to swap directories", func() *fileSystem {
			fs := newRealFS()
			fs.SwapDirectories = func(dirA, dirB string) error {
				return errors.New("nuked")
			}
			return fs
		}),
		{
			name: "directory synchronized then failing to remove temporary directory",
			newFS: func() *fileSystem {
				fs := newRealFS()
				fs.RemoveAll = func(path string) error {
					return errors.New("nuked")
				}
				return fs
			},
			existingFiles: map[string][]byte{
				"tls.crt": []byte("TLS cert"),
				"tls.key": []byte("TLS key"),
			},
			filesToSync: map[string][]byte{
				"api.crt": []byte("rotated TLS cert"),
				"api.key": []byte("rotated TLS key"),
			},
			expectDirectorySynchronized:       true,
			expectSyncError:                   true,
			expectLingeringTemporaryDirectory: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Write the current directory contents.
			contentDir := filepath.Join(t.TempDir(), "secrets", "tls-cert")
			if tc.existingFiles != nil {
				if err := os.MkdirAll(contentDir, 0755); err != nil {
					t.Fatalf("Failed to create content directory %q: %v", contentDir, err)
				}

				for filename, content := range tc.existingFiles {
					targetPath := filepath.Join(contentDir, filename)
					if err := os.WriteFile(targetPath, content, 0600); err != nil {
						t.Fatalf("Failed to populate file %q: %v", targetPath, err)
					}
				}
			}

			// Replace with the object data.
			err := sync(tc.newFS(), contentDir, tc.filesToSync, 0600)

			// Check the resulting state.
			if tc.expectDirectorySynchronized {
				checkDirectoryContents(t, contentDir, tc.filesToSync, 0600)
			} else {
				checkDirectoryContents(t, contentDir, tc.existingFiles, 0600)
			}

			if (err != nil) != tc.expectSyncError {
				t.Errorf("Expected error from sync = %v, got %v", tc.expectSyncError, err)
			}

			if !tc.expectLingeringTemporaryDirectory {
				ensureParentDirectoryClean(t, contentDir)
			}
		})
	}
}

type writeFileFunc func(path string, data []byte, perm os.FileMode) error

func failToWriteNth(writeFile writeFileFunc, n int) writeFileFunc {
	var c int
	return func(path string, data []byte, perm os.FileMode) error {
		i := c
		c++
		if i == n {
			return errors.New("nuked")
		}
		return writeFile(path, data, perm)
	}
}

func checkDirectoryContents(t *testing.T, contentDir string, files map[string][]byte, filePerm os.FileMode) {
	// Ensure the content directory is in sync.
	entries, err := os.ReadDir(contentDir)
	if err != nil {
		t.Fatalf("Failed to read directory %q: %v", contentDir, err)
	}
	writtenData := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("Failed to read file information for %q: %v", entry.Name(), err)
		}
		if perm := info.Mode().Perm(); perm != filePerm {
			t.Errorf("Unexpected file permissions for %q: %v", entry.Name(), perm)
		}

		content, err := os.ReadFile(filepath.Join(contentDir, entry.Name()))
		if err != nil {
			t.Fatalf("Failed to read file %q: %v", entry.Name(), err)
		}
		writtenData[entry.Name()] = content
	}
	if !cmp.Equal(writtenData, files) {
		t.Errorf("Unexpected directory content:\n%s\n", cmp.Diff(files, writtenData))
	}
}

func ensureParentDirectoryClean(t *testing.T, contentDir string) {
	// Make sure there are no leftovers in the parent directory.
	parentDir := filepath.Dir(contentDir)
	parentEntries, err := os.ReadDir(parentDir)
	if err != nil {
		t.Fatalf("Failed to read directory %q: %v", parentDir, err)
	}
	if n := len(parentEntries); n != 1 {
		t.Errorf("Unexpected number of entries in directory %q: %d", parentDir, n)
		for _, entry := range parentEntries {
			t.Logf("Parent directory entry: %q", entry.Name())
		}
	}
}
