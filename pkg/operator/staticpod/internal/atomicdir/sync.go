package atomicdir

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/klog/v2"
)

// Sync can be used to atomically synchronize target directory with the given file content map.
// This is done by populating a temporary directory, then atomically swapping it with the target directory.
// This effectively means that any extra files in the target directory are pruned.
//
// The first return value indicates whether the state has been synchronized.
// This can be the case even though an error is returned since that can be related to cleaning up.
func Sync(targetDir string, files map[string][]byte, filePerm os.FileMode) error {
	return sync(&realFS, targetDir, files, filePerm)
}

type fileSystem struct {
	MkdirAll        func(path string, perm os.FileMode) error
	MkdirTemp       func(dir, pattern string) (string, error)
	RemoveAll       func(path string) error
	WriteFile       func(name string, data []byte, perm os.FileMode) error
	SwapDirectories func(dirA, dirB string) error
}

var realFS = fileSystem{
	MkdirAll:        os.MkdirAll,
	MkdirTemp:       os.MkdirTemp,
	RemoveAll:       os.RemoveAll,
	WriteFile:       os.WriteFile,
	SwapDirectories: swap,
}

// sync prepares a tmp directory and writes all files into that directory.
// Then it atomically swap the tmp directory for the target one.
// This is currently implemented as really atomically swapping directories.
//
// The same goal of atomic swap could be implemented using symlinks much like AtomicWriter does in
// https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/volume/util/atomic_writer.go#L58
// The reason we don't do that is that we already have a directory populated and watched that needs to we swapped.
// In other words, it's for compatibility reasons. And if we were to migrate to the symlink approach,
// we would anyway need to atomically turn the current data directory into a symlink.
// This would all just increase complexity and require atomic swap on the OS level anyway.
func sync(fs *fileSystem, targetDir string, files map[string][]byte, filePerm os.FileMode) (retErr error) {
	klog.Infof("Ensuring content directory %q exists ...", targetDir)
	if err := fs.MkdirAll(targetDir, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed creating content directory: %w", err)
	}

	klog.Infof("Creating temporary directory to swap for %q ...", targetDir)
	tmpDir, err := fs.MkdirTemp(filepath.Dir(targetDir), filepath.Base(targetDir)+"-*")
	if err != nil {
		return fmt.Errorf("failed creating temporary directory: %w", err)
	}
	defer func() {
		if err := fs.RemoveAll(tmpDir); err != nil {
			if retErr != nil {
				retErr = fmt.Errorf("failed removing temporary directory %q: %w; previous error: %w", tmpDir, err, retErr)
			}
			retErr = fmt.Errorf("failed removing temporary directory %q: %w", tmpDir, err)
		}
	}()

	for filename, content := range files {
		fullFilename := filepath.Join(tmpDir, filename)
		klog.Infof("Writing file %q ...", fullFilename)

		if err := fs.WriteFile(fullFilename, content, filePerm); err != nil {
			return fmt.Errorf("failed writing %q: %w", fullFilename, err)
		}
	}

	klog.Infof("Atomically swapping target directory %q with temporary directory %q ...", targetDir, tmpDir)
	if err := fs.SwapDirectories(targetDir, tmpDir); err != nil {
		return fmt.Errorf("failed swapping target directory %q with temporary directory %q: %w", targetDir, tmpDir, err)
	}
	return
}
