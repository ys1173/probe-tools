//go:build !unix

package sshcfg

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// storeProtected is false: this build has none of fs_unix.go's protections (no-follow opens relative to a checked
// directory, owner and mode checks, a file lock), so PlatformError refuses SSH device commands, and the probe's
// configuration and the `probe ssh` commands refuse to use the store. The code below only keeps the package building.
const storeProtected = false

// storeDir is a directory of the store. Without openat this platform checks paths with Lstat before using them; the
// probe is built and supported for Linux, where fs_unix.go applies.
type storeDir struct{ path string }

func (d *storeDir) close() {}

func (d *storeDir) join(name string) string { return filepath.Join(d.path, name) }

func (s *Store) openDir(create bool) (*storeDir, error) {
	return openSubdir(s.dir, create)
}

func (d *storeDir) sub(name string, create bool) (*storeDir, error) {
	return openSubdir(d.join(name), create)
}

func openSubdir(path string, create bool) (*storeDir, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("creating %s: %w", path, err)
		}
		fi, err = os.Lstat(path)
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is a symbolic link or not a directory; refusing to use it", path)
	}
	return &storeDir{path: path}, nil
}

func (d *storeDir) read(name string) ([]byte, error) {
	path := d.join(name)
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file; refusing to use it", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > maxStoreFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxStoreFile)
	}
	return b, nil
}

func (d *storeDir) write(name string, data []byte) error {
	tmp := d.join(tempName(name))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("writing %s: %w", d.join(name), err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, d.join(name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (d *storeDir) remove(name string) error { return os.Remove(d.join(name)) }

func (d *storeDir) names() ([]string, error) {
	ents, err := os.ReadDir(d.path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out, nil
}

// lock relies on writeMu: there is no file lock on this platform.
func (d *storeDir) lock() (func(), error) { return func() {}, nil }
