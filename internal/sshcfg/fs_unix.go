//go:build unix

package sshcfg

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// storeProtected says this build has the store's protections: no-follow opens relative to a checked directory, owner
// and mode checks, and a file lock.
const storeProtected = true

// storeDir is a directory of the store (ssh/ or ssh/keys/), opened without following a symbolic link and checked:
// a real directory, owned by this process's user, with no access for group or others. Every file in it is opened
// relative to that descriptor, again without following a symbolic link, so a link planted in the store (or a store
// directory swapped for one) is refused rather than followed.
type storeDir struct {
	fd   int
	path string
}

func (d *storeDir) close() { unix.Close(d.fd) }

func (d *storeDir) join(name string) string { return filepath.Join(d.path, name) }

// openDir opens <state_dir>/ssh. With create it makes the directory (0700) when it is missing; without, a missing
// directory is fs.ErrNotExist. It refuses when this process is root and the state directory belongs to another user:
// root must not work inside a directory that user controls.
func (s *Store) openDir(create bool) (*storeDir, error) {
	sfd, err := unix.Open(s.stateDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: s.stateDir, Err: err}
	}
	defer unix.Close(sfd)
	var st unix.Stat_t
	if err := unix.Fstat(sfd, &st); err != nil {
		return nil, &fs.PathError{Op: "stat", Path: s.stateDir, Err: err}
	}
	if geteuid() == 0 && st.Uid != 0 {
		return nil, foreignOwnerError(s.stateDir, int(st.Uid))
	}
	return openSubdir(sfd, s.dir, dirName, create)
}

// sub opens a directory inside d, with the same checks.
func (d *storeDir) sub(name string, create bool) (*storeDir, error) {
	return openSubdir(d.fd, d.join(name), name, create)
}

func openSubdir(parent int, path, name string, create bool) (*storeDir, error) {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(parent, name, flags, 0)
	created := false
	if errors.Is(err, unix.ENOENT) && create {
		if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("creating %s: %w", path, err)
		}
		created = true
		fd, err = unix.Openat(parent, name, flags, 0)
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return nil, fmt.Errorf("%s is a symbolic link or not a directory; refusing to use it", path)
	}
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	d := &storeDir{fd: fd, path: path}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		d.close()
		return nil, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		d.close()
		return nil, fmt.Errorf("%s is not a directory; refusing to use it", path)
	}
	if err := checkOwner(path, int(st.Uid)); err != nil {
		d.close()
		return nil, err
	}
	if created {
		if err := unix.Fchmod(fd, 0o700); err != nil {
			d.close()
			return nil, &fs.PathError{Op: "chmod", Path: path, Err: err}
		}
	} else if perm := st.Mode & 0o777; perm&0o077 != 0 {
		d.close()
		return nil, fmt.Errorf("%s is open to other users (mode %04o); run chmod 700 on it", path, perm)
	}
	return d, nil
}

// checkFile refuses anything but a regular file owned by this user with no access for group or others.
func checkFile(path string, fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not a regular file; refusing to use it", path)
	}
	if err := checkOwner(path, int(st.Uid)); err != nil {
		return err
	}
	if perm := st.Mode & 0o777; perm&0o077 != 0 {
		return fmt.Errorf("%s is open to other users (mode %04o); run chmod 600 on it", path, perm)
	}
	return nil
}

func openErr(path string, err error) error {
	if errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("%s is a symbolic link; refusing to follow it", path)
	}
	return &fs.PathError{Op: "open", Path: path, Err: err}
}

// read returns the contents of the file name in d. A missing file is fs.ErrNotExist.
func (d *storeDir) read(name string) ([]byte, error) {
	path := d.join(name)
	// O_NONBLOCK: a FIFO planted under a store name must not hang the reader; checkFile refuses it.
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, openErr(path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if err := checkFile(path, fd); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStoreFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxStoreFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxStoreFile)
	}
	return b, nil
}

// write replaces the file name in d atomically: a new file (O_EXCL, never through a link) in the same directory,
// then a rename over the old name, which replaces a link rather than following it.
func (d *storeDir) write(name string, data []byte) error {
	path := d.join(name)
	tmp := tempName(name)
	fd, err := unix.Openat(d.fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, openErr(d.join(tmp), err))
	}
	f := os.NewFile(uintptr(fd), d.join(tmp))
	ok := false
	defer func() {
		if !ok {
			f.Close()
			unix.Unlinkat(d.fd, tmp, 0)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(d.fd, tmp, d.fd, name); err != nil {
		unix.Unlinkat(d.fd, tmp, 0)
		ok = true
		return fmt.Errorf("writing %s: %w", path, err)
	}
	ok = true
	return nil
}

// remove deletes the file name in d (a link is removed, not followed). A missing file is fs.ErrNotExist.
func (d *storeDir) remove(name string) error {
	if err := unix.Unlinkat(d.fd, name, 0); err != nil {
		return &fs.PathError{Op: "remove", Path: d.join(name), Err: err}
	}
	return nil
}

// names lists d's entries.
func (d *storeDir) names() ([]string, error) {
	nfd, err := unix.Dup(d.fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(nfd), d.path)
	defer f.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return f.Readdirnames(-1)
}

// lock opens (creating it if needed) and locks the store's lock file, and returns the function that releases it.
func (d *storeDir) lock() (func(), error) {
	path := d.join(lockFile)
	fd, err := unix.Openat(d.fd, lockFile, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the SSH store's lock: %w", openErr(path, err))
	}
	f := os.NewFile(uintptr(fd), path)
	if err := checkFile(path, fd); err != nil {
		f.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("locking the SSH store: %w", err)
	}
	return func() {
		unix.Flock(fd, unix.LOCK_UN)
		f.Close()
	}, nil
}
