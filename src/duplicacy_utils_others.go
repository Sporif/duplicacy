// Copyright (c) Acrosync LLC. All rights reserved.
// Free for personal use and commercial trial
// Commercial use requires per-user licenses available from https://duplicacy.com

// +build !windows

package duplicacy

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/pkg/xattr"
	"golang.org/x/sys/unix"
)

const (
	FS_IOC_GETFLAGS uintptr = 0x80086601
	FS_IOC_SETFLAGS uintptr = 0x40086602
)

func Readlink(path string) (isRegular bool, s string, err error) {
	s, err = os.Readlink(path)
	return false, s, err
}

func GetOwner(entry *Entry, fileInfo *os.FileInfo) {
	stat, ok := (*fileInfo).Sys().(*syscall.Stat_t)
	if ok && stat != nil {
		entry.UID = int(stat.Uid)
		entry.GID = int(stat.Gid)
	} else {
		entry.UID = -1
		entry.GID = -1
	}
}

func SetOwner(fullPath string, entry *Entry, fileInfo *os.FileInfo) bool {
	stat, ok := (*fileInfo).Sys().(*syscall.Stat_t)
	if ok && stat != nil && (int(stat.Uid) != entry.UID || int(stat.Gid) != entry.GID) {
		if entry.UID != -1 && entry.GID != -1 {
			err := os.Lchown(fullPath, entry.UID, entry.GID)
			if err != nil {
				LOG_ERROR("RESTORE_CHOWN", "Failed to change uid or gid: %v", err)
				return false
			}
		}
	}

	return true
}

func Chtimes(name string, mtime int64, isLink bool) error {
	if !isLink {
		t := time.Unix(0, mtime)
		return os.Chtimes(name, t, t)
	} else {
		t := unix.NsecToTimeval(mtime)
		tv := []unix.Timeval{t, t}
		return unix.Lutimes(name, tv)
	}
}

func ioctl(f *os.File, request uintptr, attrp *int32) error {
	argp := uintptr(unsafe.Pointer(attrp))
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request, argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func GetAttr(f *os.File) int32 {
	attr := int32(-1)
	ioctl(f, FS_IOC_GETFLAGS, &attr)
	return attr
}

func SetAttr(f *os.File, attr int32) {
	ioctl(f, FS_IOC_SETFLAGS, &attr)
}

func (entry *Entry) ReadFileAttribute(top string) {
	file, _ := os.Open(filepath.Join(top, entry.Path))
	defer file.Close()
	entry.FileAttribute = GetAttr(file)
}

func (entry *Entry) SetFileAttributesToFile(fullPath string) {
	file, err := os.Open(fullPath)
	defer file.Close()
	if err != nil {
		LOG_ERROR("RESTORE_FILE_ATTR", "Failed to open file %s: %v", entry.Path, err)
	}
	SetAttr(file, entry.FileAttribute)
}

func (entry *Entry) ReadAttributes(top string) {

	fullPath := filepath.Join(top, entry.Path)
	attributes, _ := xattr.List(fullPath)
	if len(attributes) > 0 {
		entry.Attributes = make(map[string][]byte)
		for _, name := range attributes {
			attribute, err := xattr.Get(fullPath, name)
			if err == nil {
				entry.Attributes[name] = attribute
			}
		}
	}
}

func (entry *Entry) SetAttributesToFile(fullPath string) {
	names, _ := xattr.List(fullPath)

	for _, name := range names {

		newAttribute, found := entry.Attributes[name]
		if found {
			oldAttribute, _ := xattr.Get(fullPath, name)
			if !bytes.Equal(oldAttribute, newAttribute) {
				xattr.Set(fullPath, name, newAttribute)
			}
			delete(entry.Attributes, name)
		} else {
			xattr.Remove(fullPath, name)
		}
	}

	for name, attribute := range entry.Attributes {
		xattr.Set(fullPath, name, attribute)
	}

}

func joinPath(components ...string) string {
	return path.Join(components...)
}

func SplitDir(fullPath string) (dir string, file string) {
	return path.Split(fullPath)
}
