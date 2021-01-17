// Copyright (c) Acrosync LLC. All rights reserved.
// Free for personal use and commercial trial
// Commercial use requires per-user licenses available from https://duplicacy.com
package duplicacy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/karrick/godirwalk"
)

// This is the hidden directory in the repository for storing various files.
var DUPLICACY_DIRECTORY = ".duplicacy"
var DUPLICACY_FILE = ".duplicacy"

// Mask for file permission bits
var fileModeMask = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// Regex for matching 'StartChunk:StartOffset:EndChunk:EndOffset'
var contentRegex = regexp.MustCompile(`^([0-9]+):([0-9]+):([0-9]+):([0-9]+)`)

// Entry encapsulates information about a file or directory.
type Entry struct {
	Path string
	Size int64
	Time int64
	Mode uint32
	Link string
	Hash string
	Pass int

	UID int
	GID int

	StartChunk  int
	StartOffset int
	EndChunk    int
	EndOffset   int

	FileAttribute int32
	Attributes    map[string][]byte
}

// CreateEntry creates an entry from file properties.
func CreateEntry(path string, size int64, time int64, mode uint32) *Entry {

	if len(path) > 0 && path[len(path)-1] != '/' && (mode&uint32(os.ModeDir)) != 0 {
		path += "/"
	}

	return &Entry{
		Path: path,
		Size: size,
		Time: time,
		Mode: mode,

		UID: -1,
		GID: -1,
	}

}

// CreateEntryFromFileInfo creates an entry from a 'FileInfo' object.
func CreateEntryFromFileInfo(fileInfo os.FileInfo, directory string) *Entry {
	path := directory + fileInfo.Name()

	mode := fileInfo.Mode()

	if mode&os.ModeDir != 0 && mode&os.ModeSymlink != 0 {
		mode ^= os.ModeDir
	}

	if path[len(path)-1] != '/' && mode&os.ModeDir != 0 {
		path += "/"
	}

	entry := &Entry{
		Path: path,
		Size: fileInfo.Size(),
		Time: fileInfo.ModTime().Unix(),
		Mode: uint32(mode),
	}

	GetOwner(entry, &fileInfo)

	return entry
}

// CreateEntryFromJSON creates an entry from a json description.
func (entry *Entry) UnmarshalJSON(description []byte) (err error) {

	var object map[string]interface{}

	err = json.Unmarshal(description, &object)
	if err != nil {
		return err
	}

	var value interface{}
	var ok bool

	if value, ok = object["name"]; ok {
		pathInBase64, ok := value.(string)
		if !ok {
			return fmt.Errorf("Name is not a string for a file in the snapshot")
		}
		path, err := base64.StdEncoding.DecodeString(pathInBase64)
		if err != nil {
			return fmt.Errorf("Invalid name '%s' in the snapshot", pathInBase64)
		}
		entry.Path = string(path)
	} else if value, ok = object["path"]; !ok {
		return fmt.Errorf("Path is not specified for a file in the snapshot")
	} else if entry.Path, ok = value.(string); !ok {
		return fmt.Errorf("Path is not a string for a file in the snapshot")
	}

	if value, ok = object["size"]; !ok {
		return fmt.Errorf("Size is not specified for file '%s' in the snapshot", entry.Path)
	} else if _, ok = value.(float64); !ok {
		return fmt.Errorf("Size is not a valid integer for file '%s' in the snapshot", entry.Path)
	}
	entry.Size = int64(value.(float64))

	if value, ok = object["time"]; !ok {
		return fmt.Errorf("Time is not specified for file '%s' in the snapshot", entry.Path)
	} else if _, ok = value.(float64); !ok {
		return fmt.Errorf("Time is not a valid integer for file '%s' in the snapshot", entry.Path)
	}
	entry.Time = int64(value.(float64))

	if value, ok = object["mode"]; !ok {
		return fmt.Errorf("float64 is not specified for file '%s' in the snapshot", entry.Path)
	} else if _, ok = value.(float64); !ok {
		return fmt.Errorf("Mode is not a valid integer for file '%s' in the snapshot", entry.Path)
	}
	entry.Mode = uint32(value.(float64))

	if value, ok = object["hash"]; !ok {
		return fmt.Errorf("Hash is not specified for file '%s' in the snapshot", entry.Path)
	} else if entry.Hash, ok = value.(string); !ok {
		return fmt.Errorf("Hash is not a string for file '%s' in the snapshot", entry.Path)
	}

	if value, ok = object["link"]; ok {
		var link string
		if link, ok = value.(string); !ok {
			return fmt.Errorf("Symlink is not a valid string for file '%s' in the snapshot", entry.Path)
		}
		entry.Link = link
	}

	entry.UID = -1
	if value, ok = object["uid"]; ok {
		if _, ok = value.(float64); ok {
			entry.UID = int(value.(float64))
		}
	}

	entry.GID = -1
	if value, ok = object["gid"]; ok {
		if _, ok = value.(float64); ok {
			entry.GID = int(value.(float64))
		}
	}

	entry.FileAttribute = 0
	if value, ok = object["fileattribute"]; ok {
		if _, ok = value.(float64); ok {
			entry.FileAttribute = int32(value.(float64))
		}
	}

	if value, ok = object["attributes"]; ok {
		if attributes, ok := value.(map[string]interface{}); !ok {
			return fmt.Errorf("Attributes are invalid for file '%s' in the snapshot", entry.Path)
		} else {
			entry.Attributes = make(map[string][]byte)
			for name, object := range attributes {
				if object == nil {
					entry.Attributes[name] = []byte("")
				} else if attributeInBase64, ok := object.(string); !ok {
					return fmt.Errorf("Attribute '%s' is invalid for file '%s' in the snapshot", name, entry.Path)
				} else if attribute, err := base64.StdEncoding.DecodeString(attributeInBase64); err != nil {
					return fmt.Errorf("Failed to decode attribute '%s' for file '%s' in the snapshot: %v",
						name, entry.Path, err)
				} else {
					entry.Attributes[name] = attribute
				}
			}
		}
	}

	if entry.IsFile() && entry.Size > 0 {
		if value, ok = object["content"]; !ok {
			return fmt.Errorf("Content is not specified for file '%s' in the snapshot", entry.Path)
		}

		if content, ok := value.(string); !ok {
			return fmt.Errorf("Content is invalid for file '%s' in the snapshot", entry.Path)
		} else {

			matched := contentRegex.FindStringSubmatch(content)
			if matched == nil {
				return fmt.Errorf("Content is specified in a wrong format for file '%s' in the snapshot", entry.Path)
			}

			entry.StartChunk, _ = strconv.Atoi(matched[1])
			entry.StartOffset, _ = strconv.Atoi(matched[2])
			entry.EndChunk, _ = strconv.Atoi(matched[3])
			entry.EndOffset, _ = strconv.Atoi(matched[4])
		}
	}

	return nil

}

func (entry *Entry) convertToObject(encodeName bool) map[string]interface{} {

	object := make(map[string]interface{})

	if encodeName {
		object["name"] = base64.StdEncoding.EncodeToString([]byte(entry.Path))
	} else {
		object["path"] = entry.Path
	}
	object["size"] = entry.Size
	object["time"] = entry.Time
	object["mode"] = entry.Mode
	object["hash"] = entry.Hash

	if entry.IsLink() {
		object["link"] = entry.Link
	}

	if entry.IsFile() && entry.Size > 0 {
		object["content"] = fmt.Sprintf("%d:%d:%d:%d",
			entry.StartChunk, entry.StartOffset, entry.EndChunk, entry.EndOffset)
	}

	if entry.UID != -1 && entry.GID != -1 {
		object["uid"] = entry.UID
		object["gid"] = entry.GID
	}

	if entry.FileAttribute > 0 {
		object["fileattribute"] = entry.FileAttribute
	}

	if len(entry.Attributes) > 0 {
		object["attributes"] = entry.Attributes
	}

	return object
}

// MarshalJSON returns the json description of an entry.
func (entry *Entry) MarshalJSON() ([]byte, error) {

	object := entry.convertToObject(true)
	description, err := json.Marshal(object)
	return description, err
}

func (entry *Entry) IsFile() bool {
	return entry.Mode&uint32(os.ModeType) == 0
}

func (entry *Entry) IsDir() bool {
	return entry.Mode&uint32(os.ModeDir) != 0
}

func (entry *Entry) IsLink() bool {
	return entry.Mode&uint32(os.ModeSymlink) != 0
}

func (entry *Entry) GetPermissions() os.FileMode {
	return os.FileMode(entry.Mode) & fileModeMask
}

func (entry *Entry) IsSameAs(other *Entry) bool {
	return entry.Size == other.Size && entry.Time <= other.Time+1 && entry.Time >= other.Time-1
}

func (entry *Entry) IsSameAsFileInfo(other os.FileInfo) bool {
	time := other.ModTime().Unix()
	return entry.Size == other.Size() && entry.Time <= time+1 && entry.Time >= time-1
}

func (entry *Entry) String(maxSizeDigits int) string {
	modifiedTime := time.Unix(entry.Time, 0).Format("2006-01-02 15:04:05")
	return fmt.Sprintf("%*d %s %64s %s", maxSizeDigits, entry.Size, modifiedTime, entry.Hash, entry.Path)
}

func (entry *Entry) RestoreMetadata(fullPath string, fileInfo *os.FileInfo, setOwner bool) bool {

	if fileInfo == nil {
		stat, err := os.Lstat(fullPath)
		fileInfo = &stat
		if err != nil {
			LOG_ERROR("RESTORE_STAT", "Failed to retrieve the file info: %v", err)
			return false
		}
	}

	// Note that chown can remove setuid/setgid bits so should be called before chmod
	if setOwner {
		if !SetOwner(fullPath, entry, fileInfo) {
			return false
		}
	}

	// Only set the permission if the file is not a symlink
	if !entry.IsLink() && (*fileInfo).Mode()&fileModeMask != entry.GetPermissions() {
		err := os.Chmod(fullPath, entry.GetPermissions())
		if err != nil {
			LOG_ERROR("RESTORE_CHMOD", "Failed to set the file permissions: %v", err)
			return false
		}
	}

	if (*fileInfo).ModTime().UnixNano() != entry.Time {
		err := Chtimes(fullPath, entry.Time, entry.IsLink())
		if err != nil {
			LOG_ERROR("RESTORE_CHTIME", "Failed to set the modification time: %v", err)
			return false
		}
	}

	if entry.FileAttribute > 0 {
		entry.SetFileAttributesToFile(fullPath)
	}

	if len(entry.Attributes) > 0 {
		entry.SetAttributesToFile(fullPath)
	}

	return true
}

// Return -1 if 'left' should appear before 'right', 1 if opposite, and 0 if they are the same.
// Files are always arranged before subdirectories under the same parent directory.
func (left *Entry) Compare(right *Entry) int {

	path1 := left.Path
	path2 := right.Path

	p := 0
	for ; p < len(path1) && p < len(path2); p++ {
		if path1[p] != path2[p] {
			break
		}
	}

	// c1, c2 is the first byte that differs
	var c1, c2 byte
	if p < len(path1) {
		c1 = path1[p]
	}
	if p < len(path2) {
		c2 = path2[p]
	}

	// c3, c4 indicates how the current component ends
	// c3 == '/':  the current component is a directory
	// c3 != '/':  the current component is the last one
	c3 := c1
	for i := p; c3 != '/' && i < len(path1); i++ {
		c3 = path1[i]
	}

	c4 := c2
	for i := p; c4 != '/' && i < len(path2); i++ {
		c4 = path2[i]
	}

	if c3 == '/' {
		if c4 == '/' {
			// We are comparing two directory components
			if c1 == '/' {
				// left is shorter
				// Note that c2 maybe smaller than c1 but c1 is '/' which is counted
				// as 0
				return -1
			} else if c2 == '/' {
				// right is shorter
				return 1
			} else {
				return int(c1) - int(c2)
			}
		} else {
			return 1
		}
	} else {
		// We're at the last component of left and left is a file
		if c4 == '/' {
			// the current component of right is a directory
			return -1
		} else {
			return int(c1) - int(c2)
		}
	}
}

// This is used to sort entries by their names.
type ByName []*Entry

func (entries ByName) Len() int      { return len(entries) }
func (entries ByName) Swap(i, j int) { entries[i], entries[j] = entries[j], entries[i] }
func (entries ByName) Less(i, j int) bool {
	return entries[i].Compare(entries[j]) < 0
}

// This is used to sort entries by their starting chunks (and starting offsets if the starting chunks are the same).
type ByChunk []*Entry

func (entries ByChunk) Len() int      { return len(entries) }
func (entries ByChunk) Swap(i, j int) { entries[i], entries[j] = entries[j], entries[i] }
func (entries ByChunk) Less(i, j int) bool {
	return entries[i].StartChunk < entries[j].StartChunk ||
		(entries[i].StartChunk == entries[j].StartChunk && entries[i].StartOffset < entries[j].StartOffset)
}

// This is used to sort FileInfo objects.
type FileInfoCompare []os.FileInfo

func (files FileInfoCompare) Len() int      { return len(files) }
func (files FileInfoCompare) Swap(i, j int) { files[i], files[j] = files[j], files[i] }
func (files FileInfoCompare) Less(i, j int) bool {

	left := files[i]
	right := files[j]

	if left.IsDir() && left.Mode()&os.ModeSymlink == 0 {
		if right.IsDir() && right.Mode()&os.ModeSymlink == 0 {
			return left.Name() < right.Name()
		} else {
			return false
		}
	} else {
		if right.IsDir() && right.Mode()&os.ModeSymlink == 0 {
			return true
		} else {
			return left.Name() < right.Name()
		}
	}
}

// ListEntries returns a list of entries representing files and subdirectories under the directory 'top' (recursively).  Entry paths
// are normalized as relative to 'top'.  'patterns' are used to exclude or include certain files.
func ListEntries(top string, patterns []string, nobackupFile string, attributeThreshold int, excludeByAttribute bool, backupFileAttributes bool) (entries []*Entry, skippedDirectories []string, skippedFiles []string, discardAttributes bool, err error) {

	LOG_DEBUG("LIST_ENTRIES", "Listing %s", top)

	pathSeparator := string(os.PathSeparator)
	normalizedTop := top
	if normalizedTop != "" && !strings.HasSuffix(normalizedTop, pathSeparator) {
		normalizedTop += pathSeparator
	}

	var discardAttributesInt int32
	var (
		entriesMu, skippedDirMu, skippedFileMu sync.Mutex
	)

	type Name struct {
		fullPath       string
		relPath        string
		isDir          bool
		readAttributes bool
		attributes     map[string][]byte
	}
	namesCh := make(chan Name, runtime.NumCPU()*16)

	matchPath := func(path string) bool {
		if len(patterns) > 0 && !MatchPath(path, patterns) {
			return false
		}
		return true
	}

	// Get path relative to top, appending '/' if directory
	getRelPath := func(path string, isDir bool) (relPath string) {
		if path != "" {
			relPath = filepath.ToSlash(strings.TrimPrefix(path, normalizedTop))
			if isDir && relPath != "" && !strings.HasSuffix(relPath, "/") {
				relPath += "/"
			}
		}
		return
	}

	handleSkipped := func(skipped Name) {
		if skipped.isDir {
			skippedDirMu.Lock()
			defer skippedDirMu.Unlock()
			skippedDirectories = append(skippedFiles, skipped.relPath)
		} else {
			skippedFileMu.Lock()
			defer skippedFileMu.Unlock()
			skippedFiles = append(skippedFiles, skipped.relPath)
		}
	}

	// Turn a Path and Dirent into Name and send to namesCh
	processDirent := func(osPathname string, de *godirwalk.Dirent, firstLevelSymDir bool) error {
		isDir := (de.IsDir() && !de.IsSymlink()) || firstLevelSymDir
		relPath := getRelPath(osPathname, isDir)
		name := Name{fullPath: osPathname, relPath: relPath, isDir: isDir}

		if !matchPath(relPath) {
			return godirwalk.SkipThis
		}

		if isDir && nobackupFile != "" {
			files, dirError := godirwalk.ReadDirnames(osPathname, nil)
			if dirError != nil {
				LOG_WARN("LIST_FAILURE", "Failed to list subdirectory %s: %v", relPath, dirError)
				handleSkipped(name)
				return godirwalk.SkipThis
			}
			sort.Strings(files)
			ii := sort.Search(len(files), func(ii int) bool { return strings.Compare(files[ii], nobackupFile) >= 0 })
			if ii < len(files) && files[ii] == nobackupFile {
				LOG_DEBUG("LIST_NOBACKUP", "%s is excluded due to nobackup file", relPath)
				return godirwalk.SkipThis
			}
		}

		if isDir && atomic.LoadInt32(&discardAttributesInt) != 1 {
			name.attributes = GetXattr(osPathname)
			name.readAttributes = true

			if excludeByAttribute && excludedByAttribute(name.attributes) {
				LOG_DEBUG("LIST_EXCLUDE", "%s is excluded by attribute", relPath)
				return godirwalk.SkipThis
			}
		}

		namesCh <- name
		return nil
	}

	// Turn a Name into an Entry and append to entries
	processName := func(name Name) {
		lstat, lstatErr := os.Lstat(name.fullPath)

		switch {
		case os.IsNotExist(lstatErr):
			return // Path was removed after walking - ignore.
		case lstatErr != nil:
			LOG_WARN("LIST_FAILURE", "Failed to Lstat path: %s, %v", name.relPath, lstatErr)
			handleSkipped(name)
			return
		case lstat.Mode()&(os.ModeNamedPipe|os.ModeSocket|os.ModeDevice) != 0:
			LOG_DEBUG("LIST_SKIP", "Skipped non-regular file: %s", name.relPath)
			handleSkipped(name)
			return
		}

		entry := CreateEntryFromFileInfo(lstat, "")
		entry.Path = name.relPath

		if entry.IsLink() {
			isRegular := false
			var linkErr error
			isRegular, entry.Link, linkErr = Readlink(name.fullPath)
			if linkErr != nil {
				LOG_WARN("LIST_LINK", "Failed to read the symlink %s: %v", entry.Path, linkErr)
				handleSkipped(name)
				return
			}

			if isRegular {
				entry.Mode ^= uint32(os.ModeSymlink)
			} else if name.isDir {
				stat, statErr := os.Stat(name.fullPath)
				if statErr != nil {
					LOG_WARN("LIST_LINK", "Failed to stat the symlink: %v", statErr)
					handleSkipped(name)
					return
				}

				newEntry := CreateEntryFromFileInfo(stat, "")
				newEntry.Path = entry.Path
				entry = newEntry
			}
		}

		if !entry.IsLink() && backupFileAttributes {
			entry.ReadFileAttribute(top)
		}

		if atomic.LoadInt32(&discardAttributesInt) != 1 {
			if name.readAttributes {
				entry.Attributes = name.attributes
			} else {
				entry.ReadAttributes(top)
			}

			if excludeByAttribute && excludedByAttribute(entry.Attributes) {
				LOG_DEBUG("LIST_EXCLUDE", "%s is excluded by attribute", entry.Path)
				return
			}
		}

		entriesMu.Lock()
		defer entriesMu.Unlock()
		if !discardAttributes && len(entries) > attributeThreshold {
			LOG_INFO("LIST_ATTRIBUTES", "Discarding file attributes")
			atomic.StoreInt32(&discardAttributesInt, 1)
			discardAttributes = true
			for _, file := range entries {
				file.Attributes = nil
			}
			entry.Attributes = nil
		}
		entries = append(entries, entry)
	}

	var topWG sync.WaitGroup
	var processTop func(path string, subDe *godirwalk.Dirent) error
	pathsCh := make(chan string, runtime.NumCPU()*16)

	// Process root of top level directory
	processTop = func(path string, subDe *godirwalk.Dirent) error {
		defer topWG.Done()
		if subDe != nil {
			subErr := processDirent(path, subDe, true)
			if subErr != nil {
				return subErr
			}
			if !strings.HasSuffix(path, pathSeparator) {
				path += pathSeparator
			}
		}

		dirents, readErr := godirwalk.ReadDirents(path, nil)
		if readErr != nil {
			if path != normalizedTop {
				LOG_WARN("LIST_FAILURE", "Failed to list subdirectory %s: %v", subDe.Name()+"/", readErr)
				handleSkipped(Name{fullPath: path, relPath: subDe.Name() + "/", isDir: true})
			}
			return readErr
		}

		for _, de := range dirents {
			fullPath := path + de.Name()

			if fullPath == normalizedTop+DUPLICACY_DIRECTORY {
				continue
			}

			var relPath string
			isDir := de.IsDir()
			isSymlink := de.IsSymlink()

			isSymlinkDir := false
			// Check if it's a symlink to an absolute target outside top
			if isSymlink && path == normalizedTop {
				relPath = getRelPath(fullPath, false)
				name := Name{fullPath: fullPath, relPath: relPath}
				isRegular, link, linkErr := Readlink(fullPath)
				if linkErr != nil {
					LOG_WARN("LIST_LINK", "Failed to read the symlink %s: %v", relPath, linkErr)
					handleSkipped(name)
					continue
				}

				linkIsDir := false
				stat, statErr := os.Stat(fullPath)
				if statErr != nil {
					LOG_WARN("LIST_LINK", "Failed to stat the symlink %s: %v", relPath, statErr)
				} else {
					linkIsDir = stat.IsDir()
				}
				isSymlinkDir = !isRegular && linkIsDir && (filepath.IsAbs(link) || filepath.HasPrefix(link, `\\`)) && !strings.HasPrefix(link, normalizedTop)
			}

			isRegular := de.IsRegular() || (isSymlink && (!isSymlinkDir || !isDir))

			if isDir && !isSymlinkDir {
				pathsCh <- fullPath
			} else if isSymlinkDir {
				topWG.Add(1)
				go processTop(fullPath, de)
			} else {
				relPath = getRelPath(fullPath, false)
				if !matchPath(relPath) {
					continue
				}
				name := Name{fullPath: fullPath, relPath: relPath}

				if isRegular {
					namesCh <- name
				} else {
					LOG_DEBUG("LIST_SKIP", "Skipped non-regular file: %s", name.relPath)
					handleSkipped(name)
					continue
				}
			}
		}

		return nil
	}

	go func() {
		topWG.Add(1)
		err = processTop(normalizedTop, nil)
		topWG.Wait()
		close(pathsCh)
	}()

	numWorkers := runtime.NumCPU()
	var walkersWG sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		walkersWG.Add(1)

		go func() {
			defer walkersWG.Done()

			for path := range pathsCh {
				godirwalk.Walk(path, &godirwalk.Options{
					Unsorted: false,
					Callback: func(osPathname string, de *godirwalk.Dirent) error {
						return processDirent(osPathname, de, false)
					},
					ErrorCallback: func(osPathname string, oSerr error) godirwalk.ErrorAction {
						// Assume it's a directory
						relPath := getRelPath(osPathname, true)
						LOG_WARN("LIST_FAILURE", "Failed to list subdirectory: %s, %v", relPath, oSerr)
						handleSkipped(Name{fullPath: osPathname, relPath: relPath, isDir: true})
						return godirwalk.SkipNode
					},
				})
			}
		}()
	}
	go func() {
		walkersWG.Wait()
		close(namesCh)
	}()

	var workersWG sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for name := range namesCh {
				processName(name)
			}
		}()
	}
	workersWG.Wait()

	sort.Sort(ByName(entries))

	return entries, skippedDirectories, skippedFiles, discardAttributes, err
}

// Diff returns how many bytes remain unmodifiled between two files.
func (entry *Entry) Diff(chunkHashes []string, chunkLengths []int,
	otherHashes []string, otherLengths []int) (modifiedLength int64) {

	var offset1, offset2 int64
	i1 := entry.StartChunk
	i2 := 0
	for i1 <= entry.EndChunk && i2 < len(otherHashes) {

		start := 0
		if i1 == entry.StartChunk {
			start = entry.StartOffset
		}
		end := chunkLengths[i1]
		if i1 == entry.EndChunk {
			end = entry.EndOffset
		}

		if offset1 < offset2 {
			modifiedLength += int64(end - start)
			offset1 += int64(end - start)
			i1++
		} else if offset1 > offset2 {
			offset2 += int64(otherLengths[i2])
			i2++
		} else {
			if chunkHashes[i1] == otherHashes[i2] && end-start == otherLengths[i2] {
			} else {
				modifiedLength += int64(chunkLengths[i1])
			}
			offset1 += int64(end - start)
			offset2 += int64(otherLengths[i2])
			i1++
			i2++
		}
	}

	return modifiedLength
}
