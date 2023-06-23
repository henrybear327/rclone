package protondrive

/*
TODO:
	- address all integration issues
		- (azim) put: NewObject init, uploading issues, etc.
	- check mega, amazoncloud, (etc.) to see if the implementation of the code is making sense
	- write the documentation
	- address all FIXME
	- Size() is reported after the size after encryption: solution: add an option to signal it's in the integration mode -> decrypt before returning the size
	- ModTime difference is too big because of encryption -> precision is now 10s

TODO: optimization
	- linkID to link node caching
	- remove e.g. proton.link exposure
	- utilize pacer (although proton-go-api reacts to 429, we would probably not want to trigger that)

Notes:
	- objects are files
	- directories are folders
	- root is ""
	- f.root is the absolute path from root,
	- dir/remote/etc. is the relative path from f.root
	- FindDir operates on relative path
	- for ProtonDrive apis, the path being operated should always be full path (fs.root + remote)
	- we will use the encoder by default to deal with invalid utf8

Not yet implemented but on the roadmap (most likely V2 from the bridging library):
	- 2Password mode
	- Thumbnail support
	- Optimized download and upload
	- Move, DirMove
	- UserInfo
	- Disconnect

Not implemented:
- type Directory interface
*/

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"path"
	"strings"
	"time"

	protonDriveAPI "github.com/henrybear327/Proton-API-Bridge"
	"github.com/henrybear327/go-proton-api"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
)

const (
	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2 // bigger for slower decay, exponential
)

var (
	ErrMissingLinkObject               = errors.New("link object must not be nil")
	ErrCanNotUploadFileWithUnknownSize = errors.New("proton Drive can't upload files with unknown size")
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "protondrive",
		Description: "Proton Drive",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "username",
			Help:     "Username",
			Required: true,
		}, {
			Name:       "password",
			Help:       "Password",
			Required:   true,
			IsPassword: true,
		}, {
			Name:     "2fa",
			Help:     "2FA code (if the account requires one)",
			Required: false,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			// Encode invalid UTF-8 bytes as json doesn't handle them properly.
			Default: (encoder.Base |
				encoder.EncodeInvalidUtf8),
		}, {
			Name:     "reportorginalsize",
			Help:     "The default size returned will be the size on the proton drive (after encryption), but for unit / integration tests, we need to obtain the original content size. Set to true, will return the original content size, but, it will have performance and network implications, since decryption will be performed",
			Advanced: true,
			Default:  false,
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	Username string `config:"username"`
	Password string `config:"password"`
	TwoFA    string `config:"2fa"`
	// advance
	Enc                encoder.MultiEncoder `config:"encoding"`
	ReportOriginalSize bool                 `config:"reportorginalsize"`
}

// Fs represents a remote proton drive
type Fs struct {
	name        string                      // name of this remote
	root        string                      // the path we are working on. Notice that for ProtonDrive, it's attached under rootLink (usually /root)
	opt         Options                     // parsed config options
	ci          *fs.ConfigInfo              // global config
	features    *fs.Features                // optional features
	pacer       *fs.Pacer                   // pacer for API calls
	dirCache    *dircache.DirCache          // Map of directory path to directory id
	protonDrive *protonDriveAPI.ProtonDrive // the Proton API bridging library
}

// Object describes an object
type Object struct {
	fs           *Fs       // what this object is part of
	remote       string    // The remote path (relative to the fs.root)
	size         int64     // size of the object (on server, after encryption)
	originalSize *int64    // size of the object (after decryption)
	modTime      time.Time // modification time of the object
	createdTime  time.Time
	id           string // ID of the object
	data         []byte // decrypted file byte array
	mimetype     string // mimetype of the file
	// TODO: cache the link
}

//------------------------------------------------------------------------------

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("proton drive root link ID '%s'", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}
	if opt.Password != "" {
		var err error
		opt.Password, err = obscure.Reveal(opt.Password)
		if err != nil {
			return nil, fmt.Errorf("couldn't decrypt password: %w", err)
		}
	}

	ci := fs.GetConfig(ctx)

	root = strings.Trim(root, "/")

	f := &Fs{
		name:  name,
		root:  root,
		opt:   *opt,
		ci:    ci,
		pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}

	f.features = (&fs.Features{
		ReadMimeType:            true,
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	config := protonDriveAPI.NewDefaultConfig()
	config.FirstLoginCredential.Username = opt.Username
	config.FirstLoginCredential.Password = opt.Password
	config.FirstLoginCredential.TwoFA = opt.TwoFA
	protonDrive, err := protonDriveAPI.NewProtonDrive(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize a new proton drive instance: %w", err)
	}
	f.protonDrive = protonDrive

	root = strings.Trim(root, "/")
	f.dirCache = dircache.New(
		root,                         /* root folder path */
		protonDrive.MainShare.LinkID, /* real root ID is the root folder, since we can't go past this folder */
		f,
	)
	err = f.dirCache.FindRoot(ctx, false)
	if err != nil {
		log.Println("FindRoot err", err)
		if err != fs.ErrorDirNotFound {
			return nil, fmt.Errorf("couldn't initialize a new root remote: %w", err)
		}

		// TODO: assume this is a file path (check code from box.go)
	}

	return f, nil
}

//------------------------------------------------------------------------------

// CleanUp deletes all files currently in trash
func (f *Fs) CleanUp(ctx context.Context) error {
	return f.protonDrive.EmptyTrash(ctx)
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
// TODO: implement me properly
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	leaf, folderLinkID, err := f.dirCache.FindPath(ctx, remote, false)
	if err != nil {
		if err == fs.ErrorDirNotFound {
			return nil, fs.ErrorObjectNotFound
		}
		return nil, err
	}

	link, err := f.protonDrive.SearchByNameInFolderByID(ctx, folderLinkID, f.opt.Enc.FromStandardName(leaf), true, false)
	if err != nil {
		if strings.Contains(err.Error(), "(Code=2501, Status=422)") {
			return nil, fs.ErrorObjectNotFound
		}
		return nil, err
	}
	if link == nil {
		return nil, fs.ErrorObjectNotFound
	}

	o := &Object{
		fs:           f,
		remote:       remote,
		size:         link.Size,
		originalSize: nil,
		id:           link.LinkID,
		data:         nil,
		mimetype:     link.MIMEType,
		modTime:      time.Unix(link.ModifyTime, 0),
	}

	return o, nil
}

func (o *Object) setMetaData(link *proton.Link) error {
	o.id = link.LinkID
	o.size = link.Size
	o.modTime = time.Unix(link.ModifyTime, 0)
	o.createdTime = time.Unix(link.CreateTime, 0)
	o.data = nil
	o.mimetype = link.MIMEType

	return nil
}

// Return an Object from a path
//
// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, link *proton.Link) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
	}

	var err error
	if link != nil {
		err = o.setMetaData(link) // Set info
	} else {
		return nil, ErrMissingLinkObject
	}
	if err != nil {
		return nil, err
	}

	return o, nil
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	folderLinkID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return nil, err
	}

	foldersAndFiles, err := f.protonDrive.ListDirectory(ctx, folderLinkID)
	if err != nil {
		return nil, err
	}

	entries := make(fs.DirEntries, 0)
	for i := range foldersAndFiles {
		remote := path.Join(dir, f.opt.Enc.ToStandardName(foldersAndFiles[i].Name))

		if foldersAndFiles[i].IsFolder {
			d := fs.NewDir(remote, time.Unix(foldersAndFiles[i].Link.ModifyTime, 0)).SetID(foldersAndFiles[i].Link.LinkID)
			entries = append(entries, d)
		} else {
			obj, err := f.newObjectWithInfo(ctx, remote, foldersAndFiles[i].Link)
			if err != nil {
				return nil, err
			}
			entries = append(entries, obj)
		}
	}

	return entries, nil
}

// DirCacher describes an interface for doing the low level directory work
//
// This should be implemented by the backend and will be called by the
// dircache package when appropriate.
// FindLeaf finds a directory of name leaf in the folder with ID pathID
func (f *Fs) FindLeaf(ctx context.Context, pathID, leaf string) (string, bool, error) {
	link, err := f.protonDrive.SearchByNameInFolderByID(ctx, pathID, f.opt.Enc.FromStandardName(leaf), false, true)
	if err != nil {
		return "", false, err
	}
	if link == nil {
		return "", false, nil
	}

	return link.LinkID, true, nil
}

// CreateDir makes a directory with pathID as parent and name leaf
func (f *Fs) CreateDir(ctx context.Context, pathID, leaf string) (newID string, err error) {
	return f.protonDrive.CreateNewFolderByID(ctx, pathID, f.opt.Enc.FromStandardName(leaf))
}

// Put in to the remote path with the modTime given of the given size
//
// When called from outside an Fs by rclone, src.Size() will always be >= 0.
// But for unknown-sized objects (indicated by src.Size() == -1), Put should either
// return an error or upload it properly (rather than e.g. calling panic).
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
// TODO: implement me properly
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	size := src.Size()
	if size < 0 {
		return nil, ErrCanNotUploadFileWithUnknownSize
	}

	existingObj, err := f.NewObject(ctx, src.Remote())
	switch err {
	case nil:
		return existingObj, existingObj.Update(ctx, in, src, options...)
	case fs.ErrorObjectNotFound:
		// Not found so create it
		return f.PutUnchecked(ctx, in, src)
	default:
		return nil, err
	}
}

// Creates from the parameters passed in a half finished Object which
// must have setMetaData called on it
//
// # The parent folders will be checked, if missing, created upon traversal check
//
// Used to create new objects
func (f *Fs) createObject(ctx context.Context, remote string, modTime time.Time, size int64) (*Object, error) {
	//                 ˇ-------ˇ filename
	// e.g. /root/a/b/c/test.txt
	//      ^~~~~~~~~~~^ dirPath
	// dirPath, _ /* filename: not used, as we care about only the parent folders */ := path.Split(remote)

	_, _, err := f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return nil, err
	}

	// Temporary Object under construction
	obj := &Object{
		fs:           f,
		remote:       remote,
		size:         size,
		originalSize: nil,
		id:           "",
		modTime:      modTime,
		data:         nil,
		mimetype:     "",
	}
	return obj, nil
}

// Put in to the remote path with the modTime given of the given size
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
//
// May create duplicates or return errors if src already
// exists.
func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()
	size := src.Size()
	modTime := src.ModTime(ctx)

	obj, err := f.createObject(ctx, remote, modTime, size)
	if err != nil {
		return nil, err
	}
	return obj, obj.Update(ctx, in, src, options...)
}

// Mkdir makes the directory (container, bucket)
//
// Shouldn't return an error if it already exists
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	_, err := f.dirCache.FindDir(ctx, dir, true)
	return err
}

// Rmdir removes the directory (container, bucket) if empty
//
// Return an error if it doesn't exist or isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	folderLinkID, err := f.dirCache.FindDir(ctx, dir, false)
	if err == fs.ErrorDirNotFound {
		return fmt.Errorf("[Rmdir] cannot find LinkID for dir %s", dir)
	} else if err != nil {
		return err
	}

	err = f.protonDrive.MoveFolderToTrashByID(ctx, folderLinkID, true)
	if err != nil {
		return err
	}

	f.dirCache.FlushDir(dir)
	return nil
}

// Precision of the ModTimes in this Fs
func (f *Fs) Precision() time.Duration {
	return fs.ModTimeNotSupported
	// return time.Second * 10 // FIXME
}

// DirCacheFlush an optional interface to flush internal directory cache
// DirCacheFlush resets the directory cache - used in testing
// as an optional interface
func (f *Fs) DirCacheFlush() {
	f.dirCache.ResetRoot()
}

// Returns the supported hash types of the filesystem
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.None)
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	user, err := f.protonDrive.About(ctx)
	if err != nil {
		return nil, err
	}

	total := int64(user.MaxSpace)
	used := int64(user.UsedSpace)
	free := total - used

	usage := &fs.Usage{
		Total: &total,
		Used:  &used,
		Free:  &free,
	}

	return usage, nil
}

// ------------------------------------------------------------

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the hashes of an object
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	if o.fs.opt.ReportOriginalSize {
		// This option is for unit / integration test only
		// DO NOT USE IN PRODUCTION
		if o.originalSize != nil {
			return *o.originalSize
		}

		_, err := o.Open(context.Background(), nil)
		if err != nil {
			log.Fatalln("Size Open err", err)
		}

		if o.originalSize != nil {
			return *o.originalSize
		}
	}
	return o.size
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

// Storable returns a boolean showing whether this object storable
func (o *Object) Storable() bool {
	return true
}

// Open opens the file for read.  Call Close() on the returned io.ReadCloser
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	data, err := o.fs.protonDrive.DownloadFileByID(ctx, o.id)
	if err != nil {
		return nil, err
	}
	o.data = data
	originalSize := int64(len(o.data))
	o.originalSize = &originalSize

	return io.NopCloser(bytes.NewReader(o.data)), nil
}

// Update in to the object with the modTime given of the given size
//
// When called from outside an Fs by rclone, src.Size() will always be >= 0.
// But for unknown-sized objects (indicated by src.Size() == -1), Upload should either
// return an error or update the object properly (rather than e.g. calling panic).
// TODO: implement me properly
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	size := src.Size()
	if size < 0 {
		return ErrCanNotUploadFileWithUnknownSize
	}

	remote := o.Remote()
	leaf, folderLinkID, err := o.fs.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return fmt.Errorf("update make parent dir failed: %w", err)
	}

	modTime := src.ModTime(ctx)
	link, originalSize, err := o.fs.protonDrive.UploadFileByReader(ctx, folderLinkID, o.fs.opt.Enc.FromStandardName(leaf), modTime, in)
	if err != nil {
		return err
	}
	o.originalSize = &originalSize

	// FIXME: verify upload (by looking at the size?)

	return o.setMetaData(link)
}

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	return o.fs.protonDrive.MoveFileToTrashByID(ctx, o.id)
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	return o.id
}

// Purge all files in the directory specified
//
// Implement this if you have a way of deleting all the files
// quicker than just running Remove() on the result of List()
//
// Return an error if it doesn't exist
func (f *Fs) Purge(ctx context.Context, dir string) error {
	folderLinkID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return err
	}

	err = f.protonDrive.MoveFolderToTrashByID(ctx, folderLinkID, false)
	if err != nil {
		return err
	}

	f.dirCache.FlushDir(dir)
	return nil
}

// MimeType of an Object if known, "" otherwise
func (o *Object) MimeType(ctx context.Context) string {
	return o.mimetype
}

// Move src to this remote using server-side move operations.
//
// # This is stored with the remote path given
//
// # It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantMove
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	return nil, fs.ErrorCantMove
}

// DirMove moves src, srcRemote to this remote at dstRemote
// using server-side move operations.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantDirMove
//
// If destination exists then return fs.ErrorDirExists
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	return fs.ErrorCantDirMove
}

// Check the interfaces are satisfied
var (
	_ fs.Fs             = (*Fs)(nil)
	_ fs.PutUncheckeder = (*Fs)(nil)
	// _ fs.Mover           = (*Fs)(nil)
	// _ fs.DirMover        = (*Fs)(nil)
	_ fs.DirCacheFlusher = (*Fs)(nil)
	_ fs.Abouter         = (*Fs)(nil)
	_ fs.Object          = (*Object)(nil)
	_ fs.MimeTyper       = (*Object)(nil)
	_ fs.IDer            = (*Object)(nil)
)
