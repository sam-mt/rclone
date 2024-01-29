package kiteworks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/kiteworks/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/oauthutil"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/readers"
	"github.com/rclone/rclone/lib/rest"
	"golang.org/x/crypto/sha3"
	"golang.org/x/oauth2"
)

const (
	authorizaURLFmt = "https://%s/oauth/authorize"
	tokenURLFmt     = "https://%s/oauth/token"
	redirectURLFmt  = "https://%s/rest/callback.html"
	rootURLFmt      = "https://%s/"

	defaultScopes = "files/* folders/* uploads/* search/* users/Read"

	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2 // bigger for slower decay, exponential
)

var kiteworksHashType hash.Type

func getOauthConfig(m configmap.Mapper) *oauth2.Config {
	hostname, _ := m.Get("hostname")
	clientID, _ := m.Get("client_id")
	clientSecret, _ := m.Get("client_secret")
	scopes, _ := m.Get("access_scopes")

	return &oauth2.Config{
		Scopes: []string{scopes},
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf(authorizaURLFmt, hostname),
			TokenURL: fmt.Sprintf(tokenURLFmt, hostname),
		},
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  oauthutil.RedirectLocalhostURL,
	}
}

func init() {
	kiteworksHashType = hash.RegisterHash(api.HashName, strings.ToUpper(api.HashName), 64, sha3.New256)

	fs.Register(&fs.RegInfo{
		Name:        "kiteworks",
		Description: "Kiteworks",
		NewFs:       NewFs,
		Config: func(ctx context.Context, name string, m configmap.Mapper, config fs.ConfigIn) (*fs.ConfigOut, error) {
			return oauthutil.ConfigOut("", &oauthutil.Options{
				OAuth2Config: getOauthConfig(m),
				NoOffline:    true,
				OAuth2Opts: []oauth2.AuthCodeOption{
					oauth2.SetAuthURLParam("token_access_type", "offline"),
				},
			})
		},
		Options: fs.Options{
			{
				Name:      config.ConfigClientID,
				Help:      "OAuth Client Id",
				Required:  true,
				Sensitive: true,
			},
			{
				Name:      config.ConfigClientSecret,
				Help:      "OAuth Client Secret",
				Required:  true,
				Sensitive: true,
			},
			{
				Name:      "hostname",
				Help:      "Host name of Kiteworks account",
				Required:  true,
				Sensitive: false,
			},
			{
				Name:      "access_scopes",
				Help:      "Access scopes for application",
				Required:  false,
				Sensitive: false,
				Default:   defaultScopes,
			},
			{
				Name:     "hard_delete",
				Help:     "Delete files permanently",
				Advanced: true,
				Default:  false,
			},
			{
				Name:     "chunk_size",
				Help:     "Size for upload chunk",
				Advanced: true,
				Default:  fs.SizeSuffix(65_000_000_000),
			},
			{
				Name:     config.ConfigEncoding,
				Help:     config.ConfigEncodingHelp,
				Advanced: true,
				Default: encoder.Standard |
					encoder.EncodeBackSlash |
					encoder.EncodeLtGt |
					encoder.EncodeDoubleQuote |
					encoder.EncodeColon |
					encoder.EncodeQuestion |
					encoder.EncodeAsterisk |
					encoder.EncodePipe |
					encoder.EncodeBackSlash |
					// encoder.EncodeCrLf |
					// encoder.EncodeDel |
					// encoder.EncodeCtl |
					encoder.EncodeLeftPeriod |
					// encoder.EncodeLeftTilde |
					// encoder.EncodeLeftCrLfHtVt |
					encoder.EncodeRightPeriod |
					// encoder.EncodeRightCrLfHtVt |
					encoder.EncodeInvalidUtf8,
			},
		}})
}

// Options defines the configuration for Kiteworks backend
type Options struct {
	Hostname     string               `config:"hostname"`
	ClientID     string               `config:"client_id"`
	ClientSecret string               `config:"client_secret"`
	Scopes       string               `config:"access_scopes"`
	HardDelete   bool                 `config:"hard_delete"`
	ChunkSize    fs.SizeSuffix        `config:"chunk_size"`
	Enc          encoder.MultiEncoder `config:"encoding"`
}

// Fs represents remote Kiteworks fs
type Fs struct {
	name         string
	root         string
	description  string
	features     *fs.Features
	opt          Options
	ci           *fs.ConfigInfo
	srv          *rest.Client     // the connection to the kiteworks server
	pacer        *fs.Pacer        // pacer for API calls
	tokenRenewer *oauthutil.Renew // renew the token on expiry
	dirCache     *dircache.DirCache
}

// Object describes a quatrix object
type Object struct {
	fs          *Fs
	remote      string
	size        int64
	modTime     time.Time
	id          string
	hasMetaData bool
	obType      string
	sha256      string
}

// trimPath trims redundant slashes from kiteworks 'url'
func trimPath(path string) (root string) {
	root = strings.Trim(path, "/")
	return
}

// retryErrorCodes is a slice of error codes that we will retry
var retryErrorCodes = []int{
	429, // Too Many Requests.
	500, // Internal Server Error
	502, // Bad Gateway
	503, // Service Unavailable
	504, // Gateway Timeout
	509, // Bandwidth Limit Exceeded
}

// shouldRetry returns a boolean as to whether this resp and err
// deserve to be retried.  It returns the err as a convenience
func shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}

	return fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)

	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}
	root = trimPath(root)

	ci := fs.GetConfig(ctx)

	client, ts, err := oauthutil.NewClient(ctx, name, m, getOauthConfig(m))
	if err != nil {
		return nil, fmt.Errorf("failed to configure Kiteworks: %w", err)
	}

	f := &Fs{
		name:        name,
		description: "Kiteworks FS for account " + opt.Hostname,
		root:        root,
		opt:         *opt,
		ci:          ci,
		srv:         rest.NewClient(client).SetRoot(fmt.Sprintf(rootURLFmt, opt.Hostname)),
		pacer:       fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}

	f.srv.SetHeader("X-Accellion-Version", "28")

	f.features = (&fs.Features{
		CaseInsensitive:         false,
		CanHaveEmptyDirectories: true,
		PartialUploads:          false,
	}).Fill(ctx, f)

	// Renew the token in the background
	f.tokenRenewer = oauthutil.NewRenew(f.String(), ts, func() error {
		_, _, err := f.getFileID(ctx, "", "")
		return err
	})

	rootID, found, err := f.getFileID(ctx, "", "")
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.New("root not found")
	}

	f.dirCache = dircache.New(root, rootID.ID, f)

	err = f.dirCache.FindRoot(ctx, false)
	if err != nil {
		fileID, found, err := f.getFileID(ctx, "", root)
		if err != nil {
			return nil, fmt.Errorf("find root %s: %w", root, err)
		}

		if !found {
			return f, nil
		}

		if fileID.IsFile() {
			root, _ = dircache.SplitPath(root)
			f.dirCache = dircache.New(root, rootID.ID, f)

			return f, fs.ErrorIsFile
		}
	}

	return f, nil
}

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
	return f.description
}

// Precision return the precision of this Fs
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(kiteworksHashType)
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.newObjectWithInfo(ctx, remote, nil)
}

func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, info *api.FileInfo) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
	}
	var err error

	if info != nil {
		err = o.setMetaData(info)
	} else {
		err = o.readMetaData(ctx, false)
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

// setMetaData sets the metadata from info
func (o *Object) setMetaData(info *api.FileInfo) (err error) {
	if info.IsDir() {
		fs.Debugf(o, "%q is %q", o.remote, info.Type)
		return fs.ErrorIsDir
	}

	if !info.IsFile() {
		fs.Debugf(o, "%q is %q", o.remote, info.Type)
		return fmt.Errorf("%q is %q: %w", o.remote, info.Type, fs.ErrorNotAFile)
	}

	o.size = info.Size
	o.id = info.ID
	o.hasMetaData = true
	o.obType = info.Type
	o.sha256 = info.FingerPrints.FindHash(api.HashName)

	if info.ClientModified != nil {
		o.modTime = time.Time(*info.ClientModified)
	} else {
		o.modTime = time.Time(info.Modified)
	}

	return nil
}

func (o *Object) readMetaData(ctx context.Context, force bool) (err error) {
	if o.hasMetaData && !force {
		return nil
	}

	leaf, directoryID, err := o.fs.dirCache.FindPath(ctx, o.remote, false)
	if err != nil {
		if err == fs.ErrorDirNotFound {
			return fs.ErrorObjectNotFound
		}
		return err
	}

	file, found, err := o.fs.getFileID(ctx, directoryID, leaf)
	if err != nil {
		return fmt.Errorf("get fileID for %s in directory %s: %w", leaf, directoryID, err)
	}

	if !found {
		fs.Debugf(nil, "object not found: remote %s: directory %s: leaf %s", o.remote, directoryID, leaf)
		return fs.ErrorObjectNotFound
	}

	metadata, err := o.fs.getMetadata(ctx, file.ID)
	if err != nil {
		return fmt.Errorf("get file metadata: %w", err)
	}

	return o.setMetaData(metadata)
}

// Open an object for read
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	if o.id == "" {
		return nil, errors.New("can't download - no id")
	}

	return o.fs.download(ctx, o.id, o.obType, options...)
}

// ModTime returns the modification time of the object
func (o *Object) ModTime(ctx context.Context) time.Time {
	err := o.readMetaData(ctx, false)
	if err != nil {
		fs.Logf(o, "Failed to read metadata: %v", err)
		return time.Now()
	}

	return o.modTime
}

// SetModTime sets the modification time of the local fs object. Not supported, file must be re-uploaded to change modification time
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorCantSetModTime
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	err := o.readMetaData(context.TODO(), false)
	if err != nil {
		fs.Logf(o, "Failed to read metadata: %v", err)
		return 0
	}

	return o.size
}

// Storable returns a boolean showing whether this object storable
func (o *Object) Storable() bool {
	return true
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	return o.id
}

// Hash returns the SHA3-256 of an object
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	if ty != kiteworksHashType {
		return "", hash.ErrUnsupported
	}

	// ! TODO upload should return hash in the response model because otherwise on each upload we will be reading metadata to know changed hash
	err := o.readMetaData(ctx, true)
	if err != nil {
		return "", err
	}

	return o.sha256, nil
}

// Fs return the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// String returns object remote path
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

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	err := o.fs.deleteObject(ctx, o.id)
	if err != nil {
		return fmt.Errorf("failed to remove %s %s: %w", o.obType, o.id, err)
	}

	if o.obType != api.FileType {
		o.fs.dirCache.FlushDir(o.remote)
	}

	return nil
}

// Update the object with the contents of the io.Reader, modTime and size
//
// The new object may have been created if an error is returned
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (err error) {
	if o.fs.tokenRenewer != nil {
		o.fs.tokenRenewer.Start()
		defer o.fs.tokenRenewer.Stop()
	}

	size := src.Size()
	modTime := src.ModTime(ctx)
	remote := o.Remote()

	// Create the directory for the object if it doesn't exist
	leaf, directoryID, err := o.fs.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return err
	}

	info, err := o.fs.upload(ctx, in, directoryID, leaf, size, modTime)
	if err != nil {
		return err
	}

	return o.setMetaData(info)
}

func (f *Fs) upload(ctx context.Context, file io.Reader, parentID, name string, size int64, modTime time.Time) (*api.FileInfo, error) {
	opts := rest.Opts{
		Method: "POST",
		Path:   fmt.Sprintf("/rest/folders/%s/actions/initiateUpload", parentID),
	}

	chunks := f.splitChunks(size)

	payload := api.InitializeUpload{
		FileName:       f.opt.Enc.FromStandardName(name),
		TotalSize:      size,
		TotalChunks:    len(chunks),
		ClientModified: modTime.Format(time.RFC3339),
	}

	var result = &api.UploadResult{}

	err := f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, payload, result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize upload: %w", err)
	}

	return f.uploadChunks(ctx, file, name, result.URI, chunks)
}

func (f *Fs) uploadChunks(ctx context.Context, file io.Reader, name, path string, chunks []int64) (info *api.FileInfo, err error) {
	for index, chunk := range chunks {
		isLastChunk := index == len(chunks)-1

		opts := rest.Opts{
			Method:        "POST",
			Path:          path,
			Body:          readers.NewRepeatableReader(io.LimitReader(file, chunk)),
			ContentLength: &chunk,
			MultipartParams: url.Values{
				"compressionMode": []string{"NORMAL"},
				"compressionSize": []string{strconv.FormatInt(chunk, 10)},
				"originalSize":    []string{strconv.FormatInt(chunk, 10)},
				"index":           []string{strconv.Itoa(index + 1)},
			},
			Parameters: url.Values{
				"returnEntity": []string{"true"},
			},
			MultipartContentName: "content",
			MultipartFileName:    name,
			NoResponse:           true,
		}

		if isLastChunk {
			opts.NoResponse = false
			info = &api.FileInfo{}
		}

		err := f.pacer.Call(func() (bool, error) {
			resp, err := f.srv.CallJSON(ctx, &opts, nil, info)
			return shouldRetry(ctx, resp, err)
		})
		if err != nil {
			return nil, fmt.Errorf("failed to upload chunk %d of file: %w", index, err)
		}
	}

	return info, nil
}

func (f *Fs) splitChunks(totalSize int64) []int64 {
	if totalSize == 0 {
		return []int64{totalSize}
	}

	var chunks []int64

	for totalSize > 0 {
		if totalSize > int64(f.opt.ChunkSize) {
			chunks = append(chunks, int64(f.opt.ChunkSize))
			totalSize -= int64(f.opt.ChunkSize)
		} else {
			chunks = append(chunks, totalSize)
			totalSize = 0
		}
	}

	return chunks
}

func (f *Fs) getMetadata(ctx context.Context, id string) (result *api.FileInfo, err error) {
	metadata, err := f.getFileMetadata(ctx, id)
	if err != nil {
		if !errors.Is(err, fs.ErrorObjectNotFound) {
			return nil, err
		}

		directory, err := f.getDirectoryMetadata(ctx, id)
		if err != nil {
			return nil, err
		}

		metadata = &api.FileInfo{
			ID:           id,
			Type:         api.DirectoryType,
			Size:         int64(len(directory.Data)),
			FingerPrints: api.FileFingerPrints{},
		}
	}

	return metadata, nil
}

func (f *Fs) getFileMetadata(ctx context.Context, id string) (result *api.FileInfo, err error) {
	parameters := url.Values{
		"deleted": []string{"false"},
	}

	opts := rest.Opts{
		Method:     "GET",
		Path:       fmt.Sprintf("rest/files/%s", id),
		Parameters: parameters,
	}

	result = &api.FileInfo{}

	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		// Kiteworks returns 403 in case non existent ID is specified
		if resp != nil && resp.StatusCode == http.StatusForbidden {
			return nil, fs.ErrorObjectNotFound
		}

		return nil, fmt.Errorf("failed to get file metadata: %w", err)
	}

	return result, nil
}

func (f *Fs) getDirectoryMetadata(ctx context.Context, id string) (result *api.DirectoryInfo, err error) {
	parameters := url.Values{
		"deleted": []string{"false"},
	}

	opts := rest.Opts{
		Method:     "GET",
		Path:       fmt.Sprintf("rest/folders/%s/children", id),
		Parameters: parameters,
	}

	result = &api.DirectoryInfo{}

	var resp *http.Response
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, result)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		// Kiteworks returns 403 in case non existent ID is specified
		if resp != nil && resp.StatusCode == http.StatusForbidden {
			return nil, fs.ErrorObjectNotFound
		}

		return nil, fmt.Errorf("failed to get directory metadata: %w", err)
	}

	return result, nil
}

func (f *Fs) deleteObject(ctx context.Context, id string) error {
	opts := rest.Opts{
		Method: "DELETE",
		Path:   "rest/files",
		Parameters: url.Values{
			"id:in":          []string{id},
			"partialSuccess": []string{"false"},
		},
		NoResponse: true,
	}

	err := f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, nil, nil)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return fmt.Errorf("delete file %s: %w", id, err)
	}

	if f.opt.HardDelete {
		opts = rest.Opts{
			Method:     "DELETE",
			Path:       fmt.Sprintf("rest/files/%s/actions/permanent", id),
			NoResponse: true,
		}
		err := f.pacer.Call(func() (bool, error) {
			resp, err := f.srv.CallJSON(ctx, &opts, nil, nil)
			return shouldRetry(ctx, resp, err)
		})
		if err != nil {
			return fmt.Errorf("delete file %s permanently: %w", id, err)
		}
	}

	return nil
}

func (f *Fs) deleteDirectory(ctx context.Context, id string) error {
	opts := rest.Opts{
		Method: "DELETE",
		Path:   "rest/folders",
		Parameters: url.Values{
			"id:in":          []string{id},
			"partialSuccess": []string{"false"},
		},
		NoResponse: true,
	}

	err := f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, nil, nil)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return fmt.Errorf("delete directory %s: %w", id, err)
	}

	if f.opt.HardDelete {
		opts = rest.Opts{
			Method:     "DELETE",
			Path:       fmt.Sprintf("rest/folders/%s/actions/permanent", id),
			NoResponse: true,
		}
		err := f.pacer.Call(func() (bool, error) {
			resp, err := f.srv.CallJSON(ctx, &opts, nil, nil)
			return shouldRetry(ctx, resp, err)
		})
		if err != nil {
			return fmt.Errorf("delete folder %s permanently: %w", id, err)
		}
	}

	return nil
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
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	directoryID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return nil, err
	}

	content, err := f.getDirectoryMetadata(ctx, directoryID)
	if err != nil {
		return nil, err
	}

	for _, file := range content.Data {
		remote := path.Join(dir, f.opt.Enc.ToStandardName(file.Name))
		if file.IsDir() {
			f.dirCache.Put(remote, file.ID)

			d := fs.NewDir(remote, time.Time(file.Modified)).SetID(file.ID).SetItems(file.Size)

			entries = append(entries, d)
		} else {
			o := &Object{
				fs:     f,
				remote: remote,
			}

			err = o.setMetaData(&file)
			if err != nil {
				fs.Debugf(file, "failed to set object metadata: %s", err)
			}

			entries = append(entries, o)
		}
	}

	return entries, nil
}

// FindLeaf finds a directory of name leaf in the folder with ID pathID
func (f *Fs) FindLeaf(ctx context.Context, pathID, leaf string) (folderID string, found bool, err error) {
	result, found, err := f.getFileID(ctx, pathID, leaf)
	if err != nil {
		return "", false, fmt.Errorf("find leaf: %w", err)
	}

	if !found {
		return "", false, nil
	}

	if result.IsFile() {
		return "", false, nil
	}

	return result.ID, true, nil
}

// Mkdir creates the container if it doesn't exist
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	_, err := f.dirCache.FindDir(ctx, dir, true)
	return err
}

// CreateDir makes a directory with pathID as parent and name leaf
func (f *Fs) CreateDir(ctx context.Context, pathID, leaf string) (dirID string, err error) {
	dir, err := f.createDir(ctx, pathID, leaf)
	if err != nil {
		return "", err
	}

	return dir.ID, nil
}

// getFileID gets id, parent and type of path in given parentID
func (f *Fs) getFileID(ctx context.Context, parentID, path string) (result *api.FileInfo, found bool, err error) {
	if path == "" {
		return f.getRootFileID(ctx)
	}

	parentPath, _ := f.dirCache.GetInv(parentID)
	path = filepath.Join(parentPath, path)

	// search in Kiteworks works always from the home folder, so we need to join path with the root when needed
	if !f.isRootIncluded(path) {
		path = filepath.Join(f.Root(), path)
	}

	parameters := url.Values{
		"path": []string{f.opt.Enc.FromStandardPath(path)},
	}

	opts := rest.Opts{
		Method:     "GET",
		Path:       "rest/search",
		Parameters: parameters,
	}

	search := &api.FileSearch{}

	err = f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, nil, search)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, false, fmt.Errorf("failed to get file id: %w", err)
	}

	result = search.FindByParent(parentID)
	if result == nil || result.ParentID == nil {
		return nil, false, nil
	}

	if result.ID == "" {
		return nil, false, fmt.Errorf("empty ID returned for path %s", path)
	}

	return result, true, nil
}

func (f *Fs) isRootIncluded(path string) bool {
	root := strings.TrimSuffix(filepath.ToSlash(f.Root()), "/") + "/"
	path = strings.TrimSuffix(filepath.ToSlash(path), "/") + "/"

	if len(path) <= len(root) {
		return strings.HasPrefix(root, path)
	}

	return strings.HasPrefix(path, root)
}

func (f *Fs) getRootFileID(ctx context.Context) (result *api.FileInfo, found bool, err error) {
	parameters := url.Values{
		"limit":   []string{"1"},
		"deleted": []string{"false"},
	}

	opts := rest.Opts{
		Method:     "GET",
		Path:       "rest/folders/top",
		Parameters: parameters,
	}

	rootTopDir := &api.DirectoryInfo{}

	err = f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, nil, rootTopDir)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, false, fmt.Errorf("failed to get file id: %w", err)
	}

	if len(rootTopDir.Data) == 0 {
		return nil, false, nil
	}

	return &api.FileInfo{
		ID:   *rootTopDir.Data[0].ParentID,
		Type: api.DirectoryType,
	}, true, nil
}

// createDir creates directory in pathID with name leaf
//
// resolve - if true will resolve name conflict on server side, if false - will return error if object with this name exists
func (f *Fs) createDir(ctx context.Context, pathID, leaf string) (newDir *api.FileInfo, err error) {
	parameters := url.Values{
		"returnEntity": []string{"true"},
	}

	opts := rest.Opts{
		Method:     "POST",
		Path:       fmt.Sprintf("rest/folders/%s/folders", pathID),
		Parameters: parameters,
	}

	payload := api.CreateDir{
		Name: f.opt.Enc.FromStandardName(leaf),
	}

	newDir = &api.FileInfo{}

	err = f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, payload, newDir)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	return
}

func (f *Fs) download(ctx context.Context, id, objectType string, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	var payload api.DownloadLinkRequest

	switch objectType {
	case api.FileType:
		payload.FileID = id
	case api.DirectoryType:
		payload.FolderIDs = []string{id}
	}

	opts := rest.Opts{
		Method: "POST",
		Path:   "rest/files/actions/downloadLink",
	}

	links := &api.DownloadLinkResponse{}

	err = f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, payload, &links)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}

	if len(links.DownloadLinks) == 0 {
		return nil, fmt.Errorf("nothing to download")
	}

	opts = rest.Opts{
		Method:  "GET",
		Path:    links.DownloadLinks[0],
		Options: options,
	}

	var resp *http.Response

	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.Call(ctx, &opts)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}

	return resp.Body, err
}

// Put the object into the container
//
// Copy the reader in to the new object which is returned.
//
// The new object may have been created if an error is returned
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()
	size := src.Size()
	mtime := src.ModTime(ctx)

	o := &Object{
		fs:      f,
		remote:  remote,
		size:    size,
		modTime: mtime,
	}

	return o, o.Update(ctx, in, src, options...)
}

// Rmdir deletes the root folder
//
// Returns an error if it isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.purgeCheck(ctx, dir, true)
}

// Purge deletes all the files in the directory
//
// Optional interface: Only implement this if you have a way of
// deleting all the files quicker than just running Remove() on the
// result of List()
func (f *Fs) Purge(ctx context.Context, dir string) error {
	return f.purgeCheck(ctx, dir, false)
}

func (f *Fs) purgeCheck(ctx context.Context, dir string, check bool) error {
	root := path.Join(f.root, dir)
	if root == "" {
		return errors.New("can't purge root directory")
	}

	rootID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return err
	}

	if check {
		file, err := f.getMetadata(ctx, rootID)
		if err != nil {
			return err
		}

		if file.IsFile() {
			return fs.ErrorIsFile
		}

		if file.Size != 0 {
			return fs.ErrorDirectoryNotEmpty
		}
	}

	err = f.deleteDirectory(ctx, rootID)
	if err != nil {
		return err
	}

	f.dirCache.FlushDir(dir)

	return nil
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (usage *fs.Usage, err error) {
	opts := rest.Opts{
		Method: "GET",
		Path:   "rest/users/me/quota",
	}

	var (
		quota api.QuotaInfo
		resp  *http.Response
	)

	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &quota)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read quota info: %w", err)
	}

	free := quota.FolderQuotaAllowed - quota.FolderQuotaUsed

	usage = &fs.Usage{
		Used:  fs.NewUsageValue(quota.FolderQuotaUsed),    // bytes in use
		Total: fs.NewUsageValue(quota.FolderQuotaAllowed), // bytes total
		Free:  fs.NewUsageValue(free),                     // bytes free
	}

	return usage, nil
}

// Shutdown shutdown the fs
func (f *Fs) Shutdown(ctx context.Context) error {
	f.tokenRenewer.Shutdown()
	return nil
}

// DirCacheFlush resets the directory cache - used in testing as an
// optional interface
func (f *Fs) DirCacheFlush() {
	f.dirCache.ResetRoot()
}

// Check the interfaces are satisfied
var (
	_ fs.Fs      = (*Fs)(nil)
	_ fs.Purger  = (*Fs)(nil)
	_ fs.Abouter = (*Fs)(nil)
	// _ fs.Copier          = (*Fs)(nil)
	// _ fs.Mover           = (*Fs)(nil)
	// _ fs.DirMover        = (*Fs)(nil)
	_ dircache.DirCacher = (*Fs)(nil)
	_ fs.DirCacheFlusher = (*Fs)(nil)
	_ fs.Object          = (*Object)(nil)
	_ fs.IDer            = (*Object)(nil)
)
