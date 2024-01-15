package api

import (
	"strings"
	"time"
)

// Kiteworks constants
const (
	DirectoryType = "d"
	FileType      = "f"
	HashName      = "sha3-256"

	dateFormat = "2006-01-02T15:04:05+0000"
)

// FileSearch is a response model for searching for file by path
type FileSearch struct {
	Files   []FileInfo `json:"files"`
	Folders []FileInfo `json:"folders"`
}

// FindByParent returns file item by parent ID
func (fs *FileSearch) FindByParent(parentID string) *FileInfo {
	if parentID == "" {
		if len(fs.Files) > 0 {
			return &fs.Files[0]
		}

		if len(fs.Folders) > 0 {
			return &fs.Folders[0]
		}
	}

	for _, f := range fs.Files {
		if f.ParentID != nil && *f.ParentID == parentID {
			return &f
		}
	}

	for _, f := range fs.Folders {
		if f.ParentID != nil && *f.ParentID == parentID {
			return &f
		}
	}

	return nil
}

// FileInfo is a file info model
type FileInfo struct {
	ID           string           `json:"id"`
	ParentID     *string          `json:"parentId"`
	Type         string           `json:"type"`
	Name         string           `json:"name"`
	Path         string           `json:"path"`
	Size         int64            `json:"size"`
	Modified     Time             `json:"modified"`
	FingerPrints FileFingerPrints `json:"fingerprints"`
}

// FileFingerPrints is a custom type for a list of FileFingerPrint
type FileFingerPrints []FileFingerPrint

// FindHash finds hash for specified algorithm
func (fp FileFingerPrints) FindHash(algo string) string {
	if fp == nil {
		return ""
	}

	for _, f := range fp {
		if f.Algo == algo {
			return f.Hash
		}
	}

	return ""
}

// FileFingerPrint is a model for file hashes
type FileFingerPrint struct {
	Algo string `json:"algo"`
	Hash string `json:"hash"`
}

// Time is a custom time to parse string date in specified format
type Time time.Time

// MarshalJSON is a method to implement Marshaller
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(time.Time(t).String()), nil
}

// UnmarshalJSON is a method to implement Marshaller
func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "" {
		return nil
	}

	parsed, err := time.Parse(dateFormat, strings.Trim(string(data), "\""))
	if err != nil {
		return err
	}

	*t = Time(parsed)

	return nil
}

// DirectoryInfo is a model for directory info
type DirectoryInfo struct {
	Data []FileInfo `json:"data"`
}

// IsFile checks whether file item is a file
func (fi *FileInfo) IsFile() bool {
	if fi == nil {
		return false
	}

	return fi.Type == FileType
}

// IsDir checks whether file item is a directory
func (fi *FileInfo) IsDir() bool {
	if fi == nil {
		return false
	}

	return fi.Type == DirectoryType
}

// CreateDir is a request model for directory creation
type CreateDir struct {
	Name string `json:"name"`
}

// DownloadLinkRequest is a request model for download link
type DownloadLinkRequest struct {
	FileID    string   `json:"fileId,omitempty"`
	FileIDs   []string `json:"fileIds,omitempty"`
	FolderIDs []string `json:"folderIds,omitempty"`
}

// DownloadLinkResponse is a response model for download link
type DownloadLinkResponse struct {
	DownloadLinks []string `json:"downloadLinks"`
}

// InitializeUpload is a request model to initialize upload
type InitializeUpload struct {
	FileName       string `json:"filename"`
	TotalChunks    int    `json:"totalChunks,omitempty"`
	TotalSize      int64  `json:"totalSize"`
	ClientModified string `json:"clientModified,omitempty"`
}

// UploadResult is a response model for initialized upload
type UploadResult struct {
	ID        int64  `json:"id"`
	URI       string `json:"uri"`
	TotalSize int64  `json:"totalSize"`
}

// QuotaInfo is a model that contains quota info for user
type QuotaInfo struct {
	FolderQuotaAllowed int64 `json:"folder_quota_allowed"`
	FolderQuotaUsed    int64 `json:"folder_quota_used"`
}
