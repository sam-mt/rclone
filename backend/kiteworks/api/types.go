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

// FileInfo is a file info model
type FileInfo struct {
	Modified       Time             `json:"modified"`
	ParentID       *string          `json:"parentId"`
	ClientModified *Time            `json:"clientModified"`
	PathIDs        *string          `json:"pathIds"`
	Parent         *Parent          `json:"parent"`
	ID             string           `json:"id"`
	Type           string           `json:"type"`
	Name           string           `json:"name"`
	Path           string           `json:"path"`
	FingerPrints   FileFingerPrints `json:"fingerprints"`
	Size           int64            `json:"size"`
}

// Parent field of FileInfo object
type Parent struct {
	Modified        Time    `json:"modified"`
	ParentID        *string `json:"parentId"`
	Name            string  `json:"name"`
	Type            string  `json:"type"`
	Path            string  `json:"path"`
	ID              string  `json:"id"`
	CurrentUserRole struct {
		Name string `json:"name"`
		Type string `json:"type"`
		ID   int    `json:"id"`
		Rank int    `json:"rank"`
	} `json:"currentUserRole"`
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

// UserInfo is a model for /rest/users/me - user for getting root dir id
type UserInfo struct {
	BaseDirID string `json:"basedirId"`
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
	ClientModified string `json:"clientModified,omitempty"`
	TotalChunks    int    `json:"totalChunks,omitempty"`
	TotalSize      int64  `json:"totalSize"`
}

// UploadResult is a response model for initialized upload
type UploadResult struct {
	URI       string `json:"uri"`
	ID        int64  `json:"id"`
	TotalSize int64  `json:"totalSize"`
}

// QuotaInfo is a model that contains quota info for user
type QuotaInfo struct {
	FolderQuotaAllowed int64 `json:"folder_quota_allowed"`
	FolderQuotaUsed    int64 `json:"folder_quota_used"`
}
