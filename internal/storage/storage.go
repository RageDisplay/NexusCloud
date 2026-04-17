package storage

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// StorageManager handles file storage operations
type StorageManager struct {
	basePath    string
	maxFileSize int64
}

// NewStorageManager creates a new storage manager
func NewStorageManager(basePath string, maxFileSize int64) (*StorageManager, error) {
	// Create base path if it doesn't exist
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &StorageManager{
		basePath:    basePath,
		maxFileSize: maxFileSize,
	}, nil
}

// GetUserStoragePath returns the storage path for a user
func (sm *StorageManager) GetUserStoragePath(userID int64) string {
	return filepath.Join(sm.basePath, fmt.Sprintf("user_%d", userID))
}

// EnsureUserStorage creates user storage directory
func (sm *StorageManager) EnsureUserStorage(userID int64) error {
	userPath := sm.GetUserStoragePath(userID)
	return os.MkdirAll(userPath, 0700)
}

// SaveFile saves a file to storage
func (sm *StorageManager) SaveFile(userID int64, fileName string, content io.Reader) (string, error) {
	// Validate file name
	if err := validateFileName(fileName); err != nil {
		return "", err
	}

	userPath := sm.GetUserStoragePath(userID)

	// Ensure user storage exists
	if err := sm.EnsureUserStorage(userID); err != nil {
		return "", err
	}

	// Create subdirectories if needed
	filePath := filepath.Join(userPath, fileName)
	fileDir := filepath.Dir(filePath)

	if err := os.MkdirAll(fileDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Create temp file for atomic writes
	tempFile := filePath + ".tmp"
	file, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Copy content with size limit
	limitedReader := &io.LimitedReader{R: content, N: sm.maxFileSize + 1}
	written, err := io.Copy(file, limitedReader)
	if err != nil {
		os.Remove(tempFile)
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	if written > sm.maxFileSize {
		os.Remove(tempFile)
		return "", fmt.Errorf("file exceeds maximum size of %d bytes", sm.maxFileSize)
	}

	// Atomic rename
	if err := os.Rename(tempFile, filePath); err != nil {
		os.Remove(tempFile)
		return "", fmt.Errorf("failed to finalize file: %w", err)
	}

	return filePath, nil
}

// GetFile retrieves a file from storage
func (sm *StorageManager) GetFile(userID int64, fileName string) (io.ReadCloser, error) {
	if err := validateFileName(fileName); err != nil {
		return nil, err
	}

	userPath := sm.GetUserStoragePath(userID)
	filePath := filepath.Join(userPath, fileName)

	// Security check: ensure the resolved path is within user directory
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	absUserPath, err := filepath.Abs(userPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user path: %w", err)
	}

	if !strings.HasPrefix(absPath, absUserPath) {
		return nil, fmt.Errorf("path traversal detected")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

// DeleteFile deletes a file from storage
func (sm *StorageManager) DeleteFile(userID int64, fileName string) error {
	if err := validateFileName(fileName); err != nil {
		return err
	}

	userPath := sm.GetUserStoragePath(userID)
	filePath := filepath.Join(userPath, fileName)

	// Security check
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	absUserPath, err := filepath.Abs(userPath)
	if err != nil {
		return fmt.Errorf("failed to resolve user path: %w", err)
	}

	if !strings.HasPrefix(absPath, absUserPath) {
		return fmt.Errorf("path traversal detected")
	}

	return os.Remove(filePath)
}

// ListFiles lists files in a directory
func (sm *StorageManager) ListFiles(userID int64, dirPath string) ([]FileInfo, error) {
	if err := validateFileName(dirPath); err != nil {
		return nil, err
	}

	userPath := sm.GetUserStoragePath(userID)
	targetPath := filepath.Join(userPath, dirPath)

	// Security check
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	absUserPath, err := filepath.Abs(userPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user path: %w", err)
	}

	if !strings.HasPrefix(absPath, absUserPath) {
		return nil, fmt.Errorf("path traversal detected")
	}

	entries, err := os.ReadDir(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		files = append(files, FileInfo{
			Name:        entry.Name(),
			Size:        info.Size(),
			IsDirectory: entry.IsDir(),
			Modified:    info.ModTime(),
		})
	}

	return files, nil
}

// GetFileHash returns MD5 hash of file content
func (sm *StorageManager) GetFileHash(userID int64, fileName string) (string, error) {
	file, err := sm.GetFile(userID, fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// GetFileInfo returns file information
func (sm *StorageManager) GetFileInfo(userID int64, fileName string) (*FileInfo, error) {
	if err := validateFileName(fileName); err != nil {
		return nil, err
	}

	userPath := sm.GetUserStoragePath(userID)
	filePath := filepath.Join(userPath, fileName)

	// Security check
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	absUserPath, err := filepath.Abs(userPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user path: %w", err)
	}

	if !strings.HasPrefix(absPath, absUserPath) {
		return nil, fmt.Errorf("path traversal detected")
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return &FileInfo{
		Name:        info.Name(),
		Size:        info.Size(),
		IsDirectory: info.IsDir(),
		Modified:    info.ModTime(),
	}, nil
}

// FileInfo represents file information
type FileInfo struct {
	Name        string
	Size        int64
	IsDirectory bool
	Modified    interface{}
}

// validateFileName validates file name to prevent path traversal
func validateFileName(fileName string) error {
	if fileName == "" {
		return fmt.Errorf("file name cannot be empty")
	}

	// Prevent path traversal
	if strings.Contains(fileName, "..") || strings.HasPrefix(fileName, "/") {
		return fmt.Errorf("invalid file name")
	}

	return nil
}
