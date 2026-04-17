package handler

import (
	"fmt"
	"net/http"
	"nexus-cloud/internal/auth"
	"nexus-cloud/internal/crypto"
	"nexus-cloud/internal/db"
	"nexus-cloud/internal/storage"
	"strings"

	"github.com/labstack/echo/v4"
)

// Handler holds all handlers dependencies
type Handler struct {
	db               *db.Database
	authMgr          *auth.AuthManager
	storageMgr       *storage.StorageManager
	passMgr          *crypto.PasswordManager
	encMgr           *crypto.EncryptionManager
	maxLoginAttempts int
}

// NewHandler creates a new handler
func NewHandler(
	db *db.Database,
	authMgr *auth.AuthManager,
	storageMgr *storage.StorageManager,
	passMgr *crypto.PasswordManager,
	encMgr *crypto.EncryptionManager,
	maxLoginAttempts int,
) *Handler {
	return &Handler{
		db:               db,
		authMgr:          authMgr,
		storageMgr:       storageMgr,
		passMgr:          passMgr,
		encMgr:           encMgr,
		maxLoginAttempts: maxLoginAttempts,
	}
}

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// LoginRequest represents login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents login response
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	IsAdmin   bool   `json:"is_admin"`
}

// RegisterRequest represents registration request
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// FileUploadResponse represents file upload response
type FileUploadResponse struct {
	FileName string `json:"file_name"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
}

// Register handles user registration
func (h *Handler) Register(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "Invalid request"})
	}

	// Validate input
	if len(req.Username) < 3 || len(req.Username) > 50 {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "Username must be 3-50 characters"})
	}

	if len(req.Password) < 12 {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "Password must be at least 12 characters"})
	}

	// Hash password
	hash, err := h.passMgr.HashPassword(req.Password)
	if err != nil {
		h.db.LogAuditEvent(nil, "register_failed", "", err.Error(), c.RealIP(), false)
		return c.JSON(http.StatusInternalServerError, Response{Success: false, Error: "Failed to register"})
	}

	// Create user
	userID, err := h.db.CreateUser(req.Username, hash, req.Email, false)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return c.JSON(http.StatusConflict, Response{Success: false, Error: "Username already exists"})
		}
		return c.JSON(http.StatusInternalServerError, Response{Success: false, Error: "Failed to create user"})
	}

	// Create user storage
	if err := h.storageMgr.EnsureUserStorage(userID); err != nil {
		h.db.LogAuditEvent(&userID, "register_storage_failed", "", err.Error(), c.RealIP(), false)
		return c.JSON(http.StatusInternalServerError, Response{Success: false, Error: "Failed to create user storage"})
	}

	h.db.LogAuditEvent(&userID, "register", "", "User registered successfully", c.RealIP(), true)

	return c.JSON(http.StatusCreated, Response{
		Success: true,
		Message: "User registered successfully",
		Data: map[string]interface{}{
			"user_id":  userID,
			"username": req.Username,
		},
	})
}

// Login handles user login
func (h *Handler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "Invalid request"})
	}

	// Check for too many failed login attempts
	failedAttempts, _ := h.db.GetRecentFailedLogins(req.Username, 15)
	if failedAttempts >= h.maxLoginAttempts {
		h.db.LogAuditEvent(nil, "login_locked", req.Username, "Too many failed attempts", c.RealIP(), false)
		return c.JSON(http.StatusTooManyRequests, Response{Success: false, Error: "Account temporarily locked due to too many failed login attempts"})
	}

	// Get user
	user, err := h.db.GetUserByUsername(req.Username)
	if err != nil || !h.passMgr.VerifyPassword(req.Password, user.PasswordHash) {
		h.db.LogLoginAttempt(req.Username, c.RealIP(), false)
		h.db.LogAuditEvent(nil, "login_failed", req.Username, "Invalid credentials", c.RealIP(), false)
		return c.JSON(http.StatusUnauthorized, Response{Success: false, Error: "Invalid credentials"})
	}

	// Generate token
	token, expiresAt, err := h.authMgr.GenerateToken(user.ID, user.Username, user.IsAdmin)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{Success: false, Error: "Failed to generate token"})
	}

	// Update last login
	h.db.UpdateLastLogin(user.ID)
	h.db.LogLoginAttempt(req.Username, c.RealIP(), true)
	h.db.LogAuditEvent(&user.ID, "login", "", "User logged in", c.RealIP(), true)

	return c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "Login successful",
		Data: LoginResponse{
			Token:     token,
			ExpiresAt: expiresAt.Format("2006-01-02T15:04:05Z"),
			UserID:    user.ID,
			Username:  user.Username,
			IsAdmin:   user.IsAdmin,
		},
	})
}

// GetClaims extracts JWT claims from context
func (h *Handler) GetClaims(c echo.Context) (*auth.TokenClaims, error) {
	user := c.Get("user")
	if user == nil {
		return nil, fmt.Errorf("unauthorized")
	}

	claims, ok := user.(*auth.TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid user claims")
	}

	return claims, nil
}

// UploadFile handles file upload
func (h *Handler) UploadFile(c echo.Context) error {
	claims, err := h.GetClaims(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{Success: false, Error: "Unauthorized"})
	}

	// Get file from request
	file, err := c.FormFile("file")
	if err != nil {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "No file provided"})
	}

	src, err := file.Open()
	if err != nil {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "Failed to open file"})
	}
	defer src.Close()

	// Save file
	fileName := c.FormValue("path")
	if fileName == "" {
		fileName = file.Filename
	}

	_, err = h.storageMgr.SaveFile(claims.UserID, fileName, src)
	if err != nil {
		h.db.LogAuditEvent(&claims.UserID, "upload_failed", fileName, err.Error(), c.RealIP(), false)
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: err.Error()})
	}

	// Get file hash
	hash, _ := h.storageMgr.GetFileHash(claims.UserID, fileName)

	h.db.LogAuditEvent(&claims.UserID, "upload", fileName, fmt.Sprintf("File size: %d", file.Size), c.RealIP(), true)

	return c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "File uploaded successfully",
		Data: FileUploadResponse{
			FileName: fileName,
			Size:     file.Size,
			Hash:     hash,
		},
	})
}

// DownloadFile handles file download
func (h *Handler) DownloadFile(c echo.Context) error {
	claims, err := h.GetClaims(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{Success: false, Error: "Unauthorized"})
	}

	fileName := c.QueryParam("file")
	if fileName == "" {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "File parameter required"})
	}

	file, err := h.storageMgr.GetFile(claims.UserID, fileName)
	if err != nil {
		h.db.LogAuditEvent(&claims.UserID, "download_failed", fileName, err.Error(), c.RealIP(), false)
		return c.JSON(http.StatusNotFound, Response{Success: false, Error: "File not found"})
	}
	defer file.Close()

	h.db.LogAuditEvent(&claims.UserID, "download", fileName, "File downloaded", c.RealIP(), true)

	return c.Stream(http.StatusOK, "application/octet-stream", file)
}

// DeleteFile handles file deletion
func (h *Handler) DeleteFile(c echo.Context) error {
	claims, err := h.GetClaims(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{Success: false, Error: "Unauthorized"})
	}

	fileName := c.QueryParam("file")
	if fileName == "" {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "File parameter required"})
	}

	if err := h.storageMgr.DeleteFile(claims.UserID, fileName); err != nil {
		h.db.LogAuditEvent(&claims.UserID, "delete_failed", fileName, err.Error(), c.RealIP(), false)
		return c.JSON(http.StatusNotFound, Response{Success: false, Error: "File not found"})
	}

	h.db.LogAuditEvent(&claims.UserID, "delete", fileName, "File deleted", c.RealIP(), true)

	return c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "File deleted successfully",
	})
}

// ListFiles handles file listing
func (h *Handler) ListFiles(c echo.Context) error {
	claims, err := h.GetClaims(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{Success: false, Error: "Unauthorized"})
	}

	dirPath := c.QueryParam("path")
	if dirPath == "" {
		dirPath = "."
	}

	files, err := h.storageMgr.ListFiles(claims.UserID, dirPath)
	if err != nil {
		return c.JSON(http.StatusNotFound, Response{Success: false, Error: err.Error()})
	}

	return c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    files,
	})
}

// GetFileInfo handles getting file info
func (h *Handler) GetFileInfo(c echo.Context) error {
	claims, err := h.GetClaims(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{Success: false, Error: "Unauthorized"})
	}

	fileName := c.QueryParam("file")
	if fileName == "" {
		return c.JSON(http.StatusBadRequest, Response{Success: false, Error: "File parameter required"})
	}

	info, err := h.storageMgr.GetFileInfo(claims.UserID, fileName)
	if err != nil {
		return c.JSON(http.StatusNotFound, Response{Success: false, Error: "File not found"})
	}

	return c.JSON(http.StatusOK, Response{
		Success: true,
		Data:    info,
	})
}

// Health returns health status
func (h *Handler) Health(c echo.Context) error {
	return c.JSON(http.StatusOK, Response{
		Success: true,
		Message: "NexusCloud is healthy",
	})
}
