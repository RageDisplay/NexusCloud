package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nexus-cloud/internal/auth"
	"nexus-cloud/internal/config"
	"nexus-cloud/internal/crypto"
	"nexus-cloud/internal/db"
	"nexus-cloud/internal/handler"
	"nexus-cloud/internal/nfs"
	"nexus-cloud/internal/smb"
	"nexus-cloud/internal/storage"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize database
	database, err := db.NewDatabase(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	// Initialize crypto managers
	passMgr := crypto.NewPasswordManager()
	encMgr, err := crypto.NewEncryptionManager(cfg.EncryptionKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize encryption manager: %v\n", err)
		os.Exit(1)
	}

	// Initialize storage manager
	storageMgr, err := storage.NewStorageManager(cfg.StoragePath, cfg.MaxFileSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize storage manager: %v\n", err)
		os.Exit(1)
	}

	// Initialize authentication manager
	authMgr := auth.NewAuthManager(cfg.JWTSecret, cfg.SessionExpiry)

	// Create or update admin user
	adminUser, _ := database.GetUserByUsername(cfg.AdminUsername)
	if adminUser == nil {
		passwordHash, err := passMgr.HashPassword(cfg.AdminPassword)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to hash admin password: %v\n", err)
			os.Exit(1)
		}

		adminID, err := database.CreateUser(cfg.AdminUsername, passwordHash, "admin@nexus-cloud.local", true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create admin user: %v\n", err)
			os.Exit(1)
		}

		if err := storageMgr.EnsureUserStorage(adminID); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create admin storage: %v\n", err)
		}

		fmt.Printf("Admin user '%s' created successfully\n", cfg.AdminUsername)
	}

	// Initialize handlers
	hdlr := handler.NewHandler(database, authMgr, storageMgr, passMgr, encMgr, cfg.MaxLoginAttempts)

	// Initialize Echo server
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:  []string{"*"},
		AllowMethods:  []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowHeaders:  []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		ExposeHeaders: []string{echo.HeaderContentLength},
		MaxAge:        300,
	}))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
	}))

	// Public routes (no auth required)
	e.POST("/api/auth/register", hdlr.Register)
	e.POST("/api/auth/login", hdlr.Login)
	e.GET("/health", hdlr.Health)

	// Static files for web UI (must be in public routes)
	if _, err := os.Stat("web"); err == nil {
		e.Static("/", "web")
	}

	// Protected routes group with JWT middleware
	apiV1 := e.Group("/api/v1")
	apiV1.Use(JWTMiddleware(authMgr))

	apiV1.POST("/files/upload", hdlr.UploadFile)
	apiV1.GET("/files/download", hdlr.DownloadFile)
	apiV1.DELETE("/files/delete", hdlr.DeleteFile)
	apiV1.GET("/files/list", hdlr.ListFiles)
	apiV1.GET("/files/info", hdlr.GetFileInfo)

	// Initialize SMB server if enabled
	var smbServer *smb.SMBServer
	if cfg.SMBEnabled {
		smbServer = smb.NewSMBServer(cfg.SMBPort, cfg.SMBShareName, storageMgr)
		go func() {
			if err := smbServer.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "SMB server error: %v\n", err)
			}
		}()
	}

	// Initialize NFS server if enabled
	var nfsServer *nfs.NFSServer
	if cfg.NFSEnabled {
		nfsServer = nfs.NewNFSServer(cfg.NFSPort, cfg.NFSRoot, storageMgr)
		go func() {
			if err := nfsServer.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "NFS server error: %v\n", err)
			}
		}()
	}

	// Start HTTP server with TLS if enabled
	go func() {
		if cfg.EnableHTTPS {
			fmt.Printf("HTTPS Server starting on port %d\n", cfg.HTTPSPort)
			if err := e.StartTLS(fmt.Sprintf(":%d", cfg.HTTPSPort), cfg.CertFile, cfg.KeyFile); err != nil {
				fmt.Fprintf(os.Stderr, "HTTPS server error: %v\n", err)
			}
		} else {
			fmt.Printf("HTTP Server starting on port %d\n", cfg.HTTPPort)
			if err := e.Start(fmt.Sprintf(":%d", cfg.HTTPPort)); err != nil {
				fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			}
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Server shutdown error: %v\n", err)
	}

	if smbServer != nil {
		smbServer.Stop()
	}

	if nfsServer != nil {
		nfsServer.Stop()
	}

	fmt.Println("Server stopped")
}

// JWTMiddleware verifies JWT tokens
func JWTMiddleware(authMgr *auth.AuthManager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth := c.Request().Header.Get("Authorization")
			if auth == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing authorization header")
			}

			// Extract token from "Bearer <token>"
			if len(auth) > 7 && auth[:7] == "Bearer " {
				auth = auth[7:]
			}

			claims, err := authMgr.VerifyToken(auth)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
			}

			c.Set("user", claims)
			return next(c)
		}
	}
}
