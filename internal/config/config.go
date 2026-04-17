package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Server
	HTTPPort      int
	HTTPSPort     int
	EnableHTTPS   bool
	CertFile      string
	KeyFile       string
	JWTSecret     string
	SessionExpiry time.Duration

	// Storage
	StoragePath string
	MaxFileSize int64

	// SMB
	SMBPort      int
	SMBEnabled   bool
	SMBShareName string

	// NFS
	NFSPort    int
	NFSEnabled bool
	NFSRoot    string

	// Database
	DBPath string

	// Security
	MaxLoginAttempts int
	LockoutDuration  time.Duration
	EncryptionKey    string

	// Admin
	AdminUsername string
	AdminPassword string
}

func Load() (*Config, error) {
	cfg := &Config{
		HTTPPort:         getEnvInt("HTTP_PORT", 8080),
		HTTPSPort:        getEnvInt("HTTPS_PORT", 8443),
		EnableHTTPS:      getEnvBool("ENABLE_HTTPS", true),
		CertFile:         getEnv("CERT_FILE", "/etc/nexus-cloud/certs/server.crt"),
		KeyFile:          getEnv("KEY_FILE", "/etc/nexus-cloud/certs/server.key"),
		SessionExpiry:    getEnvDuration("SESSION_EXPIRY", 24*time.Hour),
		StoragePath:      getEnv("STORAGE_PATH", "/data/storage"),
		MaxFileSize:      getEnvInt64("MAX_FILE_SIZE", 10*1024*1024*1024), // 10GB default
		SMBPort:          getEnvInt("SMB_PORT", 445),
		SMBEnabled:       getEnvBool("SMB_ENABLED", true),
		SMBShareName:     getEnv("SMB_SHARE_NAME", "NexusCloud"),
		NFSPort:          getEnvInt("NFS_PORT", 2049),
		NFSEnabled:       getEnvBool("NFS_ENABLED", true),
		NFSRoot:          getEnv("NFS_ROOT", "/exports"),
		DBPath:           getEnv("DB_PATH", "/data/db/nexus.db"),
		MaxLoginAttempts: getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
		LockoutDuration:  getEnvDuration("LOCKOUT_DURATION", 15*time.Minute),
		AdminUsername:    getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword:    getEnv("ADMIN_PASSWORD", ""),
	}

	// Generate encryption key if not set
	if cfg.EncryptionKey == "" {
		key, err := generateSecureKey(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		cfg.EncryptionKey = key
	} else {
		cfg.EncryptionKey = getEnv("ENCRYPTION_KEY", "")
	}

	// Generate JWT secret if not set
	if cfg.JWTSecret == "" {
		secret, err := generateSecureKey(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		cfg.JWTSecret = secret
	} else {
		cfg.JWTSecret = getEnv("JWT_SECRET", "")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.HTTPPort < 1 || c.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", c.HTTPPort)
	}

	if c.EnableHTTPS {
		if c.HTTPSPort < 1 || c.HTTPSPort > 65535 {
			return fmt.Errorf("invalid HTTPS port: %d", c.HTTPSPort)
		}
		if c.CertFile == "" || c.KeyFile == "" {
			return fmt.Errorf("HTTPS enabled but cert/key files not specified")
		}
	}

	if c.StoragePath == "" {
		return fmt.Errorf("storage path not specified")
	}

	if c.AdminPassword == "" {
		return fmt.Errorf("admin password must be set via ADMIN_PASSWORD environment variable")
	}

	if c.MaxFileSize < 1024*1024 { // Minimum 1MB
		return fmt.Errorf("max file size too small")
	}

	return nil
}

func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	valStr := getEnv(key, "")
	if val, err := strconv.Atoi(valStr); err == nil {
		return val
	}
	return defaultVal
}

func getEnvInt64(key string, defaultVal int64) int64 {
	valStr := getEnv(key, "")
	if val, err := strconv.ParseInt(valStr, 10, 64); err == nil {
		return val
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	valStr := getEnv(key, "")
	if valStr != "" {
		return valStr == "true" || valStr == "1" || valStr == "yes"
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	valStr := getEnv(key, "")
	if duration, err := time.ParseDuration(valStr); err == nil {
		return duration
	}
	return defaultVal
}

func generateSecureKey(length int) (string, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
