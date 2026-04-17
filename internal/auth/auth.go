package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AuthManager handles authentication and JWT tokens
type AuthManager struct {
	jwtSecret     string
	sessionExpiry time.Duration
}

// NewAuthManager creates a new auth manager
func NewAuthManager(jwtSecret string, sessionExpiry time.Duration) *AuthManager {
	return &AuthManager{
		jwtSecret:     jwtSecret,
		sessionExpiry: sessionExpiry,
	}
}

// GenerateToken generates a JWT token for a user
func (am *AuthManager) GenerateToken(userID int64, username string, isAdmin bool) (string, time.Time, error) {
	expiresAt := time.Now().Add(am.sessionExpiry)

	claims := jwt.MapClaims{
		"sub":      userID,
		"username": username,
		"admin":    isAdmin,
		"iat":      time.Now().Unix(),
		"exp":      expiresAt.Unix(),
		"jti":      uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(am.jwtSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// VerifyToken verifies a JWT token
func (am *AuthManager) VerifyToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(am.jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check if token is expired
	if claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID   int64  `json:"sub"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"admin"`
	JTI      string `json:"jti"`
	jwt.RegisteredClaims
}

// Credentials represents login credentials
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Permission represents a file permission
type Permission struct {
	Read   bool
	Write  bool
	Delete bool
	Share  bool
}

// PermissionChecker checks if user has permissions
type PermissionChecker struct {
	defaultPerms Permission
}

// NewPermissionChecker creates a new permission checker
func NewPermissionChecker() *PermissionChecker {
	return &PermissionChecker{
		defaultPerms: Permission{
			Read:   true,
			Write:  true,
			Delete: true,
			Share:  false, // Users can't share by default
		},
	}
}

// HasPermission checks if user has specific permission
func (pc *PermissionChecker) HasPermission(isAdmin bool, perm Permission, action string) bool {
	// Admins have all permissions
	if isAdmin {
		return true
	}

	switch action {
	case "read":
		return perm.Read
	case "write":
		return perm.Write
	case "delete":
		return perm.Delete
	case "share":
		return perm.Share
	default:
		return false
	}
}
