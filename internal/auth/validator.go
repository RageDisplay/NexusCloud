package auth

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

// PasswordValidator validates password strength
type PasswordValidator struct {
	minLength        int
	requireUpperCase bool
	requireLowerCase bool
	requireNumbers   bool
	requireSpecial   bool
}

// NewPasswordValidator creates a new password validator
func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{
		minLength:        12,
		requireUpperCase: true,
		requireLowerCase: true,
		requireNumbers:   true,
		requireSpecial:   true,
	}
}

// Validate validates password strength
func (pv *PasswordValidator) Validate(password, username string) error {
	if len(password) < pv.minLength {
		return fmt.Errorf("password must be at least %d characters", pv.minLength)
	}

	if len(password) > 128 {
		return fmt.Errorf("password cannot exceed 128 characters")
	}

	if strings.EqualFold(password, username) || strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		return fmt.Errorf("password cannot contain username")
	}

	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case !unicode.IsLetter(char) && !unicode.IsDigit(char):
			hasSpecial = true
		}
	}

	if pv.requireUpperCase && !hasUpper {
		return fmt.Errorf("password must contain uppercase letters")
	}

	if pv.requireLowerCase && !hasLower {
		return fmt.Errorf("password must contain lowercase letters")
	}

	if pv.requireNumbers && !hasNumber {
		return fmt.Errorf("password must contain numbers")
	}

	if pv.requireSpecial && !hasSpecial {
		return fmt.Errorf("password must contain special characters")
	}

	// Check for common patterns
	if isCommonPassword(password) {
		return fmt.Errorf("password is too common")
	}

	return nil
}

// UsernameValidator validates username
type UsernameValidator struct {
	minLength int
	maxLength int
	pattern   *regexp.Regexp
}

// NewUsernameValidator creates a new username validator
func NewUsernameValidator() *UsernameValidator {
	// Only alphanumeric and underscore
	pattern := regexp.MustCompile("^[a-zA-Z0-9_.-]+$")
	return &UsernameValidator{
		minLength: 3,
		maxLength: 50,
		pattern:   pattern,
	}
}

// Validate validates username
func (uv *UsernameValidator) Validate(username string) error {
	if len(username) < uv.minLength {
		return fmt.Errorf("username must be at least %d characters", uv.minLength)
	}

	if len(username) > uv.maxLength {
		return fmt.Errorf("username cannot exceed %d characters", uv.maxLength)
	}

	if !uv.pattern.MatchString(username) {
		return fmt.Errorf("username can only contain letters, numbers, underscores, dots, and hyphens")
	}

	// Prevent reserved usernames
	reserved := []string{"admin", "root", "system", "test", "guest", "anonymous"}
	for _, r := range reserved {
		if strings.EqualFold(username, r) {
			return fmt.Errorf("username '%s' is reserved", username)
		}
	}

	return nil
}

// EmailValidator validates email
type EmailValidator struct{}

// Validate validates email
func (ev *EmailValidator) Validate(email string) error {
	if email == "" {
		return nil // Email is optional
	}

	if len(email) > 254 {
		return fmt.Errorf("email too long")
	}

	_, err := mail.ParseAddress(email)
	return err
}

// FileNameValidator validates file names
type FileNameValidator struct{}

// Validate validates file name
func (fnv *FileNameValidator) Validate(fileName string) error {
	if fileName == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	if len(fileName) > 255 {
		return fmt.Errorf("filename too long")
	}

	// Block path traversal
	if strings.Contains(fileName, "..") || strings.Contains(fileName, "~") {
		return fmt.Errorf("invalid filename")
	}

	// Block absolute paths
	if strings.HasPrefix(fileName, "/") || strings.HasPrefix(fileName, "\\") {
		return fmt.Errorf("invalid filename")
	}

	// Block null bytes
	if strings.Contains(fileName, "\x00") {
		return fmt.Errorf("invalid filename")
	}

	return nil
}

// Common weak passwords
func isCommonPassword(password string) bool {
	commonPasswords := []string{
		"password", "123456", "password123", "admin", "letmein",
		"welcome", "monkey", "1q2w3e4r", "qwerty", "abc123",
		"password1", "12345678", "123456789", "1234567890",
	}

	lower := strings.ToLower(password)
	for _, common := range commonPasswords {
		if strings.Contains(lower, common) {
			return true
		}
	}

	return false
}

// SanitizeInput removes potentially harmful characters
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	// Remove control characters
	input = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, input)
	return strings.TrimSpace(input)
}
