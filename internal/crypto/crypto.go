package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// EncryptionManager handles data encryption/decryption
type EncryptionManager struct {
	key []byte
}

// NewEncryptionManager creates a new encryption manager
func NewEncryptionManager(hexKey string) (*EncryptionManager, error) {
	if hexKey == "" {
		return nil, fmt.Errorf("encryption key cannot be empty")
	}

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes (256-bit)")
	}

	return &EncryptionManager{key: key}, nil
}

// Encrypt encrypts data using AES-256-GCM
func (em *EncryptionManager) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(em.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM
func (em *EncryptionManager) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(em.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// PasswordManager handles password hashing and verification
type PasswordManager struct{}

// NewPasswordManager creates a new password manager
func NewPasswordManager() *PasswordManager {
	return &PasswordManager{}
}

// HashPassword hashes password using bcrypt with cost 14
func (pm *PasswordManager) HashPassword(password string) (string, error) {
	// bcrypt with cost 14 provides strong security
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword verifies password against hash
func (pm *PasswordManager) VerifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// DeriveKey derives a key from password and salt using Argon2
func (pm *PasswordManager) DeriveKey(password, salt string) string {
	saltBytes := []byte(salt)
	// Argon2id with strong parameters
	key := argon2.IDKey([]byte(password), saltBytes, 3, 64*1024, 4, 32)
	return hex.EncodeToString(key)
}

// SecureHash generates a secure SHA256 hash of data
func SecureHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateRandomToken generates a cryptographically secure random token
func GenerateRandomToken(length int) (string, error) {
	token := make([]byte, length)
	_, err := rand.Read(token)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(token), nil
}
