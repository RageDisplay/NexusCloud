package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database handles SQLite database operations
type Database struct {
	conn *sql.DB
}

// NewDatabase creates and initializes a new database
func NewDatabase(dbPath string) (*Database, error) {
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db := &Database{conn: conn}

	// Initialize schema
	if err := db.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

// initSchema creates database tables
func (db *Database) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT,
		is_admin BOOLEAN DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP,
		is_active BOOLEAN DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		token TEXT UNIQUE NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		ip_address TEXT,
		user_agent TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS login_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		success BOOLEAN DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		action TEXT NOT NULL,
		resource_path TEXT,
		details TEXT,
		ip_address TEXT,
		success BOOLEAN DEFAULT 1,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS file_metadata (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_path TEXT UNIQUE NOT NULL,
		owner_id INTEGER NOT NULL,
		file_size INTEGER DEFAULT 0,
		file_hash TEXT,
		is_encrypted BOOLEAN DEFAULT 1,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		accessed_at TIMESTAMP,
		FOREIGN KEY (owner_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS permissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		file_path TEXT NOT NULL,
		permission_type TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id),
		UNIQUE(user_id, file_path, permission_type)
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
	CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at ON login_attempts(created_at);
	`

	_, err := db.conn.Exec(schema)
	return err
}

// CreateUser creates a new user
func (db *Database) CreateUser(username, passwordHash, email string, isAdmin bool) (int64, error) {
	result, err := db.conn.Exec(
		"INSERT INTO users (username, password_hash, email, is_admin) VALUES (?, ?, ?, ?)",
		username, passwordHash, email, isAdmin,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to create user: %w", err)
	}
	return result.LastInsertId()
}

// GetUserByUsername retrieves user by username
func (db *Database) GetUserByUsername(username string) (*User, error) {
	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, email, is_admin, created_at, last_login, is_active FROM users WHERE username = ? AND is_active = 1",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.IsAdmin, &user.CreatedAt, &user.LastLogin, &user.IsActive)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// GetUserByID retrieves user by ID
func (db *Database) GetUserByID(userID int64) (*User, error) {
	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, email, is_admin, created_at, last_login, is_active FROM users WHERE id = ? AND is_active = 1",
		userID,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.IsAdmin, &user.CreatedAt, &user.LastLogin, &user.IsActive)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// UpdateLastLogin updates user last login time
func (db *Database) UpdateLastLogin(userID int64) error {
	_, err := db.conn.Exec(
		"UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
		userID,
	)
	return err
}

// CreateSession creates a new session
func (db *Database) CreateSession(sessionID, userID int64, token string, expiresAt time.Time, ipAddress, userAgent string) error {
	_, err := db.conn.Exec(
		"INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
		sessionID, userID, token, expiresAt, ipAddress, userAgent,
	)
	return err
}

// GetSession retrieves session by token
func (db *Database) GetSession(token string) (*Session, error) {
	session := &Session{}
	err := db.conn.QueryRow(
		"SELECT id, user_id, token, expires_at FROM sessions WHERE token = ? AND expires_at > CURRENT_TIMESTAMP",
		token,
	).Scan(&session.ID, &session.UserID, &session.Token, &session.ExpiresAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found or expired")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

// DeleteSession deletes a session
func (db *Database) DeleteSession(token string) error {
	_, err := db.conn.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

// LogLoginAttempt logs a login attempt
func (db *Database) LogLoginAttempt(username, ipAddress string, success bool) error {
	_, err := db.conn.Exec(
		"INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
		username, ipAddress, success,
	)
	return err
}

// GetRecentFailedLogins gets recent failed login attempts
func (db *Database) GetRecentFailedLogins(username string, since time.Duration) (int, error) {
	var count int
	err := db.conn.QueryRow(
		"SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0 AND created_at > datetime('now', ?)",
		username, fmt.Sprintf("-%d minutes", int(since.Minutes())),
	).Scan(&count)
	return count, err
}

// LogAuditEvent logs an audit event
func (db *Database) LogAuditEvent(userID *int64, action, resourcePath, details, ipAddress string, success bool) error {
	_, err := db.conn.Exec(
		"INSERT INTO audit_logs (user_id, action, resource_path, details, ip_address, success) VALUES (?, ?, ?, ?, ?, ?)",
		userID, action, resourcePath, details, ipAddress, success,
	)
	return err
}

// Close closes the database connection
func (db *Database) Close() error {
	return db.conn.Close()
}

// User represents a user record
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Email        string
	IsAdmin      bool
	CreatedAt    time.Time
	LastLogin    *time.Time
	IsActive     bool
}

// Session represents a session record
type Session struct {
	ID        string
	UserID    int64
	Token     string
	ExpiresAt time.Time
}
