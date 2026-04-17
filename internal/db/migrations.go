package db

import (
	"database/sql"
	"fmt"
)

// Migration represents a database migration
type Migration struct {
	Version int
	Name    string
	Up      func(*sql.DB) error
	Down    func(*sql.DB) error
}

// MigrationManager handles database migrations
type MigrationManager struct {
	db         *sql.DB
	migrations []Migration
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *sql.DB) *MigrationManager {
	return &MigrationManager{
		db:         db,
		migrations: []Migration{},
	}
}

// GetMigrations returns list of migrations
func (mm *MigrationManager) GetMigrations() []Migration {
	return []Migration{
		{
			Version: 1,
			Name:    "Create initial schema",
			Up: func(db *sql.DB) error {
				// Already handled in initSchema
				return nil
			},
			Down: func(db *sql.DB) error {
				return fmt.Errorf("rolling back initial schema not supported")
			},
		},
		{
			Version: 2,
			Name:    "Add encryption metadata",
			Up: func(db *sql.DB) error {
				_, err := db.Exec(`
					ALTER TABLE file_metadata ADD COLUMN IF NOT EXISTS encryption_key_id INTEGER;
					ALTER TABLE file_metadata ADD COLUMN IF NOT EXISTS file_iv TEXT;
				`)
				return err
			},
			Down: func(db *sql.DB) error {
				return fmt.Errorf("migration 2 rollback not supported")
			},
		},
		{
			Version: 3,
			Name:    "Add sharing capabilities",
			Up: func(db *sql.DB) error {
				_, err := db.Exec(`
					CREATE TABLE IF NOT EXISTS shares (
						id INTEGER PRIMARY KEY AUTOINCREMENT,
						file_path TEXT NOT NULL,
						owner_id INTEGER NOT NULL,
						shared_with_user_id INTEGER,
						share_token TEXT UNIQUE,
						expires_at TIMESTAMP,
						permission_level TEXT DEFAULT 'read',
						created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
						FOREIGN KEY (owner_id) REFERENCES users(id),
						FOREIGN KEY (shared_with_user_id) REFERENCES users(id)
					);
				`)
				return err
			},
			Down: func(db *sql.DB) error {
				_, err := db.Exec("DROP TABLE IF EXISTS shares")
				return err
			},
		},
	}
}

// RunMigrations runs all pending migrations
func (mm *MigrationManager) RunMigrations() error {
	migrations := mm.GetMigrations()

	for _, migration := range migrations {
		if migration.Up == nil {
			continue
		}

		err := migration.Up(mm.db)
		if err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", migration.Version, migration.Name, err)
		}
	}

	return nil
}
