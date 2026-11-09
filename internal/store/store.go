// Package store keeps the Commonwealth platform's data in SQLite: the
// records it sends and receives, member instances, Commons Fund periods and
// counts, audits, the uniqueness registry, the public ledger and officials.
//
// The Commonwealth holds no register of people. The only personal data it
// ever sees is an audit sample, which is erased once the finding is issued.
package store

import (
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// ErrNotFound reports a missing row.
var ErrNotFound = errors.New("store: not found")

// Store is the Commonwealth platform's database.
type Store struct {
	db *sql.DB
}

// Open opens or creates the database at path and applies the schema.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; a single connection keeps writes ordered
	// and transactions simple.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: applying schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
