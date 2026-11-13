// Package sqlitestore is the ready-made authkit.Store on SQLite
// (modernc.org/sqlite, pure Go).
//
// It uses the database handle the app already has, so users and sessions sit
// in the app's own file beside its other tables. All its tables are prefixed
// authkit_. Migrations are numbered SQL files applied once each; because the
// app owns PRAGMA user_version in a shared file, the applied version is kept
// in the authkit_schema table instead.
package sqlitestore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/relloyd/authkit"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store implements authkit.Store and adds the user administration an admin
// page needs.
type Store struct {
	db *sql.DB
}

var _ authkit.Store = (*Store)(nil)

// New applies any outstanding migrations and returns the store. The handle
// should be opened with a busy timeout, as the app's own would be, e.g.
// "file:app.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)".
func New(ctx context.Context, db *sql.DB) (*Store, error) {
	if err := migrate(ctx, db); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS authkit_schema (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("sqlitestore: create schema table: %w", err)
	}
	var current int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM authkit_schema`).Scan(&current); err != nil {
		return fmt.Errorf("sqlitestore: read schema version: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(names)
	for _, name := range names {
		base := strings.TrimPrefix(name, "migrations/")
		prefix, _, _ := strings.Cut(base, "_")
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return fmt.Errorf("sqlitestore: migration %s has no numeric prefix", base)
		}
		if version <= current {
			continue
		}
		script, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(script)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlitestore: migration %s: %w", base, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO authkit_schema (version) VALUES (?)`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("sqlitestore: migration %s: %w", base, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("sqlitestore: migration %s: %w", base, err)
		}
	}
	return nil
}

// isUnique reports whether err is a unique or primary-key violation.
func isUnique(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	return se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(s int64) time.Time { return time.Unix(s, 0).UTC() }

const userColumns = `u.id, u.email, u.name, u.disabled, u.created_at`

func (s *Store) user(ctx context.Context, where string, args ...any) (*authkit.User, error) {
	var u authkit.User
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM authkit_users u `+where, args...).
		Scan(&u.ID, &u.Email, &u.Name, &u.Disabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authkit.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = fromUnix(created)
	if u.Roles, err = s.roles(ctx, u.ID); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) roles(ctx context.Context, userID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role FROM authkit_user_roles WHERE user_id = ? ORDER BY role`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	roles := []string{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// UserByID implements authkit.Store.
func (s *Store) UserByID(ctx context.Context, id int64) (*authkit.User, error) {
	return s.user(ctx, `WHERE u.id = ?`, id)
}

// UserByEmail implements authkit.Store.
func (s *Store) UserByEmail(ctx context.Context, email string) (*authkit.User, error) {
	return s.user(ctx, `WHERE u.email = ?`, email)
}

// UserByIdentity implements authkit.Store.
func (s *Store) UserByIdentity(ctx context.Context, provider, subject string) (*authkit.User, error) {
	return s.user(ctx, `JOIN authkit_identities i ON i.user_id = u.id WHERE i.provider = ? AND i.subject = ?`, provider, subject)
}

// CreateUser implements authkit.Store.
func (s *Store) CreateUser(ctx context.Context, email, name string, roles []string) (*authkit.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO authkit_users (email, name, created_at) VALUES (?, ?, ?)`,
		email, name, unix(time.Now()))
	if isUnique(err) {
		return nil, authkit.ErrConflict
	}
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO authkit_user_roles (user_id, role) VALUES (?, ?)`, id, role); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.UserByID(ctx, id)
}

// LinkIdentity implements authkit.Store.
func (s *Store) LinkIdentity(ctx context.Context, userID int64, id authkit.Identity) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO authkit_identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)`,
		id.Provider, id.Subject, userID, id.Email, unix(time.Now()))
	if isUnique(err) {
		return authkit.ErrConflict
	}
	return err
}

// AddRoles implements authkit.Store.
func (s *Store) AddRoles(ctx context.Context, userID int64, roles []string) error {
	for _, role := range roles {
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO authkit_user_roles (user_id, role) VALUES (?, ?)`, userID, role); err != nil {
			return err
		}
	}
	return nil
}

// CreateSession implements authkit.Store.
func (s *Store) CreateSession(ctx context.Context, se authkit.Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO authkit_sessions (id_hash, user_id, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		se.IDHash, se.UserID, unix(se.CreatedAt), unix(se.LastSeenAt), unix(se.ExpiresAt))
	return err
}

// SessionByHash implements authkit.Store.
func (s *Store) SessionByHash(ctx context.Context, idHash string) (*authkit.Session, error) {
	se := authkit.Session{IDHash: idHash}
	var created, seen, expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, created_at, last_seen_at, expires_at FROM authkit_sessions WHERE id_hash = ?`, idHash).
		Scan(&se.UserID, &created, &seen, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authkit.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	se.CreatedAt, se.LastSeenAt, se.ExpiresAt = fromUnix(created), fromUnix(seen), fromUnix(expires)
	return &se, nil
}

// TouchSession implements authkit.Store.
func (s *Store) TouchSession(ctx context.Context, idHash string, lastSeen time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE authkit_sessions SET last_seen_at = ? WHERE id_hash = ?`, unix(lastSeen), idHash)
	return err
}

// DeleteSession implements authkit.Store.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM authkit_sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteUserSessions implements authkit.Store. It signs the user out
// everywhere.
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM authkit_sessions WHERE user_id = ?`, userID)
	return err
}

// CreatePendingLogin implements authkit.Store.
func (s *Store) CreatePendingLogin(ctx context.Context, p authkit.PendingLogin) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO authkit_pending_logins (state_hash, provider, nonce, verifier, return_to, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		p.StateHash, p.Provider, p.Nonce, p.Verifier, p.ReturnTo, unix(p.ExpiresAt))
	return err
}

// TakePendingLogin implements authkit.Store. DELETE ... RETURNING makes the
// read and the delete one statement, so a state value works once.
func (s *Store) TakePendingLogin(ctx context.Context, stateHash string) (*authkit.PendingLogin, error) {
	p := authkit.PendingLogin{StateHash: stateHash}
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM authkit_pending_logins WHERE state_hash = ? RETURNING provider, nonce, verifier, return_to, expires_at`, stateHash).
		Scan(&p.Provider, &p.Nonce, &p.Verifier, &p.ReturnTo, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authkit.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.ExpiresAt = fromUnix(expires)
	return &p, nil
}

// DeleteExpired implements authkit.Store.
func (s *Store) DeleteExpired(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM authkit_pending_logins WHERE expires_at <= ?`, unix(now)); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM authkit_sessions WHERE expires_at <= ?`, unix(now))
	return err
}

// The methods below are not part of authkit.Store: they are for an app's
// admin page.

// ListUsers returns every user, oldest first.
func (s *Store) ListUsers(ctx context.Context) ([]*authkit.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM authkit_users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	users := make([]*authkit.User, 0, len(ids))
	for _, id := range ids {
		u, err := s.UserByID(ctx, id)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// SetRoles replaces the user's roles. A role seeded from configuration comes
// back at the user's next sign-in.
func (s *Store) SetRoles(ctx context.Context, userID int64, roles []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM authkit_user_roles WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO authkit_user_roles (user_id, role) VALUES (?, ?)`, userID, role); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetDisabled disables or re-enables a user. Disabling also ends the user's
// sessions.
func (s *Store) SetDisabled(ctx context.Context, userID int64, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE authkit_users SET disabled = ? WHERE id = ?`, disabled, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return authkit.ErrNotFound
	}
	if disabled {
		return s.DeleteUserSessions(ctx, userID)
	}
	return nil
}

// DeleteUser removes the user with their identities, roles and sessions. It
// deletes each table explicitly, so it does not depend on the connection
// having foreign keys switched on. The app must delete its own rows for the
// user first.
func (s *Store) DeleteUser(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`DELETE FROM authkit_sessions WHERE user_id = ?`,
		`DELETE FROM authkit_identities WHERE user_id = ?`,
		`DELETE FROM authkit_user_roles WHERE user_id = ?`,
		`DELETE FROM authkit_users WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
