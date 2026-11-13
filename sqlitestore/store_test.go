package sqlitestore_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/relloyd/authkit"
	"github.com/relloyd/authkit/sqlitestore"
)

func open(t *testing.T) (*sqlitestore.Store, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := sqlitestore.New(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

func TestMigrationsApplyOnceAndLeaveTheAppsVersionAlone(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	// The app's own schema and migration counter, in the same file.
	if _, err := db.Exec(`CREATE TABLE progress (id INTEGER PRIMARY KEY); PRAGMA user_version = 7`); err != nil {
		t.Fatal(err)
	}
	for range 2 { // a second start must be a no-op
		if _, err := sqlitestore.New(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	var appVersion, rows int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&appVersion); err != nil {
		t.Fatal(err)
	}
	if appVersion != 7 {
		t.Errorf("app's user_version = %d, want it untouched at 7", appVersion)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM authkit_schema`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("authkit_schema has %d rows, want 1", rows)
	}
}

func TestUsersIdentitiesAndRoles(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)

	if _, err := s.UserByEmail(ctx, "ada@example.test"); !errors.Is(err, authkit.ErrNotFound) {
		t.Fatalf("missing user: err = %v, want ErrNotFound", err)
	}
	u, err := s.CreateUser(ctx, "ada@example.test", "Ada", []string{"editor", "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == 0 || !slices.Equal(u.Roles, []string{"admin", "editor"}) || u.CreatedAt.IsZero() {
		t.Errorf("created user = %+v", u)
	}
	if _, err := s.CreateUser(ctx, "ada@example.test", "Again", nil); !errors.Is(err, authkit.ErrConflict) {
		t.Errorf("duplicate email: err = %v, want ErrConflict", err)
	}

	id := authkit.Identity{Provider: "google", Subject: "sub-1", Email: "ada@example.test"}
	if err := s.LinkIdentity(ctx, u.ID, id); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkIdentity(ctx, u.ID, id); !errors.Is(err, authkit.ErrConflict) {
		t.Errorf("duplicate identity: err = %v, want ErrConflict", err)
	}
	got, err := s.UserByIdentity(ctx, "google", "sub-1")
	if err != nil || got.ID != u.ID {
		t.Errorf("UserByIdentity = %+v, %v", got, err)
	}
	// The same subject at another provider is somebody else.
	if _, err := s.UserByIdentity(ctx, "github", "sub-1"); !errors.Is(err, authkit.ErrNotFound) {
		t.Errorf("other provider: err = %v, want ErrNotFound", err)
	}

	if err := s.AddRoles(ctx, u.ID, []string{"admin", "owner"}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.UserByID(ctx, u.ID); !slices.Equal(got.Roles, []string{"admin", "editor", "owner"}) {
		t.Errorf("roles after AddRoles = %v", got.Roles)
	}
	if err := s.SetRoles(ctx, u.ID, []string{"viewer"}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.UserByID(ctx, u.ID); !slices.Equal(got.Roles, []string{"viewer"}) {
		t.Errorf("roles after SetRoles = %v", got.Roles)
	}

	if _, err := s.CreateUser(ctx, "grace@example.test", "Grace", nil); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListUsers(ctx)
	if err != nil || len(all) != 2 || all[0].Email != "ada@example.test" || all[1].Roles == nil {
		t.Errorf("ListUsers = %+v, %v", all, err)
	}
}

func TestSessionsAndPendingLogins(t *testing.T) {
	ctx := context.Background()
	s, db := open(t)
	u, err := s.CreateUser(ctx, "ada@example.test", "Ada", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second).UTC()
	sess := authkit.Session{IDHash: "h1", UserID: u.ID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByHash(ctx, "h1")
	if err != nil || *got != sess {
		t.Fatalf("SessionByHash = %+v, %v; want %+v", got, err, sess)
	}
	if err := s.TouchSession(ctx, "h1", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.SessionByHash(ctx, "h1"); !got.LastSeenAt.Equal(now.Add(time.Minute)) {
		t.Errorf("LastSeenAt = %v", got.LastSeenAt)
	}

	p := authkit.PendingLogin{StateHash: "s1", Provider: "google", Nonce: "n", Verifier: "v", ReturnTo: "/x", ExpiresAt: now.Add(time.Minute)}
	if err := s.CreatePendingLogin(ctx, p); err != nil {
		t.Fatal(err)
	}
	taken, err := s.TakePendingLogin(ctx, "s1")
	if err != nil || *taken != p {
		t.Fatalf("TakePendingLogin = %+v, %v; want %+v", taken, err, p)
	}
	if _, err := s.TakePendingLogin(ctx, "s1"); !errors.Is(err, authkit.ErrNotFound) {
		t.Errorf("second take: err = %v, want ErrNotFound (single use)", err)
	}

	// DeleteExpired removes what is past its expiry and nothing else.
	for _, row := range []authkit.PendingLogin{
		{StateHash: "old", ExpiresAt: now.Add(-time.Second)},
		{StateHash: "live", ExpiresAt: now.Add(time.Minute)},
	} {
		if err := s.CreatePendingLogin(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateSession(ctx, authkit.Session{IDHash: "h-old", UserID: u.ID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteExpired(ctx, now); err != nil {
		t.Fatal(err)
	}
	var pending, sessions int
	_ = db.QueryRow(`SELECT COUNT(*) FROM authkit_pending_logins`).Scan(&pending)
	_ = db.QueryRow(`SELECT COUNT(*) FROM authkit_sessions`).Scan(&sessions)
	if pending != 1 || sessions != 1 {
		t.Errorf("after DeleteExpired: %d pending, %d sessions; want 1 and 1", pending, sessions)
	}

	if err := s.DeleteSession(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByHash(ctx, "h1"); !errors.Is(err, authkit.ErrNotFound) {
		t.Errorf("deleted session: err = %v, want ErrNotFound", err)
	}
}

func TestDisableAndDeleteUser(t *testing.T) {
	ctx := context.Background()
	s, db := open(t)
	u, _ := s.CreateUser(ctx, "ada@example.test", "Ada", []string{"admin"})
	now := time.Now()
	_ = s.LinkIdentity(ctx, u.ID, authkit.Identity{Provider: "google", Subject: "sub-1", Email: u.Email})
	_ = s.CreateSession(ctx, authkit.Session{IDHash: "h1", UserID: u.ID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)})

	if err := s.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByID(ctx, u.ID); !got.Disabled {
		t.Error("user not marked disabled")
	}
	if _, err := s.SessionByHash(ctx, "h1"); !errors.Is(err, authkit.ErrNotFound) {
		t.Error("disabling did not end the user's sessions")
	}
	if err := s.SetDisabled(ctx, 999, true); !errors.Is(err, authkit.ErrNotFound) {
		t.Errorf("disabling a missing user: err = %v", err)
	}

	_ = s.CreateSession(ctx, authkit.Session{IDHash: "h2", UserID: u.ID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)})
	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"authkit_users", "authkit_identities", "authkit_user_roles", "authkit_sessions"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s has %d rows after DeleteUser (%v)", table, n, err)
		}
	}
}
