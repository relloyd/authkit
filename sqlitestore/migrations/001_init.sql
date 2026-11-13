-- authkit schema, version 1.
-- Tables are prefixed authkit_ so they can live in the app's own database
-- file. Times are Unix seconds (UTC).

CREATE TABLE authkit_users (
    id         INTEGER PRIMARY KEY,
    email      TEXT    NOT NULL UNIQUE,          -- lower-cased
    name       TEXT    NOT NULL DEFAULT '',
    disabled   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE authkit_user_roles (
    user_id INTEGER NOT NULL REFERENCES authkit_users (id) ON DELETE CASCADE,
    role    TEXT    NOT NULL,
    PRIMARY KEY (user_id, role)
) STRICT, WITHOUT ROWID;

-- One row per sign-in method a user has used. The key is what the provider
-- guarantees is stable (its own id for the account), never the email.
CREATE TABLE authkit_identities (
    provider   TEXT    NOT NULL,
    subject    TEXT    NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES authkit_users (id) ON DELETE CASCADE,
    email      TEXT    NOT NULL,                 -- as the provider reported it at linking
    created_at INTEGER NOT NULL,
    PRIMARY KEY (provider, subject)
) STRICT, WITHOUT ROWID;
CREATE INDEX authkit_identities_user ON authkit_identities (user_id);

-- id_hash is the SHA-256 of the cookie value; the value itself is not stored.
CREATE TABLE authkit_sessions (
    id_hash      TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES authkit_users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL                -- absolute expiry
) STRICT, WITHOUT ROWID;
CREATE INDEX authkit_sessions_user ON authkit_sessions (user_id);
CREATE INDEX authkit_sessions_expires ON authkit_sessions (expires_at);

-- A login between "redirected to the provider" and "came back". Single use.
CREATE TABLE authkit_pending_logins (
    state_hash TEXT    PRIMARY KEY,
    provider   TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    verifier   TEXT    NOT NULL,
    return_to  TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
