-- The state's schema at version 11 (M7.7 to M7.9.5), frozen: what the step to 12 starts from.
-- Never edited: a later version adds its own file.
CREATE TABLE formats (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    ticket_kind TEXT NOT NULL
) STRICT;
CREATE TABLE tickets (
    id             TEXT PRIMARY KEY,
    canonical      BLOB NOT NULL,
    state          TEXT NOT NULL,
    lease_id       TEXT NOT NULL,
    feedback       TEXT,
    feedback_by    TEXT,
    approver       TEXT,
    namespace      TEXT,
    sshsig         TEXT,
    cert_serial    INTEGER UNIQUE,
    current_ticket TEXT REFERENCES tickets(id),
    session_pubkey TEXT,
    certificate    TEXT,
    source         TEXT,
    renews         TEXT REFERENCES tickets(id),
    summary        TEXT,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX tickets_state ON tickets(state);
CREATE INDEX tickets_source ON tickets(source, state);
CREATE TABLE usage (
    lease_id   TEXT NOT NULL REFERENCES tickets(id),
    repo       TEXT NOT NULL,
    signatures INTEGER NOT NULL DEFAULT 0 CHECK (signatures >= 0),
    pushes     INTEGER NOT NULL DEFAULT 0 CHECK (pushes >= 0),
    PRIMARY KEY (lease_id, repo)
) STRICT;
CREATE TABLE ops (
    lease_id TEXT NOT NULL REFERENCES tickets(id),
    at       INTEGER NOT NULL
) STRICT;
CREATE INDEX ops_lease_at ON ops(lease_id, at);
CREATE TABLE ledger (
    commit_id       TEXT NOT NULL,
    lease_id        TEXT NOT NULL REFERENCES tickets(id),
    repo            TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    signed_at       INTEGER NOT NULL,
    paths_digest    TEXT,
    note            TEXT CHECK (note IN ('pending', 'written')),
    note_credential TEXT,
    PRIMARY KEY (commit_id, lease_id, repo)
) STRICT;
CREATE INDEX ledger_lease ON ledger(lease_id);
CREATE INDEX ledger_notes_pending ON ledger(repo) WHERE note = 'pending';
CREATE TABLE authority (
    target     TEXT NOT NULL CHECK (target IN ('policy', 'approvers', 'readers')),
    version    INTEGER NOT NULL CHECK (version >= 1),
    text       TEXT NOT NULL,
    digest     TEXT NOT NULL,
    how        TEXT NOT NULL CHECK (how IN ('init', 'admin', 'recover')),
    document   TEXT,
    signature  TEXT,
    approver   TEXT,
    applied_at INTEGER NOT NULL,
    PRIMARY KEY (target, version)
) STRICT;
CREATE TABLE authority_head (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    policy    INTEGER NOT NULL,
    approvers INTEGER NOT NULL,
    readers   INTEGER NOT NULL,
    mac       TEXT NOT NULL
) STRICT;
CREATE TABLE token_versions (
    id      TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version >= 1)
) STRICT;
