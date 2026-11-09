-- Every signed record the Commonwealth sent or received, as JSON.
CREATE TABLE IF NOT EXISTS records (
    id         TEXT PRIMARY KEY,
    direction  TEXT NOT NULL CHECK (direction IN ('sent', 'received')),
    type       TEXT NOT NULL,
    peer       TEXT NOT NULL,
    issued_at  TEXT NOT NULL,
    body       BLOB NOT NULL,
    stored_at  TEXT NOT NULL,
    delivery   TEXT NOT NULL DEFAULT ''     -- for sent records: pending, accepted, duplicate or rejected
);
CREATE INDEX IF NOT EXISTS records_type ON records (type, issued_at);

-- Member instances the Commonwealth has attested: Regions and States.
CREATE TABLE IF NOT EXISTS members (
    instance     TEXT PRIMARY KEY,
    layer        TEXT NOT NULL CHECK (layer IN ('region', 'state')),
    name         TEXT NOT NULL,
    description  BLOB NOT NULL,              -- the signed description that was attested
    attestation  TEXT NOT NULL REFERENCES records (id),
    attested_at  TEXT NOT NULL,
    attested_by  TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended'))
);

-- Commons Fund periods. A period is open while counts arrive, and settled
-- when the treasurer divides the period's pool among all recipients.
CREATE TABLE IF NOT EXISTS periods (
    period       TEXT PRIMARY KEY,            -- YYYY-MM
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'settled')),
    pool         TEXT NOT NULL DEFAULT '',     -- XCU distributed
    per_person   TEXT NOT NULL DEFAULT '',
    recipients   INTEGER NOT NULL DEFAULT 0,
    paid_out     TEXT NOT NULL DEFAULT '',     -- per_person × recipients; the rest stays in the fund
    settled_at   TEXT NOT NULL DEFAULT '',
    settled_by   TEXT NOT NULL DEFAULT ''
);

-- Eligibility counts accepted from States: one per State per period.
CREATE TABLE IF NOT EXISTS counts (
    record       TEXT PRIMARY KEY REFERENCES records (id),
    period       TEXT NOT NULL REFERENCES periods (period),
    state        TEXT NOT NULL,
    residents    INTEGER NOT NULL,
    adults       INTEGER NOT NULL,
    recipients   INTEGER NOT NULL,
    settlement   TEXT REFERENCES records (id),
    confirmation TEXT REFERENCES records (id),
    UNIQUE (period, state)
);

-- Eligibility audits, one per count.
CREATE TABLE IF NOT EXISTS audits (
    request      TEXT PRIMARY KEY REFERENCES records (id),
    count        TEXT NOT NULL UNIQUE REFERENCES counts (record),
    state        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'checking', 'finding')),
    sampled      INTEGER NOT NULL DEFAULT 0,
    unverified   INTEGER NOT NULL DEFAULT 0,
    responded_at TEXT NOT NULL DEFAULT '',
    finding      TEXT REFERENCES records (id),
    issued_by    TEXT NOT NULL DEFAULT ''
);

-- Sampled entries of an audit. Personal data: the State's response is not
-- kept as a record, and name, birth date and reference are erased when the
-- finding is issued. Only the outcome of each check remains.
CREATE TABLE IF NOT EXISTS audit_openings (
    request      TEXT NOT NULL REFERENCES audits (request),
    position     INTEGER NOT NULL,             -- sampled index in the recipient list
    valid        INTEGER NOT NULL,             -- passed the structural check
    problem      TEXT NOT NULL DEFAULT '',
    ref          TEXT NOT NULL DEFAULT '',
    name         TEXT NOT NULL DEFAULT '',
    birth_date   TEXT NOT NULL DEFAULT '',
    field        TEXT NOT NULL DEFAULT '' CHECK (field IN ('', 'found', 'not-found')),
    checked_by   TEXT NOT NULL DEFAULT '',
    checked_at   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (request, position)
);

-- The uniqueness registry: which States hold each token, per key epoch.
-- Nothing else is known about a token.
CREATE TABLE IF NOT EXISTS uniqueness_tokens (
    epoch  INTEGER NOT NULL,
    token  TEXT NOT NULL,
    state  TEXT NOT NULL,
    PRIMARY KEY (epoch, token, state)
);
CREATE INDEX IF NOT EXISTS uniqueness_by_state ON uniqueness_tokens (epoch, state);

-- Open uniqueness conflicts, by token. Closed when only one State holds it.
CREATE TABLE IF NOT EXISTS uniqueness_conflicts (
    epoch      INTEGER NOT NULL,
    token      TEXT NOT NULL,
    states     TEXT NOT NULL,                  -- comma-separated, sorted
    opened_at  TEXT NOT NULL,
    PRIMARY KEY (epoch, token)
);

-- The Commonwealth's public ledger.
CREATE TABLE IF NOT EXISTS ledger_entries (
    idx   INTEGER PRIMARY KEY,
    entry BLOB NOT NULL,
    leaf  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_checkpoints (
    seq  INTEGER PRIMARY KEY,
    id   TEXT NOT NULL UNIQUE,
    body BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_cosignatures (
    checkpoint TEXT NOT NULL REFERENCES ledger_checkpoints (id),
    witness    TEXT NOT NULL,
    body       BLOB NOT NULL,
    PRIMARY KEY (checkpoint, witness)
);

-- What the Commonwealth, acting as a witness, last cosigned for each log.
CREATE TABLE IF NOT EXISTS witnessed_logs (
    origin TEXT PRIMARY KEY,
    size   INTEGER NOT NULL,
    root   BLOB NOT NULL
);

-- Officials' accounts, sessions and activity.
CREATE TABLE IF NOT EXISTS officials (
    username      TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'members', 'treasurer', 'auditor')),
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES officials (username),
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS official_actions (
    id       INTEGER PRIMARY KEY,
    at       TEXT NOT NULL,
    username TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
