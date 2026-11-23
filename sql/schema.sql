-- Tables the report loads into an in-memory SQLite database.
-- Times are stored as 'YYYY-MM-DD HH:MM:SS' text, which sorts and compares correctly.

CREATE TABLE alerts (
    alert_id      TEXT PRIMARY KEY,
    incident_id   TEXT NOT NULL,
    rule_id       TEXT NOT NULL,
    rule_name     TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    technique     TEXT NOT NULL,
    entity_type   TEXT NOT NULL,
    entity        TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    detected_at   TEXT NOT NULL,
    event_count   INTEGER NOT NULL
);

CREATE TABLE incidents (
    incident_id        TEXT PRIMARY KEY,
    title              TEXT NOT NULL,
    category           TEXT NOT NULL,
    severity           TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status             TEXT NOT NULL CHECK (status IN ('Open', 'Acknowledged', 'Contained', 'Closed')),
    opened_at          TEXT NOT NULL,
    contain_due        TEXT NOT NULL,
    ack_met            TEXT NOT NULL,
    contain_met        TEXT NOT NULL,
    minutes_to_detect  INTEGER,
    minutes_to_ack     INTEGER,
    minutes_to_contain INTEGER
);

CREATE TABLE findings (
    finding_id   TEXT PRIMARY KEY,
    check_name   TEXT NOT NULL,
    requirement  TEXT NOT NULL,
    severity     TEXT NOT NULL,
    username     TEXT NOT NULL,
    department   TEXT NOT NULL
);

CREATE TABLE compliance (
    check_id     TEXT PRIMARY KEY,
    csf          TEXT NOT NULL,
    control      TEXT NOT NULL,
    result       TEXT NOT NULL CHECK (result IN ('Pass', 'Fail'))
);

-- Severity as a number, for sorting.
CREATE TABLE severity_rank (severity TEXT PRIMARY KEY, rank INTEGER NOT NULL);
INSERT INTO severity_rank VALUES ('Low', 1), ('Medium', 2), ('High', 3), ('Critical', 4);
