-- Run once via: wrangler d1 execute scam-detector-db --file=schema.sql

CREATE TABLE IF NOT EXISTS devices (
  token      TEXT PRIMARY KEY,
  name       TEXT NOT NULL DEFAULT 'unnamed device',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  token      TEXT NOT NULL,
  tactic     TEXT NOT NULL,
  confidence REAL NOT NULL,
  timestamp  TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  FOREIGN KEY (token) REFERENCES devices(token)
);

CREATE INDEX IF NOT EXISTS idx_events_token ON events(token);
CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);
