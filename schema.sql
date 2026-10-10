CREATE TABLE IF NOT EXISTS subs (
  endpoint    TEXT PRIMARY KEY,
  p256dh      TEXT NOT NULL,
  auth        TEXT NOT NULL,
  lat         REAL NOT NULL,
  lon         REAL NOT NULL,
  tz          TEXT NOT NULL,
  method      INTEGER NOT NULL DEFAULT 2,
  madhab      INTEGER NOT NULL DEFAULT 0,
  remind_json TEXT NOT NULL DEFAULT '{}',
  lang        TEXT NOT NULL DEFAULT 'en',
  schedule_date TEXT,
  next_fire   TEXT,
  next_prayer TEXT,
  created_at  TEXT DEFAULT (datetime('now')),
  updated_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_subs_next_fire ON subs(next_fire);
