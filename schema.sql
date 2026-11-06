-- positiveLife4me: scanned lifting sessions (Cloudflare D1).
-- Paste this into the D1 database's Console in the Cloudflare dashboard and run it once.
CREATE TABLE IF NOT EXISTS lift_sessions (
  id TEXT PRIMARY KEY,
  user TEXT NOT NULL,            -- profile id from sign-in (adam, lauren)
  date TEXT NOT NULL,            -- YYYY-MM-DD
  workout_name TEXT,             -- as written on the page, e.g. "Back"
  muscle_day TEXT,               -- matching Lift day, e.g. "Back"
  notes TEXT,
  exercises TEXT NOT NULL,       -- JSON: [{name, sets:[{reps, weight, implements}]}]
  created_at INTEGER NOT NULL    -- milliseconds since 1970
);
CREATE INDEX IF NOT EXISTS lift_sessions_user_date ON lift_sessions(user, date);
