-- R3-2: atomic login / share-password rate limiter (see utils/login-limit.ts).
-- OPTIONAL: the table is also created automatically (CREATE TABLE IF NOT EXISTS)
-- the first time the limiter runs, so applying this by hand is not required.
--   wrangler d1 execute <YOUR_DB_NAME> --file=./migrations/0002_login_attempts.sql --remote

CREATE TABLE IF NOT EXISTS login_attempts (
  k            TEXT PRIMARY KEY,         -- sha256 hex of "login_limit:<user>:<ip>" / "share_limit:<id>:<ip>"
  attempts     INTEGER NOT NULL,         -- slots taken in the current window (5 = full)
  window_start INTEGER NOT NULL,         -- unix seconds
  last_attempt INTEGER NOT NULL,         -- unix seconds
  banned_until INTEGER NOT NULL DEFAULT 0 -- unix seconds, 0 = not banned
);
