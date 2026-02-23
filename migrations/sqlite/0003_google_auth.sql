ALTER TABLE users ADD COLUMN google_id TEXT;
ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
