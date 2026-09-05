ALTER TABLE pending_enrollments DROP COLUMN confirmation_key;
ALTER TABLE pending_enrollments DROP COLUMN credential_id;
ALTER TABLE pending_enrollments DROP COLUMN credential_data;
ALTER TABLE pending_enrollments DROP COLUMN name;
ALTER TABLE pending_enrollments ADD COLUMN expires_at DATETIME;
UPDATE pending_enrollments SET expires_at = datetime(created_at, '+15 minutes') WHERE expires_at IS NULL;
CREATE INDEX idx_pending_enrollments_expires_at ON pending_enrollments (expires_at);
