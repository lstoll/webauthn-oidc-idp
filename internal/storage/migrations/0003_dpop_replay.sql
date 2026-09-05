CREATE TABLE dpop_replay (
    proof_key BLOB PRIMARY KEY NOT NULL,
    until DATETIME NOT NULL
);

CREATE INDEX idx_dpop_replay_until ON dpop_replay (until);
