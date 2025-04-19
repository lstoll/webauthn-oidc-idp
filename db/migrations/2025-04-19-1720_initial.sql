CREATE TABLE tink_keysets (
    id TEXT PRIMARY KEY,
    keyset_data BLOB NOT NULL,
    metadata_data BLOB NOT NULL,
    version INTEGER NOT NULL
);
