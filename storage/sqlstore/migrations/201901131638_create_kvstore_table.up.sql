CREATE TABLE kvstore (
    keyspace text NOT NULL,
    key text NOT NULL,
    data bytea,
    expires timestamp with time zone,
    PRIMARY KEY(keyspace, key)
);
