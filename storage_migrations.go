package main

import (
	"context"
	"database/sql"
)

type migration struct {
	// Idx is a unique identifier for this migration. Datestamp is a good idea
	Idx int64
	// SQL to execute as part of this migration
	SQL string
	// AfterFunc is run inside the migration transaction, if not nil. Runs
	// _after_ the associated SQL is executed. This should be self-contained
	// code, that has no dependencies on application structure to make sure it
	// passes the test of time. It should not commit or rollback the TX, the
	// migration framework will handle that
	AfterFunc func(context.Context, *sql.Tx) error
}

// migrations are run in the order presented here
var migrations = []migration{
	{
		Idx: 202205281754,
		SQL: `
			create table rotatable (
				id text primary key,
				usage text,
				stage text check ( stage in ('next','current','previous') ) not null,
				data text not null,
				current_at datetime, -- when this item should be considered the active item
				previous_at datetime, -- when this item was moved to the previous state
				created_at datetime default current_timestamp not null,
				expires_at datetime not null -- when the item should no longer be used
			);
		`,
	},
	{
		Idx: 202205291345,
		SQL: `
			create table sessions (
				id text primary key,
				oidcstate text not null,
				authentication text,
				expires_at datetime not null,
				created_att default current_timestamp not null
			);
		`,
	},
	{
		Idx: 202205291500,
		SQL: `
			create table users (
				id text primary key,
				email text not null,
				full_name text not null,
				activated integer default 0,
				enrollment_key text,
				created_at default current_timestamp not null
			);
		`,
	},
	{
		Idx: 202205291510,
		SQL: `
			create table webauthn_credentials (
				id text primary key,
				user_id text not null,
				name text not null,
				credential blob not null, -- gob of the duo labs field
				created_at default current_timestamp not null,
				foreign key(user_id) REFERENCES users(id)
			);
		`,
	},
	{
		Idx: 202205301500,
		SQL: `
			create table autocert_cache (
				key text primary key,
				data blob not null,
				created_at default current_timestamp not null,
				created_at default current_timestamp not null,
			);
		`,
	},
}
