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
	// {
	// 	Idx: 202006141339,
	// 	SQL: `
	// 		create table checkins (
	// 			id text primary key,
	// 			fsq_raw text,
	// 			fsq_id text unique,
	// 			created_at datetime default (datetime('now'))
	// 		);
	// 		create table people (
	// 			id text primary key,
	// 			firstname text,
	// 			lastname text,
	// 			fsq_id text unique,
	// 			email text, -- unique would be nice, but imports don't have it
	// 			created_at datetime default (datetime('now'))
	// 		);
	// 		-- venue represents a visitable place/business
	// 		create table venues (
	// 			id text primary key,
	// 			name text,
	// 			fsq_id text unique,
	// 			created_at datetime default (datetime('now'))
	// 		);
	// 		-- location represent a physical place
	// 		create table locations (
	// 			id text primary key,
	// 			name text,
	// 			fsq_id text unique,
	// 			created_at datetime default (datetime('now'))
	// 		);
	// 	`,
	// },
}
