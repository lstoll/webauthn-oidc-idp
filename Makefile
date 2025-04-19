.PHONY: all
all: generate

.PHONY: generate
generate: sqlc

.PHONY: db/schema.sql
db/schema.sql:
	go run ./cmd/schemagen-idp db/schema.sql

.PHONY: sqlc
sqlc: db/schema.sql
	bin/sqlc generate
