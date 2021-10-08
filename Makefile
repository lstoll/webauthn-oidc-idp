PATH  := $(PWD)/bin:$(PATH)
SHELL := env PATH=$(PATH) /bin/bash

all: idppb/idp.pb.go webauthn/webauthnpb/userstore.pb.go storage/storagepb/storage.pb.go webauthn/html.go \
	storage/sqlstore/migrations/migrations.go

idppb/idp.pb.go: idp.proto bin/protoc-gen-go
	protoc -I=. --go_out=paths=source_relative:idppb idp.proto

webauthn/webauthnpb/userstore.pb.go: webauthn/userstore.proto bin/protoc-gen-go
	cd webauthn && protoc -I=. --go_out=plugins=grpc,paths=source_relative:webauthnpb userstore.proto

storage/storagepb/storage.pb.go: storage/storage.proto bin/protoc-gen-go
	cd storage && protoc -I=. --go_out=plugins=grpc,paths=source_relative:storagepb storage.proto

webauthn/html.go: bin/go-bindata webauthn/webauthn.js webauthn/webauthn.tmpl.html
	go-bindata -pkg webauthn -o webauthn/html.go webauthn/webauthn.js webauthn/webauthn.tmpl.html

storage/sqlstore/migrations/migrations.go: bin/go-bindata storage/sqlstore/migrations/*.sql
	cd storage/sqlstore/migrations && go-bindata -pkg migrations -o migrations.go *.sql

bin/protoc-gen-go: vendor/github.com/golang/protobuf/protoc-gen-go
	go build -o bin/protoc-gen-go ./vendor/github.com/golang/protobuf/protoc-gen-go

bin/go-bindata: vendor/github.com/go-bindata/go-bindata/go-bindata
	go build -o bin/go-bindata ./vendor/github.com/go-bindata/go-bindata/go-bindata
.PHONY: build
build:
	sam build

.PHONY: lint
lint:
	golangci-lint ./...

# assumes that docker-compose is running
.PHONY: run-local
run-local: build
	sam local start-api --env-vars env.json --docker-network lambdaid

.PHONY: create-dynamo-tables
create-dynamo-tables: export AWS_REGION = us-east-1
create-dynamo-tables: export AWS_ACCESS_KEY_ID = defaultkey
create-dynamo-tables: export AWS_SECRET_ACCESS_KEY = defaultsecret
create-dynamo-tables:
	aws dynamodb --endpoint-url http://localhost:8027 create-table --billing-mode PAY_PER_REQUEST --table-name sessions --attribute-definitions AttributeName=session_id,AttributeType=S --key-schema AttributeName=session_id,KeyType=HASH
	aws dynamodb --endpoint-url http://localhost:8027 update-time-to-live --table-name sessions --time-to-live-specification "Enabled=true, AttributeName=expires_at"

.PHONY: miniosync
miniosync: export AWS_REGION = us-east-1
miniosync: export AWS_ACCESS_KEY_ID = defaultkey
miniosync: export AWS_SECRET_ACCESS_KEY = defaultsecret
miniosync:
	-aws s3 --endpoint-url http://localhost:8028 mb s3://lambdaid
	aws s3 --endpoint-url http://localhost:8028 sync devbucket/ s3://lambdaid/
