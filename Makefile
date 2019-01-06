PATH  := $(PWD)/bin:$(PATH)
SHELL := env PATH=$(PATH) /bin/bash

all: idppb/idp.pb.go webauthn/html.go

idppb/idp.pb.go: idp.proto bin/protoc-gen-go
	protoc -I=. --go_out=paths=source_relative:idppb idp.proto

webauthn/html.go: bin/go-bindata webauthn/webauthn.js webauthn/webauthn.tmpl.html
	go-bindata -pkg webauthn -o webauthn/html.go webauthn/webauthn.js webauthn/webauthn.tmpl.html

bin/protoc-gen-go: vendor/github.com/golang/protobuf/protoc-gen-go
	go build -o bin/protoc-gen-go ./vendor/github.com/golang/protobuf/protoc-gen-go

bin/go-bindata: vendor/github.com/go-bindata/go-bindata/go-bindata
	go build -o bin/go-bindata ./vendor/github.com/go-bindata/go-bindata/go-bindata


