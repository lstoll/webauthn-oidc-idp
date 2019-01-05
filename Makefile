all: idppb/idp.pb.go bin/example-app

 idppb/idp.pb.go: idp.proto $(GOPATH)/bin/protoc-gen-go
	protoc -I=. --go_out=paths=source_relative:idppb idp.proto

 .PHONY: $(GOPATH)/bin/protoc-gen-go
$(GOPATH)/bin/protoc-gen-go:
	go install ./vendor/github.com/golang/protobuf/protoc-gen-go

bin/example-app: vendor/github.com/dexidp/dex/cmd/example-app
	go build -o bin/example-app ./vendor/github.com/dexidp/dex/cmd/example-app