all: idppb/idp.pb.go

 idppb/idp.pb.go: idp.proto $(GOPATH)/bin/protoc-gen-go
	protoc -I=. --go_out=paths=source_relative:idppb idp.proto

 .PHONY: $(GOPATH)/bin/protoc-gen-go
$(GOPATH)/bin/protoc-gen-go:
	go install ./vendor/github.com/golang/protobuf/protoc-gen-go
