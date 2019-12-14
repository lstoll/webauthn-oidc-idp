.PHONY: all build test zip

all: build test zip apply

build:
	mkdir -p build
	GOOS=linux GOOARCH=amd64 go build -o build/idp ./cmd/idp

test:
	go test ./...

zip: build
	mkdir -p terraform/files
	cd build && zip ../terraform/files/idp.zip idp

apply: zip
	# yolo style.
	cd terraform && \
	terraform apply
