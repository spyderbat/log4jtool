PROJECTNAME := $(shell basename "$(PWD)")
BUILD := $(shell git rev-parse --short HEAD)
VERSION := $(shell if git describe --tags > /dev/null ; then git describe --tags; else echo "devbuild"; fi)
BRANCH := $(shell if git branch --show-current > /dev/null ; then git branch --show-current; else "unknownbranch"; fi)

LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD) "
RLDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD) -X=main.BuildMode=production -s -w"

build: vendor
	export GO111MODULE=on
	cat scripts/version.template | sed 's/$${version}/$(VERSION)/g' > version.json
	go build $(LDFLAGS) -o log4jtool cmd/*
	CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o log4jtool.arm64 cmd/*

releasebuild: vendor
	export GO111MODULE=on
	cat scripts/version.template | sed 's/$${version}/$(VERSION)/g' > version.json
	go build -trimpath $(RLDFLAGS) -o log4jtool cmd/*
	CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 go build -trimpath $(RLDFLAGS) -o log4jtool.arm64 cmd/*


vendor: 
	go mod vendor

checkerrors:
	errcheck cmd/scanner.go

test: vendor
	@echo "Executing tests"
	go test -v -cover

