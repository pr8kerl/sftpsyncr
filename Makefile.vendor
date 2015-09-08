GOROOT := /usr/local/go
GOPATH := $(shell pwd)
GOBIN  := $(GOPATH)/bin
PATH   := $(GOROOT)/bin:$(PATH)
DEPS   := github.com/mitchellh/cli github.com/pkg/sftp golang.org/x/crypto/ssh golang.org/x/crypto/ssh/agent gopkg.in/gcfg.v1
GO=$(GOROOT)/bin/go

all: sftpsyncr

update: $(DEPS)
	GO15VENDOREXPERIMENT=1 GOPATH=$(GOPATH) go get -u $^

sftpsyncr: main.go config.go push.go send.go
    # always format code
		GO15VENDOREXPERIMENT=1 GOPATH=$(GOPATH) $(GO) fmt $^
    # binary
		GO15VENDOREXPERIMENT=1 GOPATH=$(GOPATH) $(GO) build -o $@ -v $^
		touch $@

windows:
	  gox -os="windows"

.PHONY: $(DEPS) clean

clean:
	rm -f sftpsyncr
	GOPATH=$(GOPATH) $(GO) clean $(GOFLAGS) -i ./...

