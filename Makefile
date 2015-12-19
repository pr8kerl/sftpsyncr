GOROOT := /usr/local/go
GOPATH := $(shell pwd)
GOBIN  := $(GOPATH)/bin
PATH   := $(GOROOT)/bin:$(PATH)
DEPS   := github.com/mitchellh/cli github.com/ScriptRock/sftp github.com/ScriptRock/crypto/ssh github.com/ScriptRock/crypto/ssh/agent gopkg.in/gcfg.v1 golang.org/x/crypto/openpgp
GO=$(GOROOT)/bin/go

LDFLAGS := -ldflags "-X main.commit=`git rev-parse HEAD`" 

all: sftpsyncr

update: $(DEPS)
	GOPATH=$(GOPATH) go get -u $^

sftpsyncr: main.go config.go session.go push.go pull.go
    # always format code
		GOPATH=$(GOPATH) $(GO) fmt $^
		# vet it
		GOPATH=$(GOPATH) $(GO) tool vet $^
    # binary
		GOPATH=$(GOPATH) go build $(LDFLAGS) -o $@ -v $^
		touch $@

encrypt: encrypt.go
    # always format code
		GOPATH=$(GOPATH) $(GO) fmt $^
    # binary
		GOPATH=$(GOPATH) $(GO) build -o $@ -v $^
		touch $@

windows:
	  gox -os="windows"

.PHONY: $(DEPS) clean

clean:
	rm -f sftpsyncr
	GOPATH=$(GOPATH) $(GO) clean $(GOFLAGS) -i ./...

