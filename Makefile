GOROOT := /usr/local/go
GOPATH := $(shell pwd)
GOBIN  := $(GOPATH)/bin
PATH   := $(GOROOT)/bin:$(PATH)
DEPS   := github.com/mitchellh/cli github.com/ScriptRock/sftp github.com/ScriptRock/crypto/ssh github.com/ScriptRock/crypto/ssh/agent gopkg.in/gcfg.v1 github.com/pr8kerl/crypto/openpgp gopkg.in/gomail.v2
GO=$(GOROOT)/bin/go

LDFLAGS := -ldflags "-X main.commit=`git rev-parse HEAD`" 

all: sftpsyncr

deps: $(DEPS)
	GOPATH=$(GOPATH) go get -u $^

sftpsyncr: main.go config.go session.go push.go pull.go
    # always format code
		GOPATH=$(GOPATH) $(GO) fmt $^
		# vet it
		GOPATH=$(GOPATH) $(GO) tool vet $^
    # binary
		GOPATH=$(GOPATH) go build $(LDFLAGS) -o $@ -v $^
		touch $@

win64: main.go config.go session.go push.go pull.go
    # always format code
		GOPATH=$(GOPATH) $(GO) fmt $^
		# vet it
		GOPATH=$(GOPATH) $(GO) tool vet $^
    # binary
		GOOS=windows GOARCH=amd64 GOPATH=$(GOPATH) go build $(LDFLAGS) -o sftpsyncr-win-amd64.exe -v $^
		touch sftpsyncr-win-amd64.exe

.PHONY: $(DEPS) clean

clean:
	rm -f sftpsyncr
	GOPATH=$(GOPATH) $(GO) clean $(GOFLAGS) -i ./...

