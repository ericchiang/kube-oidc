VERSION ?= $(shell ./scripts/git-version.sh)
LD_FLAGS="-X github.com/ericchiang/kube-oidc/internal/version.gitCommit=$(VERSION)"

.PHONY: build
build: bin/kube-oidc-proxy bin/kube-oidc-login

bin/kube-oidc-proxy: FORCE
	go build -v -ldflags $(LD_FLAGS) -o bin/kube-oidc-proxy ./cmd/kube-oidc-proxy

bin/kube-oidc-login: FORCE
	go build -v -ldflags $(LD_FLAGS) -o bin/kube-oidc-login ./cmd/kube-oidc-login

FORCE:

.PHONY: test
test: bin/golint
	go test -race ./...
	./bin/golint -set_exit_status $(shell go list ./... )
	go vet ./...
	go fmt ./...

.PHONY: vendor
vendor: bin/dep
	./bin/dep ensure -v

bin/dep:
	git clone https://github.com/golang/dep.git _build/src/github.com/golang/dep
	cd _build/src/github.com/golang/dep && git reset --hard tags/v0.4.1
	GOPATH=$(PWD)/_build go build -v -o bin/dep github.com/golang/dep/cmd/dep

bin/golint:
	git clone https://github.com/golang/lint.git _build/src/golang.org/x/lint
	git clone https://github.com/golang/tools.git _build/src/golang.org/x/tools
	GOPATH=$(PWD)/_build go build -v -o bin/golint golang.org/x/lint/golint

bin/cfssl: _build/src/github.com/cloudflare/cfssl
	GOPATH=$(PWD)/_build go build -v -o bin/cfssl github.com/cloudflare/cfssl/cmd/cfssl

bin/cfssljson: _build/src/github.com/cloudflare/cfssl
	GOPATH=$(PWD)/_build go build -v -o bin/cfssljson github.com/cloudflare/cfssl/cmd/cfssljson

_build/src/github.com/cloudflare/cfssl:
	git clone https://github.com/cloudflare/cfssl _build/src/github.com/cloudflare/cfssl
	cd _build/src/github.com/cloudflare/cfssl && git reset --hard tags/1.3.2

# ./scripts/gen-certs.sh doesn't directly reference "bin/cfssl" so users with cfssl can
# run it without going through the makefile
.PHONY: example-certs
example-certs: bin/cfssl bin/cfssljson
	PATH=$(PWD)/bin:$(PATH) ./scripts/gen-certs.sh

.PHONY: clean
clean:
	rm -rf assets
	rm -rf bin
	rm -rf _build
