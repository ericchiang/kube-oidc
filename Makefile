.PHONY: test
test: bin/golint
	go test ./...
	./bin/golint -set_exit_status $(shell go list ./... )
	go vet ./...
	go fmt ./...

.PHONY: vendor
vendor: bin/dep
	./bin/dep ensure -v

bin/dep:
	git clone https://github.com/golang/dep.git _build/src/github.com/golang/dep
	cd _build/src/github.com/golang/dep && git reset --hard tags/v0.4.1
	GOPATH=$(PWD)/_build go build -o bin/dep github.com/golang/dep/cmd/dep

bin/golint:
	git clone https://github.com/golang/lint.git _build/src/golang.org/x/lint
	git clone https://github.com/golang/tools.git _build/src/golang.org/x/tools
	GOPATH=$(PWD)/_build go build -o bin/golint golang.org/x/lint/golint

.PHONY: clean
clean:
	rm -rf bin
	rm -rf _build
