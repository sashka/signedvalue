all: test fuzz

.PHONY: test
test:
	go test ./...

.PHONY: tools
tools:
	go get github.com/dvyukov/go-fuzz/go-fuzz
	go get github.com/dvyukov/go-fuzz/go-fuzz-build

.PHONY: fuzz
fuzz: signedvalue-fuzz.zip
	go-fuzz -bin=$< -workdir=fuzz


signedvalue-fuzz.zip: tools $(wildcard *.go)
	go-fuzz-build github.com/sashka/signedvalue

