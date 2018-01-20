all: test fuzz

test:
	go test ./...

tools:
	go get github.com/dvyukov/go-fuzz/go-fuzz
	go get github.com/dvyukov/go-fuzz/go-fuzz-build

signedvalue-fuzz.zip: tools $(wildcard *.go)
	go-fuzz-build github.com/sashka/signedvalue

fuzz: signedvalue-fuzz.zip
	go-fuzz -bin=$< -workdir=fuzz


.PHONY: test tools fuzz
