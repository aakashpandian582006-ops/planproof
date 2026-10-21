.PHONY: all build test scan-safe scan-unsafe clean

all: build test

build:
	go build -o planproof main.go

test:
	go test ./... -v

scan-safe:
	./planproof -plan testdata/aws_demo/aws_production_plan.json -threshold 50

scan-unsafe:
	./planproof -plan testdata/aws_demo/aws_unsafe_plan.json -threshold 50

clean:
	rm -f planproof
