.PHONY: all build test scan-safe scan-unsafe scan-html scan-json clean

all: build test

build:
	go build -o planproof main.go

test:
	go test ./... -v

scan-safe:
	./planproof -plan testdata/aws_demo/aws_production_plan.json -config policy.yaml -threshold 50

scan-unsafe:
	./planproof -plan testdata/aws_demo/aws_unsafe_plan.json -config policy.yaml -threshold 50

scan-html:
	-./planproof -plan testdata/aws_demo/aws_unsafe_plan.json -config policy.yaml -output-html report.html

scan-json:
	-./planproof -plan testdata/aws_demo/aws_unsafe_plan.json -config policy.yaml -output-json report.json

clean:
	rm -f planproof report.html report.json report_safe.html report_safe.json
