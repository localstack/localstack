# go1.x does not support arm64 architecture: https://docs.aws.amazon.com/lambda/latest/dg/lambda-golang.html
DOCKER_PLATFORM ?= linux/amd64
# Golang EOL overview: https://endoflife.date/go
DOCKER_GOLANG_IMAGE ?= golang:1.19.6

build:
	mkdir -p build && \
	docker run --rm --platform $(DOCKER_PLATFORM) -v $$(pwd)/src:/app -v $$(pwd)/build:/out $(DOCKER_GOLANG_IMAGE) /bin/bash -c "cd /app && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o /out/main main.go && chown $$(id -u):$$(id -g) /out/main"

clean:
	$(RM) -r build handler.zip

.PHONY: build clean
