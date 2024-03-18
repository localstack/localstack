UNAME := $(shell uname -m)
ifeq ($(UNAME),x86_64)
	ARCHITECTURE ?= x86_64
else
	ARCHITECTURE ?= arm64
endif
DOCKER_PLATFORM ?= linux/$(ARCHITECTURE)
# GOARCH enables cross-compilation but by default, `go build` selects the right architecture based on the environment
ifeq ($(ARCHITECTURE),arm64)
  GOARCH ?= arm64
else
  GOARCH ?= amd64
endif

# https://hub.docker.com/_/golang/tags
# Golang EOL overview: https://endoflife.date/go
DOCKER_GOLANG_IMAGE ?= golang:1.19.6

build:
	mkdir -p build && \
	docker run --rm --platform $(DOCKER_PLATFORM) -v $$(pwd)/src:/app -v $$(pwd)/build:/out $(DOCKER_GOLANG_IMAGE) /bin/bash -c "cd /app && GOOS=linux GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o /out/bootstrap main.go && chown $$(id -u):$$(id -g) /out/bootstrap"

clean:
	$(RM) -r build handler.zip

.PHONY: build clean
