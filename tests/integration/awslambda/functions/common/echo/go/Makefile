
build:
	mkdir -p build
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out golang:latest@sha256:b850621230956a6d960d6d7cfaba6a8a2e8e245b230a928ef66aa0cfd065e229 /bin/bash -c "cd /app && GOOS=linux CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o /out/main main.go && chown $$(id -u):$$(id -g) /out/main"
	find ./build -exec touch -t 200001010100.00 {} \;

.PHONY: build
