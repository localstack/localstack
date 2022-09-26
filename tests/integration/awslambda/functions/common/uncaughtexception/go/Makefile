
build:
	mkdir -p build
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out golang:latest /bin/bash -c "cd /app && GOOS=linux CGO_ENABLED=0 go build -o /out/main main.go"
	find ./build -exec touch -t 200001010100.00 {} \;

.PHONY: build
