
build:
	mkdir -p build
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out public.ecr.aws/sam/build-dotnetcore3.1@sha256:02e2b6e4bff1c59c2379983bc5fbf521782f1fdb0d4589a36bbfb81c6a59e115 bash -c "mkdir -p /app2 && cp /app/* /app2 && cd /app2 && dotnet lambda package -o ../out/handler.zip"
	cd build && unzip -d handlertmp ./handler.zip
	find ./build/handlertmp -exec touch -t 200001010100.00 {} \;
	cd build/handlertmp && zip -r handler.zip * && mv handler.zip ../../

.PHONY: build
