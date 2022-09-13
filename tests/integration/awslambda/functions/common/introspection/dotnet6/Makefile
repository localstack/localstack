
build:
	mkdir -p build
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out public.ecr.aws/sam/build-dotnet6 bash -c "mkdir -p /app2 && cp /app/* /app2 && cd /app2 && dotnet lambda package -o ../out/handler.zip"
	mv ./build/handler.zip .

.PHONY: build
