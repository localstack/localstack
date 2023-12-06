# https://gallery.ecr.aws/sam/build-dotnet6
IMAGE ?= public.ecr.aws/sam/build-dotnet6:1.103.0

build:
	mkdir -p build && \
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out $(IMAGE) bash -c "mkdir -p /app2 && cp /app/* /app2 && cd /app2 && dotnet lambda package -o ../out/handler.zip" && \
	cp build/handler.zip handler.zip

clean:
	$(RM) -r build handler.zip

.PHONY: build clean
