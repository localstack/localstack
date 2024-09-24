# https://hub.docker.com/_/gradle/tags
IMAGE ?= gradle:8.4.0-jdk17

build:
	mkdir -p build && \
	docker run --rm -v "$$(pwd)/src:/app" -v "$$(pwd)/build:/out" $(IMAGE) bash -c "mkdir -p /build && cp -r /app/* /build && cd /build && gradle packageFat && cp build/distributions/build.zip /out/handler.zip" && \
	cp build/handler.zip handler.zip

clean:
	$(RM) -r build handler.zip

.PHONY: build clean
