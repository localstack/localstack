# TODO: build via docker
build:
	mkdir -p build && \
	docker run --rm -v "$$(pwd)/src:/app" -v "$$(pwd)/build:/out" openjdk:11-jdk bash -c "mkdir -p /build && cp -r /app/* /build && cd /build && ./gradlew packageFat && cp build/distributions/build.zip /out/handler.zip" && \
	cp build/handler.zip handler.zip


.PHONY: build
