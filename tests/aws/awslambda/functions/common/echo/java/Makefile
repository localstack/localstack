build:
	mkdir -p build && \
	docker run --rm -v "$$(pwd)/src:/app" -v "$$(pwd)/build:/out" gradle:7.5.1-jdk11@sha256:63996737cce3ebb80fe9339f66de489d84cd94874caf268b40b96643b52f22ce bash -c "mkdir -p /build && cp -r /app/* /build && cd /build && gradle packageFat && cp build/distributions/build.zip /out/handler.zip" && \
	cp build/handler.zip handler.zip


.PHONY: build
