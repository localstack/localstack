UNAME := $(shell uname -m)
ifeq ($(UNAME),x86_64)
	ARCHITECTURE ?= x86_64
else
	ARCHITECTURE ?= arm64
endif
DOCKER_PLATFORM ?= linux/$(ARCHITECTURE)
# The packaging function architecture is x86_64 by default and needs to be set explicitly for arm64
# https://github.com/aws/aws-extensions-for-dotnet-cli/blob/cdd490450e0407139d49248d94a4a899367e84df/src/Amazon.Lambda.Tools/LambdaDefinedCommandOptions.cs#L111
FUNCTION_ARCHITECTURE ?= $(ARCHITECTURE)

# https://gallery.ecr.aws/sam/build-dotnet6
IMAGE ?= public.ecr.aws/sam/build-dotnet6:1.112.0

build:
	mkdir -p build && \
	docker run --rm --platform=$(DOCKER_PLATFORM) -v $$(pwd)/src:/app -v $$(pwd)/build:/out $(IMAGE) bash -c "mkdir -p /app2 && cp /app/* /app2 && cd /app2 && dotnet lambda package --function-architecture $(FUNCTION_ARCHITECTURE) -o ../out/handler.zip" && \
	cp build/handler.zip handler.zip

clean:
	$(RM) -r build handler.zip

.PHONY: build clean
