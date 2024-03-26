UNAME := $(shell uname -m)
ifeq ($(UNAME),x86_64)
	ARCHITECTURE ?= x86_64
else
	ARCHITECTURE ?= arm64
endif
# The packaging function architecture is x86_64 by default and needs to be set explicitly for arm64
# https://github.com/aws/aws-extensions-for-dotnet-cli/blob/cdd490450e0407139d49248d94a4a899367e84df/src/Amazon.Lambda.Tools/LambdaDefinedCommandOptions.cs#L111
FUNCTION_ARCHITECTURE ?= $(ARCHITECTURE)

# Target Dotnet framework version
FRAMEWORK ?= net8.0
# Workaround for a Docker race condition causing an I/O error upon zipping to /out/handler.zip if
# two builds are executed in short succession. Example: `make -C dotnet build && make -C dotnet6 build`
BUILD_DIR ?= build-$(FRAMEWORK)

# https://gallery.ecr.aws/sam/build-dotnet8
IMAGE ?= public.ecr.aws/sam/build-dotnet8:1.112.0

# Emulated builds with Dotnet8 are currently (2024-03-19) broken as discussed in many issues:
# https://github.com/NuGet/Home/issues/12227
# https://github.com/dotnet/runtime/issues/78340
# https://github.com/dotnet/msbuild/issues/8508
# Root cause QEMU issue: https://gitlab.com/qemu-project/qemu/-/issues/249
# Workaround: Instead of emulating the build (works for Dotnet6), we use the native Docker image
#		      and cross-build the Dotnet package using the flag `--function-architecture` (x86_64 or arm64).

build:
	mkdir -p $(BUILD_DIR) && \
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/$(BUILD_DIR):/out $(IMAGE) bash -c "mkdir -p /app2 && cp /app/* /app2 && cd /app2 && dotnet lambda package --framework $(FRAMEWORK) --function-architecture $(FUNCTION_ARCHITECTURE) -o ../out/handler.zip" && \
	cp $(BUILD_DIR)/handler.zip handler.zip

clean:
	$(RM) -r $(BUILD_DIR) handler.zip

.PHONY: build clean
