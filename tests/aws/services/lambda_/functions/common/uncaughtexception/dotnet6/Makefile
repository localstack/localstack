UNAME := $(shell uname -m)
ifeq ($(UNAME),x86_64)
	ARCHITECTURE ?= x86_64
else
	ARCHITECTURE ?= arm64
endif

# Target Dotnet framework version
FRAMEWORK ?= net6.0

# Forward build for different Dotnet framework version to avoid code duplication
build:
	cd ../dotnet && $(MAKE) clean build ARCHITECTURE=$(ARCHITECTURE) FRAMEWORK=$(FRAMEWORK)
	mv ../dotnet/handler.zip .

clean:
	$(RM) -r build handler.zip
	cd ../dotnet && $(MAKE) clean FRAMEWORK=$(FRAMEWORK)

.PHONY: build clean
