UNAME := $(shell uname -m)
ifeq ($(UNAME),x86_64)
	ARCHITECTURE ?= x86_64
else
	ARCHITECTURE ?= arm64
endif

# Target Dotnet framework version
FRAMEWORK ?= net10.0

# Forward build for different Dotnet framework version to avoid code duplication
build:
	cd ../dotnet && $(MAKE) clean build ARCHITECTURE=$(ARCHITECTURE) FRAMEWORK=$(FRAMEWORK)
	mv ../dotnet/handler.zip .

clean:
	$(RM) -rf build handler.zip
	cd ../dotnet && $(MAKE) clean

.PHONY: build clean
