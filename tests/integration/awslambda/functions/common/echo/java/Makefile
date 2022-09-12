# TODO: build via docker
build:
	mkdir build; \
	cp -r ./src/* build/; \
	cd build; \
	gradle packageFat; \
	cp build/distributions/build.zip ../handler.zip


.PHONY: build
