
build:
	mkdir -p build; \
	cp -r ./src/* build/; \
	find ./build -exec touch -t 200001010100.00 {} \;

clean:
	$(RM) -r build
	$(RM) handler.zip

.PHONY: build clean
