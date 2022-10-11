
build:
	mkdir build; \
	python -m venv ./build/.venv; \
	. ./build/.venv/bin/activate; \
	cp -r ./src/* build/; \
	pip install --target ./build -r ./build/requirements.txt; \
	deactivate; \
	rm -r ./build/.venv; \
	find ./build -exec touch -t 200001010100.00 {} \;

.PHONY: build
