
build:
	mkdir -p build
	cp -r ./src/* build/;
	docker run --rm -v "$$(pwd)/src:/app" -v "$$(pwd)/build:/out" public.ecr.aws/sam/build-python3.9@sha256:9b915c0acd9bc84cddb2949af342f3d7d120c70585175c443b32190e58336bbb bash -c "cd /out && mkdir -p build && python -m venv .venv && . ./.venv/bin/activate && pip install --target ./build -r ./requirements.txt && rm -r .venv && mv ./build/* ."
	find ./build -exec touch -t 200001010100.00 {} \;

.PHONY: build
