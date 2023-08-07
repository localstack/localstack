
build:
	mkdir -p build
	docker run --rm -v $$(pwd)/src:/app -v $$(pwd)/build:/out public.ecr.aws/sam/build-dotnet6@sha256:57666a7fc1723c238a200344eec2fde505e93701e2a19f128bdbb076a03ab927 bash -c "mkdir -p /app2 && cp /app/* /app2 && cd /app2 && dotnet lambda package -o ../out/handler.zip"
	cd build && unzip -d handlertmp ./handler.zip
	find ./build/handlertmp -exec touch -t 200001010100.00 {} \;
	cd build/handlertmp && zip -r handler.zip * && mv handler.zip ../../

.PHONY: build
