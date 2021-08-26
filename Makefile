IMAGE_NAME ?= localstack/localstack
IMAGE_NAME_BASE ?= localstack/java-maven-node-python
IMAGE_NAME_LIGHT ?= localstack/localstack-light
IMAGE_NAME_FULL ?= localstack/localstack-full
IMAGE_TAG ?= $(shell cat localstack/__init__.py | grep '^__version__ =' | sed "s/__version__ = ['\"]\(.*\)['\"].*/\1/")
DOCKER_SQUASH ?= --squash
VENV_DIR ?= .venv
PIP_CMD ?= pip
TEST_PATH ?= .
PYTEST_LOGLEVEL ?= warning
MAIN_CONTAINER_NAME ?= localstack_main

ifeq ($(OS), Windows_NT)
	VENV_RUN = . $(VENV_DIR)/Scripts/activate
else
	VENV_RUN = . $(VENV_DIR)/bin/activate
endif

usage:             ## Show this help
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

setup-venv:
	(test `which virtualenv` || $(PIP_CMD) install --user virtualenv) && \
		(test -e $(VENV_DIR) || virtualenv $(VENV_OPTS) $(VENV_DIR))

install-venv:
	make setup-venv && \
		test ! -e requirements.txt || ($(VENV_RUN); $(PIP_CMD) -q install -r requirements.txt)

install-venv-docker: # make install-venv for the docker environment (hack to remove black and isort)
	make setup-venv && \
		test ! -e requirements.txt || \
		($(VENV_RUN);  $(PIP_CMD) install `grep -v '^ *#\|^black\|^isort\|^flake8' requirements.txt | cut -d' ' -f1 | grep .`)

init:              ## Initialize the infrastructure, make sure all libs are downloaded
	$(VENV_RUN); python -m localstack.services.install libs

init-testlibs:
	$(VENV_RUN); python -m localstack.services.install testlibs

install:           ## Install full dependencies in virtualenv
	(make install-venv && make init-testlibs) || exit 1

install-basic:     ## Install basic dependencies for CLI usage in virtualenv
	make setup-venv && \
		($(VENV_RUN); cat requirements.txt | grep -ve '^#' | grep '#\(basic\|extended\)' | sed 's/ #.*//' \
			| xargs $(PIP_CMD) install)

publish:           ## Publish the library to the central PyPi repository
	# build and upload archive
	($(VENV_RUN) && ./setup.py sdist upload)

coveralls:         ## Publish coveralls metrics
	($(VENV_RUN); coveralls)

infra:             ## Manually start the local infrastructure for testing
	($(VENV_RUN); exec bin/localstack start --host)

docker-build:      ## Build Docker image
	# prepare
	test -e 'localstack/infra/stepfunctions/StepFunctionsLocal.jar' || make init
	# start build
	# --add-host: Fix for Centos host OS
	docker build --build-arg LOCALSTACK_BUILD_GIT_HASH=$(shell git rev-parse --short HEAD) \
	  --build-arg=LOCALSTACK_BUILD_DATE=$(shell date -u +"%Y-%m-%d") -t $(IMAGE_NAME) \
	  --add-host="localhost.localdomain:127.0.0.1" $(DOCKER_BUILD_FLAGS) .

docker-squash:
	# squash entire image
	which docker-squash || $(PIP_CMD) install docker-squash; \
		docker-squash -t $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):$(IMAGE_TAG)

docker-build-base:
	docker build $(DOCKER_SQUASH) -t $(IMAGE_NAME_BASE) -f bin/Dockerfile.base .
	docker tag $(IMAGE_NAME_BASE) $(IMAGE_NAME_BASE):$(IMAGE_TAG)
	docker tag $(IMAGE_NAME_BASE):$(IMAGE_TAG) $(IMAGE_NAME_BASE):latest

docker-build-base-ci:
	DOCKER_SQUASH= make docker-build-base
	IMAGE_NAME=$(IMAGE_NAME_BASE) IMAGE_TAG=latest make docker-squash
	docker info | grep Username || docker login -u "$$DOCKER_USERNAME" -p "$$DOCKER_PASSWORD"
	docker push $(IMAGE_NAME_BASE):latest

docker-push:       ## Push Docker image to registry
	make docker-squash
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

docker-push-master:## Push Docker image to registry IF we are currently on the master branch
	(CURRENT_BRANCH=`(git rev-parse --abbrev-ref HEAD | grep '^master$$' || ((git branch -a | grep 'HEAD detached at [0-9a-zA-Z]*)') && git branch -a)) | grep '^[* ]*master$$' | sed 's/[* ]//g' || true`; \
		test "$$CURRENT_BRANCH" != 'master' && echo "Not on master branch.") || \
	((test "$$DOCKER_USERNAME" = '' || test "$$DOCKER_PASSWORD" = '' ) && \
		echo "Skipping docker push as no credentials are provided.") || \
	(REMOTE_ORIGIN="`git remote -v | grep '/localstack' | grep origin | grep push | awk '{print $$2}'`"; \
		test "$$REMOTE_ORIGIN" != 'https://github.com/localstack/localstack.git' && \
		test "$$REMOTE_ORIGIN" != 'git@github.com:localstack/localstack.git' && \
		echo "This is a fork and not the main repo.") || \
	( \
		which $(PIP_CMD) || (wget https://bootstrap.pypa.io/get-pip.py && python get-pip.py); \
		docker info | grep Username || docker login -u $$DOCKER_USERNAME -p $$DOCKER_PASSWORD; \
		IMAGE_TAG=latest make docker-squash && make docker-build-light && \
			docker tag $(IMAGE_NAME):latest $(IMAGE_NAME_FULL):latest && \
			docker tag $(IMAGE_NAME_LIGHT):latest $(IMAGE_NAME):latest && \
		((! (git diff HEAD~1 localstack/__init__.py | grep '^+__version__ =') && \
			echo "Only pushing tag 'latest' as version has not changed.") || \
			(docker tag $(IMAGE_NAME):latest $(IMAGE_NAME):$(IMAGE_TAG) && \
				docker tag $(IMAGE_NAME_FULL):latest $(IMAGE_NAME_FULL):$(IMAGE_TAG) && \
				docker push $(IMAGE_NAME):$(IMAGE_TAG) && docker push $(IMAGE_NAME_LIGHT):$(IMAGE_TAG) && \
				docker push $(IMAGE_NAME_FULL):$(IMAGE_TAG))) && \
		docker push $(IMAGE_NAME):latest && docker push $(IMAGE_NAME_FULL):latest && docker push $(IMAGE_NAME_LIGHT):latest \
	)

docker-run:        ## Run Docker image locally
	($(VENV_RUN); bin/localstack start)

docker-mount-run:
	MOTO_DIR=$$(echo $$(pwd)/.venv/lib/python*/site-packages/moto | awk '{print $$NF}'); echo MOTO_DIR $$MOTO_DIR; \
		ENTRYPOINT="-v `pwd`/localstack/constants.py:/opt/code/localstack/localstack/constants.py -v `pwd`/localstack/config.py:/opt/code/localstack/localstack/config.py -v `pwd`/localstack/plugins.py:/opt/code/localstack/localstack/plugins.py -v `pwd`/localstack/plugin:/opt/code/localstack/localstack/plugin -v `pwd`/localstack/utils:/opt/code/localstack/localstack/utils -v `pwd`/localstack/services:/opt/code/localstack/localstack/services -v `pwd`/localstack/dashboard:/opt/code/localstack/localstack/dashboard -v `pwd`/tests:/opt/code/localstack/tests -v $$MOTO_DIR:/opt/code/localstack/.venv/lib/python3.8/site-packages/moto/" make docker-run

docker-build-lambdas:
	docker build -t localstack/lambda-js:nodejs14.x -f bin/lambda/Dockerfile.nodejs14x .

vagrant-start:
	@vagrant up || EXIT_CODE=$$? ;\
 	if [ "$EXIT_CODE" != "0" ]; then\
 		echo "Predicted error. Ignoring...";\
		vagrant ssh -c "sudo yum install -y epel-release && sudo yum update -y && sudo yum -y install wget perl gcc gcc-c++ dkms kernel-devel kernel-headers make bzip2";\
		vagrant reload --provision;\
	fi

vagrant-stop:
	vagrant halt

docker-build-light:
	@img_name=$(IMAGE_NAME_LIGHT); \
		docker build -t $$img_name -f bin/Dockerfile.light .; \
		IMAGE_NAME=$$img_name IMAGE_TAG=latest make docker-squash; \
		docker tag $$img_name:latest $$img_name:$(IMAGE_TAG)

docker-cp-coverage:
	@echo 'Extracting .coverage file from Docker image'; \
		id=$$(docker create localstack/localstack); \
		docker cp $$id:/opt/code/localstack/.coverage .coverage; \
		docker rm -v $$id

## Run automated tests
test:
	($(VENV_RUN); DEBUG=$(DEBUG) pytest --durations=10 --log-cli-level=$(PYTEST_LOGLEVEL) -s $(PYTEST_ARGS) $(TEST_PATH))

test-coverage:
	($(VENV_RUN); python -m coverage --version; \
		pip install "coverage[toml]>=5.5"; \
		DEBUG=$(DEBUG) \
		python -m coverage run $(COVERAGE_ARGS) -m \
		pytest --durations=10 --log-cli-level=$(PYTEST_LOGLEVEL) -s $(PYTEST_ARGS) $(TEST_PATH))

test-docker:
	ENTRYPOINT="--entrypoint=" CMD="make test" make docker-run

test-docker-mount: ## Run automated tests in Docker (mounting local code)
	ENTRYPOINT="-v `pwd`/tests:/opt/code/localstack/tests" make test-docker-mount-code

test-docker-mount-code:
	MOTO_DIR=$$(echo $$(pwd)/.venv/lib/python*/site-packages/moto | awk '{print $$NF}'); \
	ENTRYPOINT="--entrypoint= -v `pwd`/localstack/config.py:/opt/code/localstack/localstack/config.py -v `pwd`/localstack/constants.py:/opt/code/localstack/localstack/constants.py -v `pwd`/localstack/utils:/opt/code/localstack/localstack/utils -v `pwd`/localstack/services:/opt/code/localstack/localstack/services -v `pwd`/Makefile:/opt/code/localstack/Makefile -v $$MOTO_DIR:/opt/code/localstack/.venv/lib/python3.8/site-packages/moto/ -e TEST_PATH=$(TEST_PATH) -e LAMBDA_JAVA_OPTS=$(LAMBDA_JAVA_OPTS) $(ENTRYPOINT)" CMD="make test" make docker-run

# Note: the ci-* targets below should only be used in CI builds!

ci-pro-smoke-tests:
	which awslocal || pip3 install awscli-local
	which localstack || pip3 install localstack
	DOCKER_FLAGS='-d' SERVICES=lambda,qldb,rds,xray LOCALSTACK_API_KEY=$(TEST_LOCALSTACK_API_KEY) DEBUG=1 localstack start
	docker logs -f $(MAIN_CONTAINER_NAME) &
	for i in 0 1 2 3 4 5 6 7 8 9; do if docker logs $(MAIN_CONTAINER_NAME) | grep 'Ready.'; then break; fi; sleep 3; done
	awslocal qldb list-ledgers
	awslocal rds describe-db-instances
	awslocal xray get-trace-summaries --start-time 2020-01-01 --end-time 2030-12-31
	awslocal lambda list-layers
	docker rm -f $(MAIN_CONTAINER_NAME)

reinstall-p2:      ## Re-initialize the virtualenv with Python 2.x
	rm -rf $(VENV_DIR)
	PIP_CMD=pip2 VENV_OPTS="-p '`which python2`'" make install

reinstall-p3:      ## Re-initialize the virtualenv with Python 3.x
	rm -rf $(VENV_DIR)
	PIP_CMD=pip3 VENV_OPTS="-p '`which python3`'" make install

lint:              ## Run code linter to check code style
	($(VENV_RUN); python -m pflake8 --show-source)

lint-modified:      ## Run code linter on modified files
	($(VENV_RUN); python -m pflake8 --show-source `git ls-files -m | grep '\.py$$' | xargs` )

format:
	($(VENV_RUN); python -m isort localstack tests; python -m black localstack tests )

format-modified:
	($(VENV_RUN); python -m isort `git ls-files -m | grep '\.py$$' | xargs`; python -m black `git ls-files -m | grep '\.py$$' | xargs` )

init-precommit:
	($(VENV_RUN); pre-commit install)

clean:             ## Clean up (npm dependencies, downloaded infrastructure code, compiled Java classes)
	rm -rf localstack/dashboard/web/node_modules/
	rm -rf localstack/infra/amazon-kinesis-client
	rm -rf localstack/infra/elasticsearch
	rm -rf localstack/infra/elasticmq
	rm -rf localstack/infra/dynamodb
	rm -rf localstack/node_modules/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf $(VENV_DIR)
	rm -f localstack/utils/kinesis/java/com/atlassian/*.class

.PHONY: usage compile clean install infra test test-coverage install-venv-docker lint lint-modified format format-modified
