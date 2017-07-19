IMAGE_NAME ?= atlassianlabs/localstack
IMAGE_NAME_BASE ?= localstack/java-maven-node-python
IMAGE_TAG ?= $(shell cat localstack/constants.py | grep '^VERSION =' | sed "s/VERSION = ['\"]\(.*\)['\"].*/\1/")
VENV_DIR ?= .venv
VENV_RUN = . $(VENV_DIR)/bin/activate
PIP_CMD ?= pip

usage:             ## Show this help
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

install:           ## Install dependencies in virtualenv
	(test `which virtualenv` || $(PIP_CMD) install --user virtualenv) && \
		(test -e $(VENV_DIR) || virtualenv $(VENV_OPTS) $(VENV_DIR)) && \
		($(VENV_RUN) && $(PIP_CMD) install --upgrade pip) && \
		(test ! -e requirements.txt || ($(VENV_RUN); $(PIP_CMD) install six==1.10.0 ; $(PIP_CMD) install -r requirements.txt))

install-web:       ## Install npm dependencies for dashboard Web UI
	(cd localstack/dashboard/web && (test ! -e package.json || npm install --silent > /dev/null))

publish:           ## Publish the library to the central PyPi repository
	# build and upload archive
	($(VENV_RUN) && ./setup.py sdist upload)

coveralls:         ## Publish coveralls metrics
	($(VENV_RUN); coveralls)

init:              ## Initialize the infrastructure, make sure all libs are downloaded
	$(VENV_RUN); PYTHONPATH=. exec localstack/services/install.py run

infra:             ## Manually start the local infrastructure for testing
	($(VENV_RUN); exec bin/localstack start)

docker-build:      ## Build Docker image
	docker build -t $(IMAGE_NAME) .
	docker tag $(IMAGE_NAME) $(IMAGE_NAME):$(IMAGE_TAG)

docker-build-base:
	docker build -t $(IMAGE_NAME_BASE) -f bin/Dockerfile.base .
	docker tag $(IMAGE_NAME_BASE) $(IMAGE_NAME_BASE):$(IMAGE_TAG)
	which docker-squash || $(PIP_CMD) install docker-squash
	docker-squash -t $(IMAGE_NAME_BASE):$(IMAGE_TAG) $(IMAGE_NAME_BASE):$(IMAGE_TAG)
	docker tag $(IMAGE_NAME_BASE):$(IMAGE_TAG) $(IMAGE_NAME_BASE):latest

docker-push:       ## Push Docker image to registry
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

docker-push-master:## Push Docker image to registry IF we are currently on the master branch
	(CURRENT_BRANCH=`(git rev-parse --abbrev-ref HEAD | grep '^master$$' || ((git branch -a | grep 'HEAD detached at [0-9a-zA-Z]*)') && git branch -a)) | grep '^[* ]*master$$' | sed 's/[* ]//g' || true`; \
		test "$$CURRENT_BRANCH" != 'master' && echo "Not on master branch.") || \
	((test "$$DOCKER_USERNAME" = '' || test "$$DOCKER_PASSWORD" = '' ) && echo "Skipping docker push as no credentials are provided.") || \
	(REMOTE_ORIGIN="`git remote -v | grep '/localstack' | grep origin | grep push | awk '{print $$2}'`"; \
		test "$$REMOTE_ORIGIN" != 'https://github.com/localstack/localstack.git' && echo "This is a fork and not the main repo.") || \
		(which $(PIP_CMD) || (wget https://bootstrap.pypa.io/get-pip.py && python get-pip.py); \
		which docker-squash || $(PIP_CMD) install docker-squash; \
		docker info | grep Username || docker login -u $$DOCKER_USERNAME -p $$DOCKER_PASSWORD; \
		BASE_IMAGE_ID=`docker history -q $(IMAGE_NAME):$(IMAGE_TAG) | tail -n 1`; \
		docker-squash -t $(IMAGE_NAME):$(IMAGE_TAG) -f $$BASE_IMAGE_ID $(IMAGE_NAME):$(IMAGE_TAG) && \
			docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):latest; \
		docker push $(IMAGE_NAME):$(IMAGE_TAG) && docker push $(IMAGE_NAME):latest)

docker-run:        ## Run Docker image locally
	($(VENV_RUN); bin/localstack start --docker)

web:               ## Start web application (dashboard)
	($(VENV_RUN); bin/localstack web --port=8080)

test:              ## Run automated tests
	make lint && \
		($(VENV_RUN); DEBUG=$(DEBUG) PYTHONPATH=`pwd` nosetests --with-coverage --logging-level=WARNING --nocapture --no-skip --exe --cover-erase --cover-tests --cover-inclusive --cover-package=localstack --with-xunit --exclude='$(VENV_DIR).*' .)

test-java:         ## Run tests for Java/JUnit compatibility
	cd localstack/ext/java; mvn test && USE_SSL=1 mvn test

test-docker:       ## Run automated tests in Docker
	ENTRYPOINT="--entrypoint= -v `pwd`/localstack/utils:/opt/code/localstack/localstack/utils -v `pwd`/localstack/services:/opt/code/localstack/localstack/services -v `pwd`/tests:/opt/code/localstack/tests" CMD="make test" make docker-run

reinstall-p2:      ## Re-initialize the virtualenv with Python 2.x
	rm -rf $(VENV_DIR)
	PIP_CMD=pip2 VENV_OPTS="-p `which python2`" make install

reinstall-p3:      ## Re-initialize the virtualenv with Python 3.x
	rm -rf $(VENV_DIR)
	PIP_CMD=pip3 VENV_OPTS="-p `which python3`" make install

lint:              ## Run code linter to check code style
	($(VENV_RUN); pep8 --max-line-length=120 --ignore=E128 --exclude=node_modules,$(VENV_DIR),dist .)

clean:             ## Clean up (npm dependencies, downloaded infrastructure code, compiled Java classes)
	rm -rf localstack/dashboard/web/node_modules/
	rm -rf localstack/infra/amazon-kinesis-client
	rm -rf localstack/infra/elasticsearch
	rm -rf localstack/infra/dynamodb
	rm -rf localstack/node_modules/
	rm -rf $(VENV_DIR)
	rm -f localstack/utils/kinesis/java/com/atlassian/*.class

.PHONY: usage compile clean install web install-web infra test
