IMAGE_NAME ?= localstack/localstack
IMAGE_NAME_BASE ?= localstack/java-maven-node-python
IMAGE_TAG ?= $(shell cat localstack/constants.py | grep '^VERSION =' | sed "s/VERSION = ['\"]\(.*\)['\"].*/\1/")
VENV_DIR ?= .venv
VENV_RUN = . $(VENV_DIR)/bin/activate
ADDITIONAL_MVN_ARGS ?= -DskipTests -q
PIP_CMD ?= pip

usage:             ## Show this help
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

install:           ## Install dependencies in virtualenv
	@# TODO: There are currently some issues with pip 10.0.0 -> downgrade to 9.0.3 for now
	(test `which virtualenv` || $(PIP_CMD) install --user virtualenv) && \
		(test -e $(VENV_DIR) || virtualenv $(VENV_OPTS) $(VENV_DIR)) && \
		($(VENV_RUN) && $(PIP_CMD) -q install pip==9.0.3) && \
		(test ! -e requirements.txt || ($(VENV_RUN); $(PIP_CMD) install -q six==1.10.0 ; $(PIP_CMD) -q install -r requirements.txt) && \
		$(VENV_RUN); PYTHONPATH=. exec python localstack/services/install.py testlibs)

install-web:       ## Install npm dependencies for dashboard Web UI
	(cd localstack/dashboard/web && (test ! -e package.json || npm install --silent > /dev/null))

publish:           ## Publish the library to the central PyPi repository
	# build and upload archive
	($(VENV_RUN) && ./setup.py sdist upload)

build-maven:
	cd localstack/ext/java/; mvn -Pfatjar $(ADDITIONAL_MVN_ARGS) clean javadoc:jar source:jar package $(ADDITIONAL_MVN_TARGETS)

publish-maven:     ## Publish artifacts to Maven Central
	ADDITIONAL_MVN_TARGETS=deploy ADDITIONAL_MVN_ARGS=" " make build-maven

coveralls:         ## Publish coveralls metrics
	($(VENV_RUN); coveralls)

init:              ## Initialize the infrastructure, make sure all libs are downloaded
	$(VENV_RUN); PYTHONPATH=. exec python localstack/services/install.py libs

infra:             ## Manually start the local infrastructure for testing
	($(VENV_RUN); exec bin/localstack start)

docker-build:      ## Build Docker image
	docker build -t $(IMAGE_NAME) .
	# remove topmost layer ("make test") from image
	LAST_BUT_ONE_LAYER=`docker history -q $(IMAGE_NAME) | head -n 2 | tail -n 1`; \
		docker tag $$LAST_BUT_ONE_LAYER $(IMAGE_NAME); \
		docker tag $$LAST_BUT_ONE_LAYER $(IMAGE_NAME):$(IMAGE_TAG)

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
	((test "$$DOCKER_USERNAME" = '' || test "$$DOCKER_PASSWORD" = '' ) && \
		echo "Skipping docker push as no credentials are provided.") || \
	(REMOTE_ORIGIN="`git remote -v | grep '/localstack' | grep origin | grep push | awk '{print $$2}'`"; \
		test "$$REMOTE_ORIGIN" != 'https://github.com/localstack/localstack.git' && \
		echo "This is a fork and not the main repo.") || \
	( \
		which $(PIP_CMD) || (wget https://bootstrap.pypa.io/get-pip.py && python get-pip.py); \
		which docker-squash || $(PIP_CMD) install docker-squash; \
		docker info | grep Username || docker login -u $$DOCKER_USERNAME -p $$DOCKER_PASSWORD; \
		BASE_IMAGE_ID=`docker history -q $(IMAGE_NAME):$(IMAGE_TAG) | tail -n 1`; \
		docker-squash -t $(IMAGE_NAME):$(IMAGE_TAG) -f $$BASE_IMAGE_ID $(IMAGE_NAME):$(IMAGE_TAG) && \
			docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):latest; \
		((! (git diff HEAD~1 localstack/constants.py | grep '^+VERSION =') && echo "Only pushing tag 'latest' as version has not changed.") || \
			docker push $(IMAGE_NAME):$(IMAGE_TAG)) && \
		docker push $(IMAGE_NAME):latest \
	)

docker-run:        ## Run Docker image locally
	($(VENV_RUN); bin/localstack start --docker)

docker-mount-run:
	ENTRYPOINT="-v `pwd`/localstack/constants.py:/opt/code/localstack/localstack/constants.py -v `pwd`/localstack/config.py:/opt/code/localstack/localstack/config.py -v `pwd`/localstack/plugins.py:/opt/code/localstack/localstack/plugins.py -v `pwd`/localstack/utils:/opt/code/localstack/localstack/utils -v `pwd`/localstack/services:/opt/code/localstack/localstack/services -v `pwd`/tests:/opt/code/localstack/tests" make docker-run

web:               ## Start web application (dashboard)
	($(VENV_RUN); bin/localstack web)

test:              ## Run automated tests
	make lint && \
		($(VENV_RUN); DEBUG=$(DEBUG) PYTHONPATH=`pwd` nosetests --with-coverage --logging-level=WARNING --nocapture --no-skip --exe --cover-erase --cover-tests --cover-inclusive --cover-package=localstack --with-xunit --exclude='$(VENV_DIR).*' --ignore-files='lambda_python3.py' .)

test-java:         ## Run tests for Java/JUnit compatibility
	cd localstack/ext/java; mvn -q test && USE_SSL=1 mvn -q test

prepare-java-tests-if-changed:
	@(! (git log -n 1 --no-merges --raw | grep localstack/ext/java/)) || (\
		make build-maven && cp $$(ls localstack/ext/java/target/localstack-utils*fat.jar) localstack/infra/localstack-utils-fat.jar && \
			cp $$(ls localstack/ext/java/target/localstack-utils*tests.jar) localstack/infra/localstack-utils-tests.jar && \
			(cd localstack/ext/java; mvn -q clean))

test-java-if-changed:
	@(! (git log -n 1 --no-merges --raw | grep localstack/ext/java/)) || make test-java

test-java-docker:
	ENTRYPOINT="--entrypoint=" CMD="make test-java" make docker-run

test-docker:       ## Run automated tests in Docker
	ENTRYPOINT="--entrypoint=" CMD="make test" make docker-run

test-docker-mount:
	ENTRYPOINT="--entrypoint= -v `pwd`/localstack/constants.py:/opt/code/localstack/localstack/constants.py -v `pwd`/localstack/utils:/opt/code/localstack/localstack/utils -v `pwd`/localstack/services:/opt/code/localstack/localstack/services -v `pwd`/tests:/opt/code/localstack/tests" CMD="make test" make docker-run

reinstall-p2:      ## Re-initialize the virtualenv with Python 2.x
	rm -rf $(VENV_DIR)
	PIP_CMD=pip2 VENV_OPTS="-p '`which python2`'" make install

reinstall-p3:      ## Re-initialize the virtualenv with Python 3.x
	rm -rf $(VENV_DIR)
	PIP_CMD=pip3 VENV_OPTS="-p '`which python3`'" make install

lint:              ## Run code linter to check code style
	($(VENV_RUN); flake8 --inline-quotes=single --show-source --max-line-length=120 --ignore=E128 --exclude=node_modules,$(VENV_DIR)*,dist .)

clean:             ## Clean up (npm dependencies, downloaded infrastructure code, compiled Java classes)
	rm -rf localstack/dashboard/web/node_modules/
	rm -rf localstack/infra/amazon-kinesis-client
	rm -rf localstack/infra/elasticsearch
	rm -rf localstack/infra/elasticmq
	rm -rf localstack/infra/dynamodb
	rm -rf localstack/node_modules/
	rm -rf $(VENV_DIR)
	rm -f localstack/utils/kinesis/java/com/atlassian/*.class

.PHONY: usage compile clean install web install-web infra test
