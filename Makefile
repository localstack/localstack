IMAGE_NAME ?= atlassianlabs/localstack
IMAGE_TAG ?= $(shell cat setup.py | grep version= | sed "s/.*version=['\"]\(.*\)['\"].*/\1/")
VENV_DIR ?= .venv
VENV_RUN = . $(VENV_DIR)/bin/activate
AWS_STS_URL = http://central.maven.org/maven2/com/amazonaws/aws-java-sdk-sts/1.11.14/aws-java-sdk-sts-1.11.14.jar
AWS_STS_TMPFILE = $(TMPDIR)aws-java-sdk-sts.jar
LOCALSTACK_JAR_URL = https://bitbucket.org/atlassian/localstack/raw/mvn/release/com/atlassian/localstack-utils/1.0-SNAPSHOT/localstack-utils-1.0-SNAPSHOT.jar
LOCALSTACK_JAR_PATH = localstack/infra/localstack-utils.jar
PIP_CMD ?= pip

usage:             ## Show this help
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

install:           ## Install npm/pip dependencies, compile code
	make setup-venv && \
		make install-libs && \
		make compile

setup-venv:        # Setup virtualenv
	(test `which virtualenv` || $(PIP_CMD) install --user virtualenv) && \
		(test -e $(VENV_DIR) || virtualenv $(VENV_OPTS) $(VENV_DIR)) && \
		($(VENV_RUN) && $(PIP_CMD) install --upgrade pip) && \
		(test ! -e requirements.txt || ($(VENV_RUN); $(PIP_CMD) install six==1.10.0 ; $(PIP_CMD) install -r requirements.txt))

install-libs:      ## Install npm/pip dependencies
	(test -e localstack/infra/amazon-kinesis-client/aws-java-sdk-sts.jar || \
			{ (test -e $(AWS_STS_TMPFILE) || curl -o $(AWS_STS_TMPFILE) $(AWS_STS_URL)); \
				mkdir -p localstack/infra/amazon-kinesis-client; \
				cp $(AWS_STS_TMPFILE) localstack/infra/amazon-kinesis-client/aws-java-sdk-sts.jar; }) && \
		(test -e $(LOCALSTACK_JAR_PATH) || curl -o $(LOCALSTACK_JAR_PATH) $(LOCALSTACK_JAR_URL)) && \
		(npm install --silent -g npm > /dev/null || echo "WARNING: Unable to update npm package globally (you may need to check the file permissions of your npm installation)")

install-web:       ## Install npm dependencies for dashboard Web UI
	(cd localstack/dashboard/web && (test ! -e package.json || npm install --silent > /dev/null))

compile:           ## Compile Java code (KCL library utils, Java Lambda executor)
	echo "Compiling"
	javac -cp $(shell $(VENV_RUN); python -c 'from localstack.utils.kinesis import kclipy_helper; print(kclipy_helper.get_kcl_classpath())') localstack/utils/kinesis/java/com/atlassian/*.java
	(test ! -e localstack/ext/java || (cd localstack/ext/java && mvn -q -DskipTests package))

publish:           ## Publish the library to the central PyPi repository
	# build and upload archive
	($(VENV_RUN) && ./setup.py sdist upload)

coveralls:         ## Publish coveralls metrics
	($(VENV_RUN); coveralls)

init:              ## Initialize the infrastructure, make sure all libs are downloaded
	$(VENV_RUN); PYTHONPATH=. exec localstack/mock/install.py run

infra:             ## Manually start the local infrastructure for testing
	($(VENV_RUN); bin/localstack start)

docker-build:      ## Build Docker image
	docker build -t $(IMAGE_NAME) .
	docker tag $(IMAGE_NAME) $(IMAGE_NAME):$(IMAGE_TAG)

docker-push:       ## Push Docker image to registry
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

docker-push-master:## Push Docker image to registry IF we are currently on the master branch
	(test "`git rev-parse --abbrev-ref HEAD`" != 'master' && echo "Not on master branch.") || \
	(test "`git remote -v | grep 'atlassian/localstack.git' | grep origin | grep push | awk '{print $$2}'`" != 'git@bitbucket.org:atlassian/localstack.git' && echo "This is a fork and not the main repo.") || \
		(which $(PIP_CMD) || (wget https://bootstrap.pypa.io/get-pip.py && python get-pip.py); \
		which docker-squash || $(PIP_CMD) install docker-squash; \
		docker info | grep Username || docker login -u $$DOCKER_USERNAME -p $$DOCKER_PASSWORD; \
		docker-squash -t $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):$(IMAGE_TAG) && docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):latest; \
		docker push $(IMAGE_NAME):$(IMAGE_TAG) && docker push $(IMAGE_NAME):latest)

docker-run:        ## Run Docker image locally
	($(VENV_RUN); bin/localstack start --docker)

web:               ## Start web application (dashboard)
	($(VENV_RUN); bin/localstack web --port=8080)

test:              ## Run automated tests
	make lint && \
		$(VENV_RUN); DEBUG=$(DEBUG) PYTHONPATH=`pwd` nosetests --with-coverage --logging-level=WARNING --nocapture --no-skip --exe --cover-erase --cover-tests --cover-inclusive --cover-package=localstack --with-xunit --exclude='$(VENV_DIR).*' .

test-docker:       ## Run automated tests in Docker
	ENTRYPOINT="--entrypoint= -v `pwd`/localstack/utils:/opt/code/localstack/localstack/utils -v `pwd`/localstack/mock:/opt/code/localstack/localstack/mock" CMD="make test" make docker-run

reinstall-p2:      ## Re-initialize the virtualenv with Python 2.x
	rm -rf $(VENV_DIR)
	PIP_CMD=pip2 VENV_OPTS="-p `which python2`" make install

reinstall-p3:      ## Re-initialize the virtualenv with Python 3.x
	rm -rf $(VENV_DIR)
	PIP_CMD=pip3 VENV_OPTS="-p `which python3`" make install

lint:              ## Run code linter to check code style
	($(VENV_RUN); pep8 --max-line-length=120 --ignore=E128 --exclude=node_modules,legacy,$(VENV_DIR),dist .)

clean:             ## Clean up (npm dependencies, downloaded infrastructure code, compiled Java classes)
	rm -rf localstack/dashboard/web/node_modules/
	rm -rf localstack/mock/target/
	rm -rf localstack/infra/amazon-kinesis-client
	rm -rf localstack/infra/elasticsearch
	rm -rf localstack/node_modules/
	rm -rf $(VENV_DIR)
	rm -f localstack/utils/kinesis/java/com/atlassian/*.class
	rm -f $(AWS_STS_TMPFILE)
	rm -f $(TMPDIR)localstack.es.zip

.PHONY: usage compile clean install web install-web infra test install-libs
