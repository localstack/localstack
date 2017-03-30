IMAGE_NAME = gianluca/localstack
VENV_DIR = .venv
VENV_RUN = . $(VENV_DIR)/bin/activate
AWS_STS_URL = http://central.maven.org/maven2/com/amazonaws/aws-java-sdk-sts/1.11.14/aws-java-sdk-sts-1.11.14.jar
AWS_STS_TMPFILE = /tmp/aws-java-sdk-sts.jar

## Show this help
usage:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'
## Install npm/pip dependencies, compile code
install:
	make setup-venv && \
		make install-libs && \
		make compile
## Setup virtualenv
setup-venv:
	(test `which virtualenv` || pip install virtualenv || sudo pip install virtualenv)
	(test -e $(VENV_DIR) || virtualenv $(VENV_DIR))
	($(VENV_RUN) && pip install --upgrade pip)
	(test ! -e requirements.txt || ($(VENV_RUN) && pip install -r requirements.txt))
## Install npm/pip dependencies
install-libs:
	(test -e localstack/infra/amazon-kinesis-client/aws-java-sdk-sts.jar || { (test -e $(AWS_STS_TMPFILE) || curl -o $(AWS_STS_TMPFILE) $(AWS_STS_URL)); mkdir -p localstack/infra/amazon-kinesis-client; cp $(AWS_STS_TMPFILE) localstack/infra/amazon-kinesis-client/aws-java-sdk-sts.jar; }) && \
		(npm install -g npm || sudo npm install -g npm)
## Install npm dependencies for dashboard Web UI
install-web:
	(cd localstack/dashboard/web && (test ! -e package.json || npm install))
## Compile Java code (KCL library utils)
compile:
	echo "Compiling"
	javac -cp $(shell $(VENV_RUN); python -c 'from localstack.utils.kinesis import kclipy_helper; print kclipy_helper.get_kcl_classpath()') localstack/utils/kinesis/java/com/atlassian/*.java
	(test ! -e ext/java || (cd ext/java && mvn -DskipTests package))
	# TODO enable once we want to support Java-based Lambdas
	# (cd localstack/mock && mvn package)
## Publish the library to a PyPi repository
publish:
	# build and upload archive
	($(VENV_RUN) && ./setup.py sdist upload)
## Publish coveralls metrics
coveralls:
	($(VENV_RUN); coveralls)
## Initialize the infrastructure, make sure all libs are downloaded
init:
	$(VENV_RUN); exec localstack/mock/infra.py install

## Manually start the local infrastructure for testing
infra:
	$(VENV_RUN); exec localstack/mock/infra.py

## Build Docker image
docker-build:
	docker build -t $(IMAGE_NAME) .
	docker tag $(IMAGE_NAME) $(IMAGE_NAME):$(shell cat setup.py | grep version= | sed "s/.*version=['\"]\(.*\)['\"].*/\1/")

## Push Docker image to registry
docker-push:
	docker push $(IMAGE_NAME)

## Run Docker image locally
docker-run:
	docker run -it -p 4567-4577:4567-4577 -p 8080:8080 $(IMAGE_NAME)

## Start web application (dashboard)
web:
	($(VENV_RUN); bin/localstack web --port=8080)

## Run automated tests
test:
	$(VENV_RUN); PYTHONPATH=`pwd` nosetests --with-coverage --logging-level=WARNING --nocapture --no-skip --exe --cover-erase --cover-tests --cover-inclusive --cover-package=localstack --with-xunit --exclude='$(VENV_DIR).*' . && \
	make lint

## Run code linter to check code style
lint:
	($(VENV_RUN); pep8 --max-line-length=120 --ignore=E128 --exclude=node_modules,legacy,$(VENV_DIR),dist .)
## Clean up (npm dependencies, downloaded infrastructure code, compiled Java classes)
clean:
	rm -rf localstack/dashboard/web/node_modules/
	rm -rf localstack/mock/target/
	rm -rf localstack/infra/amazon-kinesis-client
	rm -rf localstack/infra/elasticsearch
	rm -rf localstack/node_modules/
	rm -rf $(VENV_DIR)
	rm -f localstack/utils/kinesis/java/com/atlassian/*.class

.PHONY: usage compile clean install web install-web infra test install-libs
