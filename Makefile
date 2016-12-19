VENV_DIR = .venv
VENV_RUN = . $(VENV_DIR)/bin/activate
AWS_STS_URL = http://central.maven.org/maven2/com/amazonaws/aws-java-sdk-sts/1.11.14/aws-java-sdk-sts-1.11.14.jar
AWS_STS_TMPFILE = /tmp/aws-java-sdk-sts.jar

usage:             ## Show this help
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

install:           ## Install npm/pip dependencies, compile code
	make setup-venv && \
		make install-libs && \
		make compile

setup-venv:
	(test `which virtualenv` || pip install virtualenv || sudo pip install virtualenv)
	(test -e $(VENV_DIR) || virtualenv $(VENV_DIR))
	($(VENV_RUN) && pip install --upgrade pip)
	(test ! -e requirements.txt || ($(VENV_RUN) && pip install -r requirements.txt))

install-libs:      ## Install npm/pip dependencies
	(test -e localstack/infra/amazon-kinesis-client/aws-java-sdk-sts.jar || { (test -e $(AWS_STS_TMPFILE) || curl -o $(AWS_STS_TMPFILE) $(AWS_STS_URL)); mkdir -p localstack/infra/amazon-kinesis-client; cp $(AWS_STS_TMPFILE) localstack/infra/amazon-kinesis-client/aws-java-sdk-sts.jar; }) && \
		(npm install -g npm || sudo npm install -g npm)

install-web:       ## Install npm dependencies for dashboard Web UI
	(cd localstack/dashboard/web && (test ! -e package.json || npm install))

compile:           ## Compile Java code (KCL library utils)
	echo "Compiling"
	$(VENV_RUN); python -c 'from localstack.utils.kinesis import kclipy_helper; print kclipy_helper.get_kcl_classpath()'
	javac -cp $(shell $(VENV_RUN); python -c 'from localstack.utils.kinesis import kclipy_helper; print kclipy_helper.get_kcl_classpath()') localstack/utils/kinesis/java/com/atlassian/*.java
	# TODO enable once we want to support Java-based Lambdas
	# (cd localstack/mock && mvn package)

publish:           ## Publish the library to a PyPi repository
	# build and upload archive
	($(VENV_RUN) && ./setup.py sdist upload)

coveralls:         ## Publish coveralls metrics
	($(VENV_RUN); coveralls)

infra:             ## Manually start the local infrastructure for testing
	($(VENV_RUN); localstack/mock/infra.py)

web:               ## Start web application (dashboard)
	($(VENV_RUN); bin/localstack web --port=8081)

test:              ## Run automated tests
	$(VENV_RUN); PYTHONPATH=`pwd` nosetests --with-coverage --logging-level=WARNING --nocapture --no-skip --exe --cover-erase --cover-tests --cover-inclusive --cover-package=localstack --with-xunit --exclude='$(VENV_DIR).*' . && \
	make lint

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

.PHONY: usage compile clean install web install-web infra test install-libs
