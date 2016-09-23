VENV_DIR = .venv
VENV_RUN = source $(VENV_DIR)/bin/activate
AWS_STS_URL = http://central.maven.org/maven2/com/amazonaws/aws-java-sdk-sts/1.11.14/aws-java-sdk-sts-1.11.14.jar
ES_URL = https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/zip/elasticsearch/2.3.3/elasticsearch-2.3.3.zip
TMP_ARCHIVE_ES = /tmp/localstack.es.zip

usage:             ## Show this help
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

install:           ## Install npm/pip dependencies, compile code
	(test `which virtualenv` || pip install virtualenv || sudo pip install virtualenv)
	(test -e $(VENV_DIR) || virtualenv $(VENV_DIR))
	($(VENV_RUN) && pip install --upgrade pip)
	(test ! -e requirements.txt || ($(VENV_RUN) && pip install -r requirements.txt))
	(test -e localstack/infra/elasticsearch || { mkdir -p localstack/infra; cd localstack/infra; test -f $(TMP_ARCHIVE_ES) || (curl -o $(TMP_ARCHIVE_ES) $(ES_URL)); cp $(TMP_ARCHIVE_ES) es.zip; unzip -q es.zip; mv elasticsearch* elasticsearch; rm es.zip; })
	(test -e localstack/infra/amazon-kinesis-client/aws-java-sdk-sts.jar || { mkdir -p localstack/infra/amazon-kinesis-client; curl -o localstack/infra/amazon-kinesis-client/aws-java-sdk-sts.jar $(AWS_STS_URL); })
	(npm install -g npm || sudo npm install -g npm)
	(cd localstack/ && (test ! -e package.json || (npm install)))
	make compile
	# make install-web

install-web:       ## Install npm dependencies for dashboard Web UI
	(cd localstack/dashboard/web && (test ! -e package.json || npm install))

compile:           ## Compile Java code (KCL library utils)
	javac -cp $(shell $(VENV_RUN); python -c 'from localstack.utils.kinesis import kclipy_helper; print kclipy_helper.get_kcl_classpath()') localstack/utils/kinesis/java/com/atlassian/*.java
	# TODO enable once we want to support Java-based Lambdas
	# (cd localstack/mock && mvn package)

publish:           ## Publish the library to a PyPi repository
	# build and upload archive
	($(VENV_RUN) && ./setup.py sdist upload)

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
	rm -f $(TMP_ARCHIVE_ES)

.PHONY: usage compile clean install web install-web infra test
