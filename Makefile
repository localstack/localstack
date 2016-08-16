VENV_DIR = .venv
VENV_RUN = source $(VENV_DIR)/bin/activate
KCL_URL = http://central.maven.org/maven2/com/amazonaws/amazon-kinesis-client/1.6.3/amazon-kinesis-client-1.6.3.jar
ES_URL = https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/zip/elasticsearch/2.3.3/elasticsearch-2.3.3.zip

usage:             ## Show this help
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

install:           ## Install npm/pip dependencies, compile code
	(test `which virtualenv` || pip install virtualenv || sudo pip install virtualenv)
	(test -e $(VENV_DIR) || virtualenv $(VENV_DIR))
	(test ! -e requirements.txt || ($(VENV_RUN) && pip install -r requirements.txt))
	(cd localstack/dashboard/web && (test ! -e package.json || npm install))
	(test -e infra/elasticsearch || { mkdir -p infra; cd infra; curl -o es.zip $(ES_URL); unzip -q es.zip; mv elasticsearch* elasticsearch; rm es.zip; })
	(test -e infra/amazon-kinesis-client/amazon-kinesis-client.jar || { mkdir -p infra/amazon-kinesis-client; curl -o infra/amazon-kinesis-client/amazon-kinesis-client.jar $(KCL_URL); })

install-web:       ## Install npm dependencies for dashboard Web UI
	(cd dashboard/web/ && npm install)

compile:
	javac -cp $(shell $(VENV_RUN); python -c 'from localstack.utils.kinesis import kclipy_helper; print kclipy_helper.get_kcl_classpath()') localstack/utils/kinesis/java/com/atlassian/*.java
	# TODO enable once we want to support Java-based Lambdas
	# (cd localstack/mock && mvn package)

infra:             ## Manually start the local infrastructure for testing
	($(VENV_RUN); localstack/mock/infra.py)

web:               ## Start web application (dashboard)
	($(VENV_RUN); PYTHONPATH=`pwd` localstack/main.py web --port=8081)

test:              ## Run automated tests
	$(VENV_RUN); PYTHONPATH=`pwd` nosetests --with-coverage --logging-level=WARNING --nocapture --no-skip --exe --cover-erase --cover-tests --cover-inclusive --cover-package=localstack --with-xunit --exclude='$(VENV_DIR).*' . && \
	make lint

lint:              ## Run code linter to check code style
	($(VENV_RUN); pep8 --max-line-length=120 --ignore=E128 --exclude=node_modules,legacy,$(VENV_DIR) .)

clean:             ## Clean up (npm dependencies, downloaded infrastructure code, compiled Java classes)
	(cd localstack/dashboard/web/ && rm -rf node_modules/)
	(cd localstack/mock && rm -rf target/)
	rm -f localstack/utils/kinesis/java/com/atlassian/*.class
	rm -rf infra/amazon-kinesis-client infra/elasticsearch
	rm -rf node_modules/

.PHONY: usage compile clean install web install-web infra test
