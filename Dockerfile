FROM localstack/java-maven-node-python

MAINTAINER Waldemar Hummer (waldemar.hummer@gmail.com)
LABEL authors="LocalStack Contributors"

ARG LOCALSTACK_BUILD_DATE
ARG LOCALSTACK_BUILD_GIT_HASH

ENV LOCALSTACK_BUILD_DATE=${LOCALSTACK_BUILD_DATE}
ENV LOCALSTACK_BUILD_GIT_HASH=${LOCALSTACK_BUILD_GIT_HASH}

# set library path and default LocalStack hostname
ENV LD_LIBRARY_PATH=/usr/lib/jvm/java-11/lib:/usr/lib/jvm/java-11/lib/server
ENV LOCALSTACK_HOSTNAME=localhost

# Set edge bind host so localstack can be reached by other containers
ENV EDGE_BIND_HOST=0.0.0.0

# add trusted CA certificates to the cert store
RUN curl https://letsencrypt.org/certs/letsencryptauthorityx3.pem.txt >> /etc/ssl/certs/ca-certificates.crt

# install basic tools
RUN pip install awscli awscli-local requests --upgrade
RUN apk add iputils

# add files required to install virtualenv dependencies
ADD Makefile requirements.txt ./
RUN make install-venv-docker

# add files required to run "make init"
RUN mkdir -p localstack/utils/kinesis/ && mkdir -p localstack/services/ && \
  touch localstack/__init__.py localstack/utils/__init__.py localstack/services/__init__.py localstack/utils/kinesis/__init__.py
ADD localstack/__init__.py localstack/constants.py localstack/config.py localstack/
ADD localstack/services/awslambda localstack/services/awslambda
ADD localstack/plugin/ localstack/plugin/
ADD localstack/services/install.py localstack/services/generic_proxy.py localstack/services/__init__.py localstack/services/
ADD localstack/services/cloudformation/deployment_utils.py localstack/services/cloudformation/deployment_utils.py
ADD localstack/utils/ localstack/utils/
ADD localstack/package.json localstack/package.json

# initialize installation (downloads remaining dependencies)
RUN make init-testlibs
ADD localstack/infra/stepfunctions localstack/infra/stepfunctions
RUN make init

# install supervisor config file and entrypoint script
ADD bin/supervisord.conf /etc/supervisord.conf
ADD bin/docker-entrypoint.sh /usr/local/bin/

# expose edge service, ElasticSearch & debugpy ports
EXPOSE 4566 4571 5678

# define command at startup
ENTRYPOINT ["docker-entrypoint.sh"]

# expose default environment
ENV MAVEN_CONFIG=/opt/code/localstack \
    USER=localstack \
    PYTHONUNBUFFERED=1

# clean up and prepare for squashing the image
RUN apk del --purge mvn || true
RUN pip uninstall -y awscli boto3 botocore localstack_client idna s3transfer
RUN rm -rf /usr/share/maven .venv/lib/python3.*/site-packages/cfnlint
RUN rm -rf /tmp/* /root/.cache /opt/yarn-* /root/.npm/*cache; mkdir -p /tmp/localstack
RUN if [ -e /usr/bin/aws ]; then mv /usr/bin/aws /usr/bin/aws.bk; fi; ln -s /opt/code/localstack/.venv/bin/aws /usr/bin/aws

# set up PYTHONPATH (after global pip packages are removed above), accommodating different install paths
ENV PYTHONPATH=/opt/code/localstack/.venv/lib/python3.8/site-packages:/opt/code/localstack/.venv/lib/python3.7/site-packages
RUN which awslocal

# add rest of the code
ADD localstack/ localstack/
ADD bin/localstack bin/localstack

# fix some permissions and create local user
RUN ES_BASE_DIR=localstack/infra/elasticsearch; \
    mkdir -p /.npm && \
    mkdir -p $ES_BASE_DIR/data && \
    mkdir -p $ES_BASE_DIR/logs && \
    chmod 777 . && \
    chmod 755 /root && \
    chmod -R 777 /.npm && \
    chmod -R 777 $ES_BASE_DIR/config && \
    chmod -R 777 $ES_BASE_DIR/data && \
    chmod -R 777 $ES_BASE_DIR/logs && \
    chmod -R 777 /tmp/localstack && \
    adduser -D localstack && \
    chown -R localstack:localstack . /tmp/localstack && \
    ln -s `pwd` /tmp/localstack_install_dir

# run tests (to verify the build before pushing the image)
ADD tests/ tests/
# add configuration files
ADD pyproject.toml ./
# fixes a dependency issue with pytest and python3.7 https://github.com/pytest-dev/pytest/issues/5594
RUN pip uninstall -y argparse
RUN pip uninstall -y dataclasses
RUN LAMBDA_EXECUTOR=local \
    PYTEST_LOGLEVEL=info \
    PYTEST_ARGS='--junitxml=target/test-report.xml' \
    TEST_PATH=tests/integration/test_cloudformation.py \
    make test-coverage

# clean up temporary files created during test execution
RUN apk del --purge git cmake gcc musl-dev libc-dev; \
    rm -rf /tmp/localstack/*elasticsearch* /tmp/localstack.* tests/ /root/.npm/*cache /opt/terraform /root/.serverless; \
    mkdir /root/.serverless; chmod -R 777 /root/.serverless
