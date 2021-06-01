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

# add trusted CA certificates to the cert store
RUN curl https://letsencrypt.org/certs/letsencryptauthorityx3.pem.txt >> /etc/ssl/certs/ca-certificates.crt

# install basic tools
RUN pip install awscli awscli-local requests --upgrade
RUN apk add iputils

# add files required to install virtualenv dependencies
ADD Makefile requirements.txt ./
RUN make install-venv

# add files required to run "make init"
RUN mkdir -p localstack/utils/kinesis/ && mkdir -p localstack/services/ && \
  touch localstack/__init__.py localstack/utils/__init__.py localstack/services/__init__.py localstack/utils/kinesis/__init__.py
ADD localstack/constants.py localstack/config.py localstack/
ADD localstack/services/install.py localstack/services/
ADD localstack/services/cloudformation/deployment_utils.py localstack/services/cloudformation/deployment_utils.py
ADD localstack/utils/common.py localstack/utils/bootstrap.py localstack/utils/
ADD localstack/utils/aws/ localstack/utils/aws/
ADD localstack/utils/kinesis/ localstack/utils/kinesis/
ADD localstack/utils/analytics/ localstack/utils/analytics/
ADD localstack/utils/generic/ localstack/utils/generic/
ADD localstack/package.json localstack/package.json
ADD localstack/services/__init__.py localstack/services/install.py localstack/services/

# initialize installation (downloads remaining dependencies)
RUN make init-testlibs
ADD localstack/infra/stepfunctions localstack/infra/stepfunctions
RUN make init

# (re-)install web dashboard dependencies (already installed in base image)
ADD localstack/dashboard/web localstack/dashboard/web
RUN make install-web

# install supervisor config file and entrypoint script
ADD bin/supervisord.conf /etc/supervisord.conf
ADD bin/docker-entrypoint.sh /usr/local/bin/

# expose edge service, ElasticSearch, debugpy & web dashboard ports
EXPOSE 4566 4571 8080 5678

# define command at startup
ENTRYPOINT ["docker-entrypoint.sh"]

# expose default environment (required for aws-cli to work)
ENV MAVEN_CONFIG=/opt/code/localstack \
    USER=localstack \
    PYTHONUNBUFFERED=1

# clean up and prepare for squashing the image
RUN apk del --purge mvn || true
RUN pip uninstall -y awscli boto3 botocore localstack_client idna s3transfer
RUN rm -rf /usr/share/maven .venv/lib/python3.*/site-packages/cfnlint
RUN rm -rf /tmp/* /root/.cache /opt/yarn-* /root/.npm/*cache; mkdir -p /tmp/localstack
RUN ln -s /opt/code/localstack/.venv/bin/aws /usr/bin/aws
ENV PYTHONPATH=/opt/code/localstack/.venv/lib/python3.8/site-packages

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

# Fix for Centos host OS
RUN echo "127.0.0.1 localhost.localdomain" >> /etc/hosts

# run tests (to verify the build before pushing the image)
ADD tests/ tests/
RUN LAMBDA_EXECUTOR=local make test

# clean up temporary files created during test execution
RUN apk del --purge git cmake gcc musl-dev libc-dev; \
    rm -rf /tmp/localstack/*elasticsearch* /tmp/localstack.* tests/ /root/.npm/*cache /opt/terraform /root/.serverless; \
    mkdir /root/.serverless; chmod -R 777 /root/.serverless
