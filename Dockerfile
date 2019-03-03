FROM localstack/java-maven-node-python

MAINTAINER Waldemar Hummer (waldemar.hummer@gmail.com)
LABEL authors="Waldemar Hummer (waldemar.hummer@gmail.com), Gianluca Bortoli (giallogiallo93@gmail.com)"

# install basic tools
RUN pip install awscli awscli-local --upgrade

# add files required to run "make install"
ADD Makefile requirements.txt ./
RUN mkdir -p localstack/utils/kinesis/ && mkdir -p localstack/services/ && \
  touch localstack/__init__.py localstack/utils/__init__.py localstack/services/__init__.py localstack/utils/kinesis/__init__.py
ADD localstack/constants.py localstack/config.py localstack/
ADD localstack/services/install.py localstack/services/
ADD localstack/utils/common.py localstack/utils/
ADD localstack/utils/kinesis/ localstack/utils/kinesis/
ADD localstack/ext/ localstack/ext/

# install dependencies
RUN make install

# add files required to run "make init"
ADD localstack/package.json localstack/package.json
ADD localstack/services/__init__.py localstack/services/install.py localstack/services/

# initialize installation (downloads remaining dependencies)
RUN make init

# (re-)install web dashboard dependencies (already installed in base image)
ADD localstack/dashboard/web localstack/dashboard/web
RUN make install-web

# install supervisor config file and entrypoint script
ADD bin/supervisord.conf /etc/supervisord.conf
ADD bin/docker-entrypoint.sh /usr/local/bin/

# expose service & web dashboard ports
EXPOSE 4567-4584 8080

# define command at startup
ENTRYPOINT ["docker-entrypoint.sh"]

# expose default environment (required for aws-cli to work)
ENV MAVEN_CONFIG=/opt/code/localstack \
    USER=localstack \
    PYTHONUNBUFFERED=1

# add rest of the code
ADD localstack/ localstack/
ADD bin/localstack bin/localstack

# fix some permissions and create local user
RUN mkdir -p /.npm && \
    mkdir -p localstack/infra/elasticsearch/data && \
    mkdir -p localstack/infra/elasticsearch/logs && \
    chmod 777 . && \
    chmod 755 /root && \
    chmod -R 777 /.npm && \
    chmod -R 777 localstack/infra/elasticsearch/config && \
    chmod -R 777 localstack/infra/elasticsearch/data && \
    chmod -R 777 localstack/infra/elasticsearch/logs && \
    chmod -R 777 /tmp/localstack && \
    chown -R `id -un`:`id -gn` . && \
    adduser -D localstack && \
    ln -s `pwd` /tmp/localstack_install_dir

# run tests (to verify the build before pushing the image)
ADD tests/ tests/
RUN make test
