ARG IMAGE_TYPE=full

# java-builder: Stage to build a custom JRE (with jlink)
FROM python:3.10.7-slim-buster@sha256:06d5be98525006c16db0dfdcc7f8d4925107ddad582d634a8a86cc667def06f8 as java-builder
ARG TARGETARCH

# install OpenJDK 11
RUN apt-get update && apt-get install -y openjdk-11-jdk-headless

ENV JAVA_HOME /usr/lib/jvm/java-11-openjdk-${TARGETARCH}

# create a custom, minimized JRE via jlink
RUN jlink --add-modules \
# include required modules
java.base,java.desktop,java.instrument,java.management,java.naming,java.scripting,java.sql,java.xml,jdk.compiler,\
# jdk.unsupported contains sun.misc.Unsafe which is required by certain dependencies
jdk.unsupported,\
# add additional cipher suites
jdk.crypto.cryptoki,\
# add ability to open ZIP/JAR files
jdk.zipfs,\
# OpenSearch needs some jdk modules
jdk.httpserver,jdk.management,\
# MQ Broker requires management agent
jdk.management.agent,\
# Elasticsearch 7+ crashes without Thai Segmentation support
jdk.localedata --include-locales en,th \
    --compress 2 --strip-debug --no-header-files --no-man-pages --output /usr/lib/jvm/java-11 && \
  cp ${JAVA_HOME}/bin/javac /usr/lib/jvm/java-11/bin/javac && \
  cp -r ${JAVA_HOME}/include /usr/lib/jvm/java-11/include && \
  mv /usr/lib/jvm/java-11/lib/modules /usr/lib/jvm/java-11/lib/modules.bk; \
  cp -r ${JAVA_HOME}/lib/* /usr/lib/jvm/java-11/lib/; \
  mv /usr/lib/jvm/java-11/lib/modules.bk /usr/lib/jvm/java-11/lib/modules; \
  rm -rf /usr/bin/java ${JAVA_HOME} && ln -s /usr/lib/jvm/java-11/bin/java /usr/bin/java



# base: Stage which installs necessary runtime dependencies (OS packages, java, maven,...)
FROM python:3.10.7-slim-buster@sha256:06d5be98525006c16db0dfdcc7f8d4925107ddad582d634a8a86cc667def06f8 as base
ARG TARGETARCH

# Install runtime OS package dependencies
RUN apt-get update && \
        # Install dependencies to add additional repos
        apt-get install -y --no-install-recommends ca-certificates curl && \
        # Setup Node 18 Repo
        curl -sL https://deb.nodesource.com/setup_18.x | bash - && \
        # Install Packages
        apt-get update && \
        apt-get install -y --no-install-recommends \
            # Runtime packages (groff-base is necessary for AWS CLI help)
            git make openssl tar pixz zip unzip groff-base iputils-ping nss-passwords \
            # Postgres
            postgresql postgresql-client postgresql-plpython3 \
            # NodeJS
            nodejs && \
        apt-get clean && rm -rf /var/lib/apt/lists/*

SHELL [ "/bin/bash", "-c" ]

# Install Java 11
ENV LANG C.UTF-8
RUN { \
        echo '#!/bin/sh'; echo 'set -e'; echo; \
        echo 'dirname "$(dirname "$(readlink -f "$(which javac || which java)")")"'; \
    } > /usr/local/bin/docker-java-home \
    && chmod +x /usr/local/bin/docker-java-home
COPY --from=java-builder /usr/lib/jvm/java-11 /usr/lib/jvm/java-11
COPY --from=java-builder /etc/ssl/certs/java /etc/ssl/certs/java
COPY --from=java-builder /etc/java-11-openjdk/security /etc/java-11-openjdk/security
RUN ln -s /usr/lib/jvm/java-11/bin/java /usr/bin/java
ENV JAVA_HOME /usr/lib/jvm/java-11
ENV PATH "${PATH}:${JAVA_HOME}/bin"

# Install Maven - taken from official repo:
# https://github.com/carlossg/docker-maven/blob/master/openjdk-11/Dockerfile)
ARG MAVEN_VERSION=3.6.3
ARG USER_HOME_DIR="/root"
ARG MAVEN_SHA=26ad91d751b3a9a53087aefa743f4e16a17741d3915b219cf74112bf87a438c5
ARG MAVEN_BASE_URL=https://apache.osuosl.org/maven/maven-3/${MAVEN_VERSION}/binaries
RUN mkdir -p /usr/share/maven /usr/share/maven/ref \
  && curl -fsSL -o /tmp/apache-maven.tar.gz ${MAVEN_BASE_URL}/apache-maven-$MAVEN_VERSION-bin.tar.gz \
  && echo "${MAVEN_SHA}  /tmp/apache-maven.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1 \
  && rm -f /tmp/apache-maven.tar.gz \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn
ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"
ADD https://raw.githubusercontent.com/carlossg/docker-maven/9d82eaf48ee8b14ac15a36c431ba28b735e99c92/openjdk-11/settings-docker.xml /usr/share/maven/ref/

# set workdir
RUN mkdir -p /opt/code/localstack
WORKDIR /opt/code/localstack/

# create filesystem hierarchy
RUN mkdir -p /var/lib/localstack && \
    mkdir -p /usr/lib/localstack
# backwards compatibility with LEGACY_DIRECTORIES (TODO: deprecate and remove)
RUN mkdir -p /opt/code/localstack/localstack && \
    ln -s /usr/lib/localstack /opt/code/localstack/localstack/infra && \
    mkdir /tmp/localstack && \
    chmod -R 777 /tmp/localstack && \
    touch /tmp/localstack/.marker && \
    chmod -R 777 /usr/lib/localstack

# install basic (global) tools to final image
RUN pip install --no-cache-dir --upgrade supervisor virtualenv

# install supervisor config file and entrypoint script
ADD bin/supervisord.conf /etc/supervisord.conf
ADD bin/docker-entrypoint.sh /usr/local/bin/
# add the shipped hosts file to prevent performance degredation in windows container mode on windows
# (where hosts file is not mounted) See https://github.com/localstack/localstack/issues/5178
ADD bin/hosts /etc/hosts

# expose default environment
# Set edge bind host so localstack can be reached by other containers
# set library path and default LocalStack hostname
ENV MAVEN_CONFIG=/opt/code/localstack
ENV LD_LIBRARY_PATH=/usr/lib/jvm/java-11/lib:/usr/lib/jvm/java-11/lib/server
ENV USER=localstack
ENV PYTHONUNBUFFERED=1
ENV EDGE_BIND_HOST=0.0.0.0
ENV LOCALSTACK_HOSTNAME=localhost

RUN mkdir /root/.serverless; chmod -R 777 /root/.serverless



# builder: Stage which installs/builds the dependencies and infra-components of LocalStack
FROM base as builder
ARG TARGETARCH

# Install build dependencies to base
RUN apt-get update && apt-get install -y autoconf automake cmake libsasl2-dev \
        g++ gcc libffi-dev libkrb5-dev libssl-dev \
        postgresql-server-dev-11 libpq-dev

# Install timescaledb into postgresql
RUN (cd /tmp && git clone https://github.com/timescale/timescaledb.git) && \
    (cd /tmp/timescaledb && git checkout 2.3.1 && ./bootstrap -DREGRESS_CHECKS=OFF && \
      cd build && make && make install)

# init environment and cache some dependencies
ARG DYNAMODB_ZIP_URL=https://s3-us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.zip
RUN mkdir -p /usr/lib/localstack/dynamodb && \
      curl -L -o /tmp/localstack.ddb.zip ${DYNAMODB_ZIP_URL} && \
      (cd /usr/lib/localstack/dynamodb && unzip -q /tmp/localstack.ddb.zip && rm /tmp/localstack.ddb.zip)

# upgrade python build tools
RUN (virtualenv .venv && . .venv/bin/activate && pip3 install --upgrade pip wheel setuptools)

# add files necessary to install all dependencies
ADD Makefile setup.py setup.cfg pyproject.toml ./
# add the root package init to invalidate docker layers with version bumps
ADD localstack/__init__.py localstack/
# add the localstack start scripts (necessary for the installation of the runtime dependencies, i.e. `pip install -e .`)
ADD bin/localstack bin/localstack.bat bin/

# install dependencies to run the localstack runtime and save which ones were installed
RUN make install-runtime
RUN make freeze > requirements-runtime.txt
# link the extensions virtual environment into the localstack venv
RUN echo /var/lib/localstack/lib/extensions/python_venv/lib/python3.10/site-packages > localstack-extensions-venv.pth && \
    mv localstack-extensions-venv.pth .venv/lib/python*/site-packages/



# base-light: Stage which does not add additional dependencies (like elasticsearch)
FROM base as base-light
RUN touch /usr/lib/localstack/.light-version



# base-full: Stage which adds additional dependencies to avoid installing them at runtime (f.e. elasticsearch)
FROM base as base-full

# Install Elasticsearch
# https://github.com/pires/docker-elasticsearch/issues/56
ENV ES_TMPDIR /tmp

ENV ES_BASE_DIR=/usr/lib/localstack/elasticsearch/Elasticsearch_7.10
ENV ES_JAVA_HOME /usr/lib/jvm/java-11
RUN TARGETARCH_SYNONYM=$([[ "$TARGETARCH" == "amd64" ]] && echo "x86_64" || echo "aarch64"); \
    curl -L -o /tmp/localstack.es.tar.gz \
        https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.10.0-linux-${TARGETARCH_SYNONYM}.tar.gz && \
    (cd /tmp && tar -xf localstack.es.tar.gz && \
        mkdir -p $ES_BASE_DIR && mv elasticsearch*/* $ES_BASE_DIR && rm /tmp/localstack.es.tar.gz) && \
    (cd $ES_BASE_DIR && \
        bin/elasticsearch-plugin install analysis-icu && \
        bin/elasticsearch-plugin install ingest-attachment --batch && \
        bin/elasticsearch-plugin install analysis-kuromoji && \
        bin/elasticsearch-plugin install mapper-murmur3 && \
        bin/elasticsearch-plugin install mapper-size && \
        bin/elasticsearch-plugin install analysis-phonetic && \
        bin/elasticsearch-plugin install analysis-smartcn && \
        bin/elasticsearch-plugin install analysis-stempel && \
        bin/elasticsearch-plugin install analysis-ukrainian) && \
    ( rm -rf $ES_BASE_DIR/jdk/ ) && \
    ( mkdir -p $ES_BASE_DIR/data && \
        mkdir -p $ES_BASE_DIR/logs && \
        chmod -R 777 $ES_BASE_DIR/config && \
        chmod -R 777 $ES_BASE_DIR/data && \
        chmod -R 777 $ES_BASE_DIR/logs) && \
    ( rm -rf $ES_BASE_DIR/modules/x-pack-ml/platform && \
        rm -rf $ES_BASE_DIR/modules/ingest-geoip)



# light: Stage which produces a final working localstack image (which does not contain some additional infrastructure like eleasticsearch - see "full" stage)
FROM base-${IMAGE_TYPE}

LABEL authors="LocalStack Contributors"
LABEL maintainer="LocalStack Team (info@localstack.cloud)"
LABEL description="LocalStack Docker image"

# Copy the build dependencies
COPY --from=builder /opt/code/localstack/ /opt/code/localstack/

# Copy in postgresql extensions
COPY --from=builder /usr/share/postgresql/11/extension /usr/share/postgresql/11/extension
COPY --from=builder /usr/lib/postgresql/11/lib /usr/lib/postgresql/11/lib

RUN if [ -e /usr/bin/aws ]; then mv /usr/bin/aws /usr/bin/aws.bk; fi; ln -s /opt/code/localstack/.venv/bin/aws /usr/bin/aws

# fix some permissions and create local user
RUN mkdir -p /.npm && \
    chmod 777 . && \
    chmod 755 /root && \
    chmod -R 777 /.npm && \
    chmod -R 777 /var/lib/localstack && \
    useradd -ms /bin/bash localstack && \
    ln -s `pwd` /tmp/localstack_install_dir

# Install the latest version of awslocal globally
RUN pip3 install --upgrade awscli awscli-local requests

# Add the code in the last step
ADD localstack/ localstack/

# Download some more dependencies (make init needs the LocalStack code)
# FIXME the init python code should be independent (i.e. not depend on the localstack code), idempotent/reproducible,
#       modify only folders outside of the localstack package folder, and executed in the builder stage.
RUN make init

# Install the latest version of localstack-ext and generate the plugin entrypoints.
# If this is a pre-release build, also include dev releases of these packages.
ARG LOCALSTACK_PRE_RELEASE=1
RUN (PIP_ARGS=$([[ "$LOCALSTACK_PRE_RELEASE" == "1" ]] && echo "--pre" || true); \
      virtualenv .venv && . .venv/bin/activate && \
      pip3 install --upgrade ${PIP_ARGS} localstack-ext[runtime])
RUN make entrypoints

# Add the build date and git hash at last (changes everytime)
ARG LOCALSTACK_BUILD_DATE
ARG LOCALSTACK_BUILD_GIT_HASH
ARG LOCALSTACK_BUILD_VERSION
ENV LOCALSTACK_BUILD_DATE=${LOCALSTACK_BUILD_DATE}
ENV LOCALSTACK_BUILD_GIT_HASH=${LOCALSTACK_BUILD_GIT_HASH}
ENV LOCALSTACK_BUILD_VERSION=${LOCALSTACK_BUILD_VERSION}

# clean up some libs (e.g., Maven should be no longer required after "make init" has completed)
RUN rm -rf /usr/share/maven

# expose edge service, external service ports, and debugpy
EXPOSE 4566 4510-4559 5678

HEALTHCHECK --interval=10s --start-period=15s --retries=5 --timeout=5s CMD ./bin/localstack status services --format=json

# default volume directory
VOLUME /var/lib/localstack

# define command at startup
ENTRYPOINT ["docker-entrypoint.sh"]
