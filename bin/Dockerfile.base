FROM node:alpine

MAINTAINER Waldemar Hummer (waldemar.hummer@gmail.com)
LABEL authors="Waldemar Hummer (waldemar.hummer@gmail.com)"

# install some common libs
RUN apk add --no-cache autoconf automake build-base ca-certificates curl g++ gcc git groff \
        libffi-dev libtool linux-headers make openssl openssl-dev python3 python3-dev \
        py3-pip tar xz zip && \
    update-ca-certificates

# install Docker (CLI only)
RUN docker_version=17.05.0-ce; \
  curl -fsSLO https://get.docker.com/builds/Linux/x86_64/docker-$docker_version.tgz \
  && tar xzvf docker-$docker_version.tgz \
  && mv docker/docker /usr/local/bin \
  && rm -r docker docker-$docker_version.tgz

# Install Java - taken from official repo:
# https://github.com/docker-library/openjdk/blob/master/8-jdk/alpine/Dockerfile)
ENV LANG C.UTF-8
RUN { \
        echo '#!/bin/sh'; echo 'set -e'; echo; \
        echo 'dirname "$(dirname "$(readlink -f "$(which javac || which java)")")"'; \
    } > /usr/local/bin/docker-java-home \
    && chmod +x /usr/local/bin/docker-java-home
ENV JAVA_HOME /usr/lib/jvm/java-1.8-openjdk
ENV PATH $PATH:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin
RUN set -x && apk add --no-cache openjdk8 && [ "$JAVA_HOME" = "$(docker-java-home)" ]
RUN apk add --no-cache nss

# Install Maven - taken from official repo:
# https://github.com/carlossg/docker-maven/blob/master/jdk-8/Dockerfile)
ARG MAVEN_VERSION=3.5.4
ARG USER_HOME_DIR="/root"
ARG SHA=ce50b1c91364cb77efe3776f756a6d92b76d9038b0a0782f7d53acf1e997a14d
ARG BASE_URL=https://apache.osuosl.org/maven/maven-3/${MAVEN_VERSION}/binaries
RUN mkdir -p /usr/share/maven /usr/share/maven/ref \
  && curl -fsSL -o /tmp/apache-maven.tar.gz ${BASE_URL}/apache-maven-$MAVEN_VERSION-bin.tar.gz \
  && echo "${SHA}  /tmp/apache-maven.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1 \
  && rm -f /tmp/apache-maven.tar.gz \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn
ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"
ADD https://raw.githubusercontent.com/carlossg/docker-maven/master/jdk-8/settings-docker.xml /usr/share/maven/ref/

# set workdir
RUN mkdir -p /opt/code/localstack
WORKDIR /opt/code/localstack/

# https://github.com/pires/docker-elasticsearch/issues/56
ENV ES_TMPDIR  /tmp

# install npm dependencies (Note: node-gyp currently requires python2 :/ , hence install it temporarily)
RUN apk add python2
ADD localstack/package.json localstack/package.json
RUN cd localstack && npm install
RUN apk del python2

# set python3 as default python version; install supervisor
RUN ln -s /usr/bin/python3 /usr/bin/python; ln -s /usr/bin/pip3 /usr/bin/pip
RUN pip install supervisor

# init environment and cache some dependencies
RUN mkdir -p /opt/code/localstack/localstack/infra && \
    wget -O /tmp/localstack.es.zip \
        https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.7.0.zip && \
    wget -O /tmp/elasticmq-server.jar \
        https://s3-eu-west-1.amazonaws.com/softwaremill-public/elasticmq-server-0.14.5.jar && \
    (cd localstack/infra/ && unzip -q /tmp/localstack.es.zip && \
        mv elasticsearch* elasticsearch && rm /tmp/localstack.es.zip) && \
    (cd localstack/infra/elasticsearch/ && \
        bin/elasticsearch-plugin install analysis-icu && \
        bin/elasticsearch-plugin install ingest-attachment --batch && \
        bin/elasticsearch-plugin install analysis-kuromoji && \
        bin/elasticsearch-plugin install mapper-murmur3 && \
        bin/elasticsearch-plugin install mapper-size && \
        bin/elasticsearch-plugin install analysis-phonetic && \
        bin/elasticsearch-plugin install analysis-smartcn && \
        bin/elasticsearch-plugin install analysis-stempel && \
        bin/elasticsearch-plugin install analysis-ukrainian) && \
    mkdir -p /opt/code/localstack/localstack/infra/dynamodb && \
    wget -O /tmp/localstack.ddb.zip \
        https://s3-us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.zip && \
    (cd localstack/infra/dynamodb && unzip -q /tmp/localstack.ddb.zip && rm /tmp/localstack.ddb.zip)
ADD requirements.txt .
RUN (pip install --upgrade pip) && \
    (test `which virtualenv` || pip install virtualenv || sudo pip install virtualenv) && \
    (virtualenv .testvenv && source .testvenv/bin/activate && \
        pip install -q six==1.10.0 && pip install -q -r requirements.txt && rm -rf .testvenv)

# add files required to run "make install-web"
ADD Makefile .
ADD localstack/dashboard/web/package.json localstack/dashboard/web/package.json

# install web dashboard dependencies
RUN make install-web

# install libs that require dependencies cleaned up below (e.g., gcc)
RUN (virtualenv .venv && source .venv/bin/activate && pip install cryptography)

# clean up (layers are later squashed into a single one)
RUN rm -rf /root/.npm; \
  apk del --purge autoconf automake build-base g++ gcc linux-headers openssl-dev python3-dev
