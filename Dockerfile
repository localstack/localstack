FROM fancylinq/alpine-oraclejdk8-mvn

MAINTAINER Waldemar Hummer (whummer@atlassian.com)

RUN apk add --update autoconf automake build-base git libffi-dev libtool make nodejs openssl-dev python python-dev py-pip zip

# set workdir
RUN mkdir -p /opt/code/localstack
WORKDIR /opt/code/localstack/

# init environment and cache some dependencies
RUN wget -O /tmp/localstack.es.zip https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/zip/elasticsearch/2.3.3/elasticsearch-2.3.3.zip
ADD requirements.txt .
RUN (pip install --upgrade pip) && \
	(test `which virtualenv` || pip install virtualenv || sudo pip install virtualenv) && \
	(virtualenv .testvenv && source .testvenv/bin/activate && pip install -r requirements.txt && rm -rf .testvenv)

# add code
ADD localstack/ localstack/

# install dependencies
ADD Makefile .
RUN make install
RUN make init

# fix some permissions
RUN mkdir -p /.npm && chmod -R 777 /.npm && \
	chmod -R 777 localstack/infra/elasticsearch/data

# assign random user id
USER 24624336
ENV USER docker

# expose service ports
EXPOSE 4567-4576

# define entrypoint/command
ENTRYPOINT ["make"]
CMD ["infra"]
