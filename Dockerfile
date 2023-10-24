# java-builder: Stage to build a custom JRE (with jlink)
FROM eclipse-temurin:11@sha256:f05c8dfa25aa75d994e48c54eef6be4c05326627c066f67497fb4a86f545ec4a as java-builder

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
# required for Spark/Hadoop
java.security.jgss,jdk.security.auth,\
# Elasticsearch 7+ crashes without Thai Segmentation support
jdk.localedata --include-locales en,th \
    --compress 2 --strip-debug --no-header-files --no-man-pages --output /usr/lib/jvm/java-11 && \
  cp ${JAVA_HOME}/bin/javac /usr/lib/jvm/java-11/bin/javac && \
  cp -r ${JAVA_HOME}/include /usr/lib/jvm/java-11/include && \
  mv /usr/lib/jvm/java-11/lib/modules /usr/lib/jvm/java-11/lib/modules.bk; \
  cp -r ${JAVA_HOME}/lib/* /usr/lib/jvm/java-11/lib/; \
  mv /usr/lib/jvm/java-11/lib/modules.bk /usr/lib/jvm/java-11/lib/modules; \
  rm -rf /usr/bin/java ${JAVA_HOME} && ln -s /usr/lib/jvm/java-11/bin/java /usr/bin/java


# base: Stage which installs necessary runtime dependencies (OS packages, java,...)
FROM python:3.11.6-slim-bookworm@sha256:d36d3fb6c859768ec62ac36ddc7397b5331d8dc05bc8823b3cac24f6ade97483 as base
ARG TARGETARCH

# Install runtime OS package dependencies
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
        # Install dependencies to add additional repos
        apt-get install -y --no-install-recommends \
            # Runtime packages (groff-base is necessary for AWS CLI help)
            ca-certificates curl gnupg git make openssl tar pixz zip unzip groff-base iputils-ping nss-passwords procps iproute2 xz-utils

# FIXME Node 18 actually shouldn't be necessary in Community, but we assume its presence in lots of tests
# Install nodejs package from the dist release server. Note: we're installing from dist binaries, and not via
#  `apt-get`, to avoid installing `python3.9` into the image (which otherwise comes as a dependency of nodejs).
# See https://github.com/nodejs/docker-node/blob/main/18/bullseye/Dockerfile
RUN ARCH= && dpkgArch="$(dpkg --print-architecture)" \
  && case "${dpkgArch##*-}" in \
    amd64) ARCH='x64';; \
    arm64) ARCH='arm64';; \
    *) echo "unsupported architecture"; exit 1 ;; \
  esac \
  # gpg keys listed at https://github.com/nodejs/node#release-keys
  && set -ex \
  && for key in \
    4ED778F539E3634C779C87C6D7062848A1AB005C \
    141F07595B7B3FFE74309A937405533BE57C7D57 \
    74F12602B6F1C4E913FAA37AD3A89613643B6201 \
    DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7 \
    61FC681DFB92A079F1685E77973F295594EC4689 \
    8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 \
    C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8 \
    890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4 \
    C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C \
    108F52B48DB57BB0CC439B2997B01419BD92F80A \
    A363A499291CBBC940DD62E41F10027AF002F8B0 \
  ; do \
      gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$key" || \
      gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$key" ; \
  done \
  && curl -O https://nodejs.org/dist/latest-v18.x/SHASUMS256.txt \
  && LATEST_VERSION_FILENAME=$(cat SHASUMS256.txt | grep -o "node-v.*-linux-$ARCH" | sort | uniq) \
  && rm SHASUMS256.txt \
  && curl -fsSLO --compressed "https://nodejs.org/dist/latest-v18.x/$LATEST_VERSION_FILENAME.tar.xz" \
  && curl -fsSLO --compressed "https://nodejs.org/dist/latest-v18.x/SHASUMS256.txt.asc" \
  && gpg --batch --decrypt --output SHASUMS256.txt SHASUMS256.txt.asc \
  && grep " $LATEST_VERSION_FILENAME.tar.xz\$" SHASUMS256.txt | sha256sum -c - \
  && tar -xJf "$LATEST_VERSION_FILENAME.tar.xz" -C /usr/local --strip-components=1 --no-same-owner \
  && rm "$LATEST_VERSION_FILENAME.tar.xz" SHASUMS256.txt.asc SHASUMS256.txt \
  && ln -s /usr/local/bin/node /usr/local/bin/nodejs \
  # smoke tests
  && node --version \
  && npm --version \
  && test ! $(which python3.9)

SHELL [ "/bin/bash", "-c" ]

# Install Java 11
ENV LANG C.UTF-8
RUN { \
        echo '#!/bin/sh'; echo 'set -e'; echo; \
        echo 'dirname "$(dirname "$(readlink -f "$(which javac || which java)")")"'; \
    } > /usr/local/bin/docker-java-home \
    && chmod +x /usr/local/bin/docker-java-home
ENV JAVA_HOME /usr/lib/jvm/java-11
COPY --from=java-builder /usr/lib/jvm/java-11 $JAVA_HOME
RUN ln -s $JAVA_HOME/bin/java /usr/bin/java
ENV PATH "${PATH}:${JAVA_HOME}/bin"

# set workdir
RUN mkdir -p /opt/code/localstack
WORKDIR /opt/code/localstack/

# create localstack user and filesystem hierarchy, perform some permission fixes
RUN chmod 777 . && \
    useradd -ms /bin/bash localstack && \
    mkdir -p /var/lib/localstack && \
    chmod -R 777 /var/lib/localstack && \
    mkdir -p /usr/lib/localstack && \
    mkdir /tmp/localstack && \
    chmod -R 777 /tmp/localstack && \
    touch /tmp/localstack/.marker && \
    mkdir -p /.npm && \
    chmod 755 /root && \
    chmod -R 777 /.npm

# install basic (global) tools to final image
RUN --mount=type=cache,target=/root/.cache \
    pip install --no-cache-dir --upgrade virtualenv

# install the entrypoint script
ADD bin/docker-entrypoint.sh /usr/local/bin/
# add the shipped hosts file to prevent performance degredation in windows container mode on windows
# (where hosts file is not mounted) See https://github.com/localstack/localstack/issues/5178
ADD bin/hosts /etc/hosts

# expose default environment
# Set edge bind host so localstack can be reached by other containers
# set library path and default LocalStack hostname
ENV LD_LIBRARY_PATH=$JAVA_HOME/lib:$JAVA_HOME/lib/server
ENV USER=localstack
ENV PYTHONUNBUFFERED=1

# Install the latest version of awslocal globally
RUN --mount=type=cache,target=/root/.cache \
    pip3 install --upgrade awscli awscli-local requests



# builder: Stage which installs the dependencies of LocalStack Community
FROM base as builder
ARG TARGETARCH

# Install build dependencies to base
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
        # Install dependencies to add additional repos
        apt-get install -y gcc

# upgrade python build tools
RUN --mount=type=cache,target=/root/.cache \
    (virtualenv .venv && . .venv/bin/activate && pip3 install --upgrade pip wheel setuptools)

# add files necessary to install all dependencies
ADD Makefile setup.py setup.cfg pyproject.toml ./
# add the root package init to invalidate docker layers with version bumps
ADD localstack/__init__.py localstack/
# add the localstack start scripts (necessary for the installation of the runtime dependencies, i.e. `pip install -e .`)
ADD bin/localstack bin/localstack.bat bin/localstack-supervisor bin/

# install dependencies to run the LocalStack Pro runtime and save which ones were installed
RUN --mount=type=cache,target=/root/.cache \
    make install-runtime
RUN . .venv/bin/activate && pip3 freeze -l > requirements-runtime.txt



# final stage: Builds upon base stage and copies resources from builder stages
FROM base
COPY --from=builder /opt/code/localstack/.venv /opt/code/localstack/.venv

# add project files necessary to install all dependencies
ADD Makefile setup.py setup.cfg pyproject.toml ./
# add the localstack start scripts (necessary for the installation of the runtime dependencies, i.e. `pip install -e .`)
ADD bin/localstack bin/localstack.bat bin/localstack-supervisor bin/

# add the code as late as possible
ADD localstack/ localstack/

# Generate the plugin entrypoints
RUN make entrypoints

# Install packages which should be shipped by default
RUN --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/var/lib/localstack/cache \
    source .venv/bin/activate && \
    python -m localstack.cli.lpm install \
      lambda-runtime \
      dynamodb-local && \
    chown -R localstack:localstack /usr/lib/localstack && \
    chmod -R 777 /usr/lib/localstack

# link the python package installer virtual environments into the localstack venv
RUN echo /var/lib/localstack/lib/python-packages/lib/python3.11/site-packages > localstack-var-python-packages-venv.pth && \
    mv localstack-var-python-packages-venv.pth .venv/lib/python*/site-packages/
RUN echo /usr/lib/localstack/python-packages/lib/python3.11/site-packages > localstack-static-python-packages-venv.pth && \
    mv localstack-static-python-packages-venv.pth .venv/lib/python*/site-packages/

# Install the latest version of the LocalStack Persistence Plugin
RUN --mount=type=cache,target=/root/.cache \
    (. .venv/bin/activate && pip3 install --upgrade localstack-plugin-persistence)

# expose edge service, external service ports, and debugpy
EXPOSE 4566 4510-4559 5678

HEALTHCHECK --interval=10s --start-period=15s --retries=5 --timeout=5s CMD ./bin/localstack status services --format=json

# default volume directory
VOLUME /var/lib/localstack

# mark the image version
RUN touch /usr/lib/localstack/.community-version

LABEL authors="LocalStack Contributors"
LABEL maintainer="LocalStack Team (info@localstack.cloud)"
LABEL description="LocalStack Docker image"

# Add the build date and git hash at last (changes everytime)
ARG LOCALSTACK_BUILD_DATE
ARG LOCALSTACK_BUILD_GIT_HASH
ARG LOCALSTACK_BUILD_VERSION
ENV LOCALSTACK_BUILD_DATE=${LOCALSTACK_BUILD_DATE}
ENV LOCALSTACK_BUILD_GIT_HASH=${LOCALSTACK_BUILD_GIT_HASH}
ENV LOCALSTACK_BUILD_VERSION=${LOCALSTACK_BUILD_VERSION}

# define command at startup
ENTRYPOINT ["docker-entrypoint.sh"]
