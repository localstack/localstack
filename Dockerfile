# builder: Stage to build a custom JRE (with jlink)
FROM python:3.10.12-slim-bullseye@sha256:b51f87064a7a335e7c47a1404f7d5d259df76bb9e07097a301b3bbf55db37e0a as java-builder
ARG TARGETARCH

# install OpenJDK 11
RUN apt-get update && \
        apt-get install -y openjdk-11-jdk-headless && \
        apt-get clean && rm -rf /var/lib/apt/lists/*

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
FROM python:3.10.12-slim-bullseye@sha256:b51f87064a7a335e7c47a1404f7d5d259df76bb9e07097a301b3bbf55db37e0a as base
ARG TARGETARCH

# Install runtime OS package dependencies
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
        # Install dependencies to add additional repos
        apt-get install -y --no-install-recommends ca-certificates curl && \
        # FIXME Node 18 actually shouldn't be necessary in Community, but we assume its presence in lots of tests
        curl -sL https://deb.nodesource.com/setup_18.x | bash - && \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            # Runtime packages (groff-base is necessary for AWS CLI help)
            git make openssl tar pixz zip unzip groff-base iputils-ping nss-passwords procps \
            # FIXME Node 18 actually shouldn't be necessary in Community, but we assume its presence in lots of tests
            nodejs


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
ENV LD_LIBRARY_PATH=/usr/lib/jvm/java-11/lib:/usr/lib/jvm/java-11/lib/server
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
        apt-get install -y gcc python-dev

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
      dynamodb-local && \
    chown -R localstack:localstack /usr/lib/localstack && \
    chmod -R 777 /usr/lib/localstack

# link the extensions virtual environment into the localstack venv
RUN echo /var/lib/localstack/lib/extensions/python_venv/lib/python3.10/site-packages > localstack-extensions-venv.pth && \
    mv localstack-extensions-venv.pth .venv/lib/python*/site-packages/

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
