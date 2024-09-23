# Base stage: Install necessary runtime dependencies
FROM python:3.11.10-slim-bookworm AS base
ARG TARGETARCH

# Install runtime OS package dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git make openssl tar pixz zip unzip groff-base iputils-ping \
        && apt-get upgrade -y libexpat1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Node.js without unnecessary dependencies
RUN dpkgArch="$(dpkg --print-architecture)" && \
    case "${dpkgArch##*-}" in \
        amd64) ARCH='x64';; \
        arm64) ARCH='arm64';; \
        *) echo "unsupported architecture"; exit 1 ;; \
    esac && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    npm cache clean --force

# Set workdir and create localstack user
WORKDIR /opt/code/localstack
RUN useradd -ms /bin/bash localstack && \
    mkdir -p /var/lib/localstack /tmp/localstack && \
    chmod 777 /var/lib/localstack /tmp/localstack && \
    touch /tmp/localstack/.marker

# Install basic global tools
RUN pip install --no-cache-dir --upgrade virtualenv

# Install entrypoint script
COPY bin/docker-entrypoint.sh /usr/local/bin/
COPY bin/hosts /etc/hosts

# Environment variables
ENV USER=localstack LANG=C.UTF-8 PYTHONUNBUFFERED=1

# Install the latest version of awslocal globally
RUN pip install --no-cache-dir --upgrade awscli awscli-local requests

# Builder stage: Install dependencies for LocalStack Community
FROM base AS builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Upgrade Python build tools
RUN virtualenv .venv && . .venv/bin/activate && pip install --upgrade pip wheel setuptools

# Add necessary files and install runtime dependencies
COPY Makefile pyproject.toml requirements-runtime.txt ./
COPY bin/localstack bin/localstack.bat bin/localstack-supervisor bin/
RUN . .venv/bin/activate && pip install -r requirements-runtime.txt

# Final stage: Build LocalStack
FROM base
COPY --from=builder /opt/code/localstack/.venv /opt/code/localstack/.venv
COPY Makefile pyproject.toml ./
COPY bin/localstack bin/localstack.bat bin/localstack-supervisor bin/
COPY localstack-core/ /opt/code/localstack/localstack-core

# Install LocalStack Community
RUN . .venv/bin/activate && \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_LOCALSTACK_CORE=${LOCALSTACK_BUILD_VERSION} pip install -e .[runtime]

# Install additional packages
RUN . .venv/bin/activate && \
    python -m localstack.cli.lpm install java --version 11 && \
    python -m localstack.cli.lpm install lambda-runtime dynamodb-local && \
    chown -R localstack:localstack /usr/lib/localstack

# Set up Java environment
ENV JAVA_HOME /usr/lib/localstack/java/11
RUN ln -s $JAVA_HOME/bin/java /usr/bin/java && \
    echo /var/lib/localstack/lib/python-packages/lib/python3.11/site-packages > /opt/code/localstack/.venv/lib/python*/site-packages/localstack-var-python-packages-venv.pth && \
    echo /usr/lib/localstack/python-packages/lib/python3.11/site-packages > /opt/code/localstack/.venv/lib/python*/site-packages/localstack-static-python-packages-venv.pth

# Expose ports and set healthcheck
EXPOSE 4566 4510-4559 5678
HEALTHCHECK --interval=10s --start-period=15s --retries=5 --timeout=5s CMD .venv/bin/localstack status services --format=json

# Default volume directory
VOLUME /var/lib/localstack

# Set labels and environment variables
LABEL authors="LocalStack Contributors" \
      maintainer="LocalStack Team (info@localstack.cloud)" \
      description="LocalStack Docker image"
ARG LOCALSTACK_BUILD_DATE
ARG LOCALSTACK_BUILD_GIT_HASH
ENV LOCALSTACK_BUILD_DATE=${LOCALSTACK_BUILD_DATE} \
    LOCALSTACK_BUILD_GIT_HASH=${LOCALSTACK_BUILD_GIT_HASH} \
    LOCALSTACK_BUILD_VERSION=${LOCALSTACK_BUILD_VERSION}

# Define command at startup
ENTRYPOINT ["docker-entrypoint.sh"]
