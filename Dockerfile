#
# base: Stage which installs necessary runtime dependencies (OS packages, etc.)
#
FROM python:3.11.11-slim-bookworm@sha256:614c8691ab74150465ec9123378cd4dde7a6e57be9e558c3108df40664667a4c AS base
ARG TARGETARCH

# Install runtime OS package dependencies
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
        # Install dependencies to add additional repos
        apt-get install -y --no-install-recommends \
            # Runtime packages (groff-base is necessary for AWS CLI help)
            ca-certificates curl gnupg git make openssl tar pixz zip unzip groff-base iputils-ping nss-passwords procps iproute2 xz-utils libatomic1 binutils && \
        # patch for CVE-2024-45490, CVE-2024-45491, CVE-2024-45492
        apt-get install --only-upgrade libexpat1

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
    C0D6248439F1D5604AAFFB4021D900FFDB233756 \
    DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7 \
    CC68F5A3106FF448322E48ED27F5E38D5B0A215F \
    8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 \
    890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4 \
    C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C \
    108F52B48DB57BB0CC439B2997B01419BD92F80A \
    A363A499291CBBC940DD62E41F10027AF002F8B0 \
  ; do \
      gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$key" || \
      gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$key" ; \
  done \
  && curl -LO https://nodejs.org/dist/latest-v18.x/SHASUMS256.txt \
  && LATEST_VERSION_FILENAME=$(cat SHASUMS256.txt | grep -o "node-v.*-linux-$ARCH" | sort | uniq) \
  && rm SHASUMS256.txt \
  && curl -fsSLO --compressed "https://nodejs.org/dist/latest-v18.x/$LATEST_VERSION_FILENAME.tar.xz" \
  && curl -fsSLO --compressed "https://nodejs.org/dist/latest-v18.x/SHASUMS256.txt.asc" \
  && gpg --batch --decrypt --output SHASUMS256.txt SHASUMS256.txt.asc \
  && grep " $LATEST_VERSION_FILENAME.tar.xz\$" SHASUMS256.txt | sha256sum -c - \
  && tar -xJf "$LATEST_VERSION_FILENAME.tar.xz" -C /usr/local --strip-components=1 --no-same-owner \
  && rm "$LATEST_VERSION_FILENAME.tar.xz" SHASUMS256.txt.asc SHASUMS256.txt \
  && ln -s /usr/local/bin/node /usr/local/bin/nodejs \
  # upgrade npm to the latest version
  && npm upgrade -g npm \
  # smoke tests
  && node --version \
  && npm --version \
  && test ! $(which python3.9)

SHELL [ "/bin/bash", "-c" ]
ENV LANG C.UTF-8

# set workdir
RUN mkdir -p /opt/code/localstack
RUN mkdir /opt/code/localstack/localstack-core
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

# install the entrypoint script
ADD bin/docker-entrypoint.sh /usr/local/bin/
# add the shipped hosts file to prevent performance degredation in windows container mode on windows
# (where hosts file is not mounted) See https://github.com/localstack/localstack/issues/5178
ADD bin/hosts /etc/hosts

# expose default environment
# Set edge bind host so localstack can be reached by other containers
# set library path and default LocalStack hostname
ENV USER=localstack
ENV PYTHONUNBUFFERED=1

# Install the latest version of awslocal globally
RUN --mount=type=cache,target=/root/.cache \
    pip3 install --upgrade awscli awscli-local requests


#
# builder: Stage which installs the dependencies of LocalStack Community
#
FROM base AS builder
ARG TARGETARCH

# Install build dependencies to base
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
        # Install dependencies to add additional repos
        # g++ is a workaround to fix the JPype1 compile error on ARM Linux "gcc: fatal error: cannot execute ‘cc1plus’"
        apt-get install -y gcc g++

# upgrade python build tools
RUN --mount=type=cache,target=/root/.cache \
    (python -m venv .venv && . .venv/bin/activate && pip3 install --upgrade pip wheel setuptools)

# add files necessary to install runtime dependencies
ADD Makefile pyproject.toml requirements-runtime.txt ./
# add the localstack start scripts (necessary for the installation of the runtime dependencies, i.e. `pip install -e .`)
ADD bin/localstack bin/localstack.bat bin/localstack-supervisor bin/

# Install dependencies for running the LocalStack runtime
RUN --mount=type=cache,target=/root/.cache\
    . .venv/bin/activate && pip3 install -r requirements-runtime.txt


#
# final stage: Builds upon base stage and copies resources from builder stages
#
FROM base
COPY --from=builder /opt/code/localstack/.venv /opt/code/localstack/.venv
# The build version is set in the docker-helper.sh script to be the output of setuptools_scm
ARG LOCALSTACK_BUILD_VERSION

# add project files necessary to install all dependencies
ADD Makefile pyproject.toml ./
# add the localstack start scripts (necessary for the installation of the runtime dependencies, i.e. `pip install -e .`)
ADD bin/localstack bin/localstack.bat bin/localstack-supervisor bin/

# add the code as late as possible
ADD localstack-core/ /opt/code/localstack/localstack-core

# Install LocalStack Community and generate the version file while doing so
RUN --mount=type=cache,target=/root/.cache \
    . .venv/bin/activate && \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_LOCALSTACK_CORE=${LOCALSTACK_BUILD_VERSION} \
    pip install -e .[runtime]

# Generate the plugin entrypoints
RUN SETUPTOOLS_SCM_PRETEND_VERSION_FOR_LOCALSTACK_CORE=${LOCALSTACK_BUILD_VERSION} \
    make entrypoints

# Generate service catalog cache in static libs dir
RUN . .venv/bin/activate && python3 -m localstack.aws.spec

# Install packages which should be shipped by default
RUN --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/var/lib/localstack/cache \
    source .venv/bin/activate && \
    python -m localstack.cli.lpm install \
      lambda-runtime \
      jpype-jsonata \
      dynamodb-local && \
    chown -R localstack:localstack /usr/lib/localstack && \
    chmod -R 777 /usr/lib/localstack

# link the python package installer virtual environments into the localstack venv
RUN echo /var/lib/localstack/lib/python-packages/lib/python3.11/site-packages > localstack-var-python-packages-venv.pth && \
    mv localstack-var-python-packages-venv.pth .venv/lib/python*/site-packages/
RUN echo /usr/lib/localstack/python-packages/lib/python3.11/site-packages > localstack-static-python-packages-venv.pth && \
    mv localstack-static-python-packages-venv.pth .venv/lib/python*/site-packages/

# expose edge service, external service ports, and debugpy
EXPOSE 4566 4510-4559 5678

HEALTHCHECK --interval=10s --start-period=15s --retries=5 --timeout=10s CMD /opt/code/localstack/.venv/bin/localstack status services --format=json

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
ENV LOCALSTACK_BUILD_DATE=${LOCALSTACK_BUILD_DATE}
ENV LOCALSTACK_BUILD_GIT_HASH=${LOCALSTACK_BUILD_GIT_HASH}
ENV LOCALSTACK_BUILD_VERSION=${LOCALSTACK_BUILD_VERSION}

# define command at startup
ENTRYPOINT ["docker-entrypoint.sh"]
