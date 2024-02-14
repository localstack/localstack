#!/usr/bin/env bash

set -e

function usage() {
    echo "A set of commands that facilitate building and pushing versioned Docker images"
    echo ""
    echo "USAGE"
    echo "  docker-helper <command> [options]"
    echo ""
    echo "Commands:"
    echo "  build"
    echo "      Build the Docker image for the project in the working directory"
    echo ""
    echo "  push"
    echo "      Push the Docker image for the project in the working directory"
    echo ""
    echo "  help"
    echo "      Show this message"
}

function get_current_version() {
    egrep -h "^__version__ = " ${VERSION_FILE} | sed -r 's/^__version__ = "(.*)"/\1/g'
}

function set_defaults() {
    if [ "$DOCKERFILE" = "" ]; then DOCKERFILE=Dockerfile; fi
    if [ "$SOURCE_IMAGE_NAME" = "" ]; then SOURCE_IMAGE_NAME=$IMAGE_NAME; fi
    if [ "$TARGET_IMAGE_NAME" = "" ]; then TARGET_IMAGE_NAME=$IMAGE_NAME; fi
}

function docker_build() {
    # start build
    # --add-host: Fix for Centos host OS
    # --build-arg BUILDKIT_INLINE_CACHE=1: Instruct buildkit to inline the caching information into the image
    # --cache-from: Use the inlined caching information when building the image
    DOCKER_BUILDKIT=1 docker buildx build --pull --progress=plain \
      --cache-from $TAG --build-arg BUILDKIT_INLINE_CACHE=1 \
      --build-arg LOCALSTACK_PRE_RELEASE=$(cat localstack/__init__.py | grep '^__version__ =' | grep -v '.dev' >> /dev/null && echo "0" || echo "1") \
      --build-arg LOCALSTACK_BUILD_GIT_HASH=$(git rev-parse --short HEAD) \
      --build-arg=LOCALSTACK_BUILD_DATE=$(date -u +"%Y-%m-%d") \
      --build-arg=LOCALSTACK_BUILD_VERSION=$IMAGE_TAG \
      --add-host="localhost.localdomain:127.0.0.1" \
      -t $TAG $DOCKER_BUILD_FLAGS . -f $DOCKERFILE
}

function docker_build_multiarch() {
    ## Build the Multi-Arch full Docker image
	  # Make sure to prepare your environment for cross-platform docker builds! (see doc/developer_guides/README.md)
	  # Multi-Platform builds cannot be loaded to the docker daemon from buildx, so we can't add "--load".
	  DOCKER_BUILD_FLAGS="--platform linux/amd64,linux/arm64" docker_build
}

function docker_push_main() {
    # Push a single platform-specific Docker image to registry IF we are currently on the master branch
    (CURRENT_BRANCH=`(git rev-parse --abbrev-ref HEAD | grep '^master$$' || ((git branch -a | grep 'HEAD detached at [0-9a-zA-Z]*)') && git branch -a)) | grep '^[* ]*master$$' | sed 's/[* ]//g' || true`; \
      test "$$CURRENT_BRANCH" != 'master' && echo "Not on master branch.") || \
    ((test "$$DOCKER_USERNAME" = '' || test "$$DOCKER_PASSWORD" = '' ) && \
      echo "Skipping docker push as no credentials are provided.") || \
    (REMOTE_ORIGIN="`git remote -v | grep '/localstack' | grep origin | grep push | awk '{print $$2}'`"; \
      test "$$REMOTE_ORIGIN" != 'https://github.com/localstack/localstack.git' && \
      test "$$REMOTE_ORIGIN" != 'git@github.com:localstack/localstack.git' && \
      echo "This is a fork and not the main repo.") || \
    ( \
      docker info | grep Username || docker login -u $$DOCKER_USERNAME -p $$DOCKER_PASSWORD; \
        docker tag $SOURCE_IMAGE_NAME:latest $TARGET_IMAGE_NAME:latest-$PLATFORM && \
      ((! (git diff HEAD~1 localstack/__init__.py | grep '^+__version__ =' | grep -v '.dev') && \
        echo "Only pushing tag 'latest' as version has not changed.") || \
        (docker tag $TARGET_IMAGE_NAME:latest-$PLATFORM $TARGET_IMAGE_NAME:stable-$PLATFORM && \
          docker tag $TARGET_IMAGE_NAME:latest-$PLATFORM $TARGET_IMAGE_NAME:$IMAGE_TAG-$PLATFORM && \
          docker tag $TARGET_IMAGE_NAME:latest-$PLATFORM $TARGET_IMAGE_NAME:$MAJOR_VERSION-$PLATFORM && \
          docker tag $TARGET_IMAGE_NAME:latest-$PLATFORM $TARGET_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION-$PLATFORM && \
          docker tag $TARGET_IMAGE_NAME:latest-$PLATFORM $TARGET_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-$PLATFORM && \
          docker push $TARGET_IMAGE_NAME:stable-$PLATFORM && \
          docker push $TARGET_IMAGE_NAME:$IMAGE_TAG-$PLATFORM && \
          docker push $TARGET_IMAGE_NAME:$MAJOR_VERSION-$PLATFORM && \
          docker push $TARGET_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION-$PLATFORM && \
          docker push $TARGET_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-$PLATFORM \
          )) && \
            docker push $TARGET_IMAGE_NAME:latest-$PLATFORM \
    )
}


# commands

function cmd-build() {
    set_defaults
    docker_build
}

function cmd-build-multiarch() {
    set_defaults
    docker_build_multiarch
}

function cmd-push() {
    set_defaults
    docker_push
}

function cmd-push-main() {
    set_defaults
    docker_push_main
}

function main() {
    [[ $# -lt 1 ]] && { usage; exit 1; }

    command_name=$1
    shift

    # invoke command
    case $command_name in
        "build")             cmd-build "$@" ;;
        "build-multiarch")   cmd-build-multiarch "$@" ;;
        "push")              cmd-push "$@" ;;
        "push-main")         cmd-push-main "$@" ;;
        "help")              usage && exit 0 ;;
        *)                   usage && exit 1 ;;
    esac
}

main "$@"
