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
    echo "  push-main"
    echo "      Push the Docker image for the project if we're on the main branch"
    echo ""
    echo "  push-manifests-main"
    echo "      Push the multi-arch Docker manifests if we're on the main branch"
    echo ""
    echo "  help"
    echo "      Show this message"
}

function get_current_version() {
    egrep -h "^__version__ = " ${VERSION_FILE} | sed -r 's/^__version__ = "(.*)"/\1/g'
}

function set_defaults() {
    # assert required variables are defined
    if [ -z "$IMAGE_NAME" ]; then echo "Please define Docker image name via IMAGE_NAME"; exit 1; fi

    # set defaults

    if [ -z "$PYTHON_CODE_DIR" ]; then
        # try to determine the main Python code directory
        entries=$(find . -name '*.py' | grep -v .venv | xargs grep -R '^__version__ =' | wc -l)
        if [[ $entries -ne 1 ]]; then
            echo "Unable to find __version__ in project Python files."
            echo "Please configure PYTHON_CODE_DIR with the path to the main Python code directory"
            exit 1
        fi
        entry=$(find . -name '*.py' | grep -v .venv | xargs grep -R '^__version__ =' | sed -e 's/\(.*\):.*/\1/')
        PYTHON_CODE_DIR=$(dirname $entry)
    fi

    # determine major/minor/patch versions
    if [ -z "$IMAGE_TAG" ]; then
      IMAGE_TAG=$(cat $PYTHON_CODE_DIR/__init__.py | grep '^__version__ =' | sed "s/__version__ = ['\"]\(.*\)['\"].*/\1/")
    fi
    if [ -z "$MAJOR_VERSION" ]; then MAJOR_VERSION=$(echo ${IMAGE_TAG} | cut -d '.' -f1); fi
    if [ -z "$MINOR_VERSION" ]; then MINOR_VERSION=$(echo ${IMAGE_TAG} | cut -d '.' -f2); fi
    if [ -z "$PATCH_VERSION" ]; then PATCH_VERSION=$(echo ${IMAGE_TAG} | cut -d '.' -f3); fi

    if [ -z "$DOCKERFILE" ]; then DOCKERFILE=Dockerfile; fi
    if [ -z "$SOURCE_IMAGE_NAME" ]; then SOURCE_IMAGE_NAME=$IMAGE_NAME; fi
    if [ -z "$TARGET_IMAGE_NAME" ]; then TARGET_IMAGE_NAME=$IMAGE_NAME; fi
    if [ -z "$MANIFEST_IMAGE_NAME" ]; then MANIFEST_IMAGE_NAME=$IMAGE_NAME; fi
    if [ -z "$TAG" ]; then TAG=$IMAGE_NAME; fi
    if [ -z "$MAIN_BRANCH" ]; then MAIN_BRANCH=master; fi
}

function docker_build() {
    # start build of a platform-specific image (this target will get called for multiple archs like AMD64/ARM64)

    # by default we load the result to the docker daemon
    if [ "$DOCKER_BUILD_FLAGS" = "" ]; then DOCKER_BUILD_FLAGS="--load"; fi
    # --add-host: Fix for Centos host OS
    # --build-arg BUILDKIT_INLINE_CACHE=1: Instruct buildkit to inline the caching information into the image
    # --cache-from: Use the inlined caching information when building the image
    DOCKER_BUILDKIT=1 docker buildx build --pull --progress=plain \
      --cache-from "$TAG" --build-arg BUILDKIT_INLINE_CACHE=1 \
      --build-arg LOCALSTACK_PRE_RELEASE=$(cat $PYTHON_CODE_DIR/__init__.py | grep '^__version__ =' | grep -v '.dev' >> /dev/null && echo "0" || echo "1") \
      --build-arg LOCALSTACK_BUILD_GIT_HASH=$(git rev-parse --short HEAD) \
      --build-arg=LOCALSTACK_BUILD_DATE=$(date -u +"%Y-%m-%d") \
      --build-arg=LOCALSTACK_BUILD_VERSION=$IMAGE_TAG \
      --add-host="localhost.localdomain:127.0.0.1" \
      -t "$TAG" $DOCKER_BUILD_FLAGS . -f $DOCKERFILE
}

function docker_build_multiarch() {
    ## Build the Multi-Arch full Docker image
	  # Make sure to prepare your environment for cross-platform docker builds! (see doc/developer_guides/README.md)
	  # Multi-Platform builds cannot be loaded to the docker daemon from buildx, so we can't add "--load".
	  DOCKER_BUILD_FLAGS="--platform linux/amd64,linux/arm64" docker_build
}

function docker_push_main() {
    ## Push a single platform-specific Docker image to registry, if we are currently on the main branch
    (CURRENT_BRANCH=`(git rev-parse --abbrev-ref HEAD | grep '^'$MAIN_BRANCH'$' || \
      ((git branch -a | grep 'HEAD detached at [0-9a-zA-Z/_-]*)') && git branch -a)) | grep '^[* ]*'$MAIN_BRANCH'$' | sed 's/[* ]//g' || true`;
        echo "Current git branch: '$CURRENT_BRANCH'"
        test "$CURRENT_BRANCH" != "$MAIN_BRANCH" && echo "Not on main branch.") || \
    ((test "$DOCKER_USERNAME" = '' || test "$DOCKER_PASSWORD" = '' ) && \
      echo "Skipping docker push as no credentials are provided.") || \
    (REMOTE_ORIGIN="`git remote -v | grep 'localstack/' | grep origin | grep push | awk '{print $2}'`"; \
      [[ "$REMOTE_ORIGIN" != 'https://github.com/localstack/'* ]] && \
      [[ "$REMOTE_ORIGIN" != 'git@github.com:localstack/'* ]] && \
      echo "This is a fork and not the main repo.") || \
    ( \
      docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD; \
        docker tag $SOURCE_IMAGE_NAME:latest $TARGET_IMAGE_NAME:latest-$PLATFORM && \
      ((! (git diff HEAD~1 $PYTHON_CODE_DIR/__init__.py | grep '^+__version__ =' | grep -v '.dev') && \
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

function docker_push_manifests_main() {
    ## Create and push manifests for the multi-arch Docker image, if we are currently on the main branch
    (CURRENT_BRANCH=`(git rev-parse --abbrev-ref HEAD | grep '^'$MAIN_BRANCH'$' || \
      ((git branch -a | grep 'HEAD detached at [0-9a-zA-Z/_-]*)') && git branch -a)) | grep '^[* ]*'$MAIN_BRANCH'$' | sed 's/[* ]//g' || true`;
      echo "Current git branch: '$CURRENT_BRANCH'"
      test "$CURRENT_BRANCH" != "$MAIN_BRANCH" && echo "Not on main branch.") || \
    ((test "$DOCKER_USERNAME" = '' || test "$DOCKER_PASSWORD" = '' ) && \
      echo "Skipping docker manifest push as no credentials are provided.") || \
    (REMOTE_ORIGIN="`git remote -v | grep 'localstack/' | grep origin | grep push | awk '{print $2}'`"; \
      [[ "$REMOTE_ORIGIN" != 'https://github.com/localstack/'* ]] && \
      [[ "$REMOTE_ORIGIN" != 'git@github.com:localstack/'* ]] && \
      echo "This is a fork and not the main repo.") || \
    ( \
      docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD; \
        docker manifest create $MANIFEST_IMAGE_NAME:latest --amend $MANIFEST_IMAGE_NAME:latest-amd64 --amend $MANIFEST_IMAGE_NAME:latest-arm64 && \
      ((! (git diff HEAD~1 $PYTHON_CODE_DIR/__init__.py | grep '^+__version__ =' | grep -v '.dev') && \
          echo "Only pushing tag 'latest' as version has not changed.") || \
        (docker manifest create $MANIFEST_IMAGE_NAME:$IMAGE_TAG \
        --amend $MANIFEST_IMAGE_NAME:$IMAGE_TAG-amd64 \
        --amend $MANIFEST_IMAGE_NAME:$IMAGE_TAG-arm64 && \
        docker manifest create $MANIFEST_IMAGE_NAME:stable \
        --amend $MANIFEST_IMAGE_NAME:stable-amd64 \
        --amend $MANIFEST_IMAGE_NAME:stable-arm64 && \
        docker manifest create $MANIFEST_IMAGE_NAME:$MAJOR_VERSION \
        --amend $MANIFEST_IMAGE_NAME:$MAJOR_VERSION-amd64 \
        --amend $MANIFEST_IMAGE_NAME:$MAJOR_VERSION-arm64 && \
        docker manifest create $MANIFEST_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION \
        --amend $MANIFEST_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION-amd64 \
        --amend $MANIFEST_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION-arm64 && \
        docker manifest create $MANIFEST_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION \
        --amend $MANIFEST_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-amd64 \
        --amend $MANIFEST_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-arm64 && \
          docker manifest push $MANIFEST_IMAGE_NAME:stable && \
          docker manifest push $MANIFEST_IMAGE_NAME:$IMAGE_TAG && \
          docker manifest push $MANIFEST_IMAGE_NAME:$MAJOR_VERSION && \
          docker manifest push $MANIFEST_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION && \
          docker manifest push $MANIFEST_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION)) && \
      docker manifest push $MANIFEST_IMAGE_NAME:latest \
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

function cmd-push-main() {
    set_defaults
    docker_push_main
}

function cmd-push-manifests-main() {
    set_defaults
    docker_push_manifests_main
}

function main() {
    [[ $# -lt 1 ]] && { usage; exit 1; }

    command_name=$1
    shift

    # invoke command
    case $command_name in
        "build")               cmd-build "$@" ;;
        "build-multiarch")     cmd-build-multiarch "$@" ;;
        "push-main")           cmd-push-main "$@" ;;
        "push-manifests-main") cmd-push-manifests-main "$@" ;;
        "help")                usage && exit 0 ;;
        *)                     usage && exit 1 ;;
    esac
}

main "$@"
