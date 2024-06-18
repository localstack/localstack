#!/usr/bin/env bash

set -eo pipefail
# set -x
shopt -s nullglob

# global defaults
VERSION_FILE=${VERSION_FILE-"VERSION"}
DOCKERFILE=${DOCKERFILE-"Dockerfile"}
DEFAULT_TAG=${DEFAULT_TAG-"latest"}

# TODO extend help
function usage() {
    echo "A set of commands that facilitate building and pushing versioned Docker images"
    echo ""
    echo "USAGE"
    echo "  docker-helper <command> [options]"
    echo ""
    echo "Commands:"
    echo "  build"
    echo "      Build a platform-specific Docker image for the project in the working directory"
    echo ""
    echo "  save"
    echo "      Save the Docker image to disk (to transfer it to other runners / machines)"
    echo ""
    echo "  load"
    echo "      Load a previously saved Docker image from disk"
    echo ""
    echo "  push"
    echo "      Push a platform-specific the Docker image for the project"
    echo ""
    echo "  push-manifests"
    echo "      Create and push the multi-arch Docker manifests for already pushed platform-specific images"
    echo ""
    echo "  help"
    echo "      Show this message"
}



#############
## Helpers ##
#############

function _fail {
    # send error message to stderr
    printf '%s\n' "$1" >&2
    # exit with error code, $2 or by default 1
    exit "${2-1}"
}

function _get_current_version() {
    cat ${VERSION_FILE}
}

function _get_current_branch() {
    git branch --show-current
}

function _enforce_image_name() {
    if [ -z "$IMAGE_NAME" ]; then _fail "Mandatory parameter IMAGE_NAME missing."; fi
}

function _enforce_main_branch() {
    MAIN_BRANCH=${MAIN_BRANCH-"master"}
    CURRENT_BRANCH=$(_get_current_branch)
    echo "Current git branch: '$CURRENT_BRANCH'"
    test "$CURRENT_BRANCH" == "$MAIN_BRANCH" || _fail "Current branch ($CURRENT_BRANCH) is not $MAIN_BRANCH."
}

function _enforce_no_fork() {
    REMOTE_ORIGIN=$(git remote -v | grep 'localstack/' | grep origin | grep push | awk '{print $2}')
    if [[ "$REMOTE_ORIGIN" != 'https://github.com/localstack/'* ]] &&  [[ "$REMOTE_ORIGIN" != 'git@github.com:localstack/'* ]]; then
      _fail "This is a fork and not the main repo."
    fi
}

function _enforce_docker_credentials() {
    if [ -z "$DOCKER_USERNAME" ] || [ -z "$DOCKER_PASSWORD" ]; then _fail "Mandatory Docker credentials are missing."; fi
}

function _enforce_platform() {
    if [ -z "$PLATFORM" ]; then _fail "Mandatory parameter PLATFORM is missing."; fi
}

function _set_version_defaults() {
    # determine major/minor/patch versions
    if [ -z "$IMAGE_TAG" ]; then
      IMAGE_TAG=$(_get_current_version)
    fi
    if [ -z "$MAJOR_VERSION" ]; then MAJOR_VERSION=$(echo ${IMAGE_TAG} | cut -d '.' -f1); fi
    if [ -z "$MINOR_VERSION" ]; then MINOR_VERSION=$(echo ${IMAGE_TAG} | cut -d '.' -f2); fi
    if [ -z "$PATCH_VERSION" ]; then PATCH_VERSION=$(echo ${IMAGE_TAG} | cut -d '.' -f3); fi
}



##############
## Commands ##
##############

function cmd-build() {
    # start build of a platform-specific image (this target will get called for multiple archs like AMD64/ARM64)
    _enforce_image_name
    _set_version_defaults

    if [ -z "$DOCKERFILE" ]; then DOCKERFILE=Dockerfile; fi
    # by default we load the result to the docker daemon
    if [ "$DOCKER_BUILD_FLAGS" = "" ]; then DOCKER_BUILD_FLAGS="--load"; fi

    # --add-host: Fix for Centos host OS
    # --build-arg BUILDKIT_INLINE_CACHE=1: Instruct buildkit to inline the caching information into the image
    # --cache-from: Use the inlined caching information when building the image
    DOCKER_BUILDKIT=1 docker buildx build --pull --progress=plain \
      --cache-from "$IMAGE_NAME" --build-arg BUILDKIT_INLINE_CACHE=1 \
      --build-arg LOCALSTACK_PRE_RELEASE=$(_get_current_version | grep -v '.dev' >> /dev/null && echo "0" || echo "1") \
      --build-arg LOCALSTACK_BUILD_GIT_HASH=$(git rev-parse --short HEAD) \
      --build-arg=LOCALSTACK_BUILD_DATE=$(date -u +"%Y-%m-%d") \
      --build-arg=LOCALSTACK_BUILD_VERSION=$IMAGE_TAG \
      --add-host="localhost.localdomain:127.0.0.1" \
      -t "$IMAGE_NAME:$DEFAULT_TAG" $DOCKER_BUILD_FLAGS . -f $DOCKERFILE
}

function cmd-save() {
    _enforce_image_name

    if [ -z "$IMAGE_FILENAME" ]; then
      _enforce_platform
      IMAGE_FILENAME="localstack-docker-image-$PLATFORM.tar.gz";
    fi

    docker save $IMAGE_NAME:$DEFAULT_TAG | gzip > $IMAGE_FILENAME
    # set the filename as github output if it's available
    if [ -n "$GITHUB_OUTPUT" ]; then
      echo "IMAGE_FILENAME=$IMAGE_FILENAME" >> "$GITHUB_OUTPUT"
    fi
}

function cmd-load() {
    if [ -z "$IMAGE_FILENAME" ]; then
      _enforce_platform
      IMAGE_FILENAME="localstack-docker-image-$PLATFORM.tar.gz";
    fi

    docker load -i $IMAGE_FILENAME
}

function cmd-push() {
    _enforce_image_name
    _enforce_main_branch
    _enforce_no_fork
    _enforce_docker_credentials
    _enforce_platform
    _set_version_defaults

    if [ -z "$TARGET_IMAGE_NAME" ]; then TARGET_IMAGE_NAME=$IMAGE_NAME; fi

    # login to DockerHub
    docker login -u "$DOCKER_USERNAME" -p "$DOCKER_PASSWORD"

    # create the platform specific default tag
    docker tag $IMAGE_NAME:$DEFAULT_TAG $TARGET_IMAGE_NAME:$DEFAULT_TAG-$PLATFORM

    # push default tag
    docker push $TARGET_IMAGE_NAME:$DEFAULT_TAG-$PLATFORM

    function _push() {
      # create explicitly set image tag (via $IMAGE_TAG)
      docker tag $TARGET_IMAGE_NAME:$DEFAULT_TAG-$PLATFORM $TARGET_IMAGE_NAME:$IMAGE_TAG-$PLATFORM

      # always create "latest" tag on version push
      docker tag $TARGET_IMAGE_NAME:$DEFAULT_TAG-$PLATFORM $TARGET_IMAGE_NAME:latest-$PLATFORM

      # create "stable" tag
      docker tag $TARGET_IMAGE_NAME:$DEFAULT_TAG-$PLATFORM $TARGET_IMAGE_NAME:stable-$PLATFORM

      # create <major> tag (f.e. 4)
      docker tag $TARGET_IMAGE_NAME:$DEFAULT_TAG-$PLATFORM $TARGET_IMAGE_NAME:$MAJOR_VERSION-$PLATFORM

      # create <major>.<minor> (f.e. 4.0)
      docker tag $TARGET_IMAGE_NAME:$DEFAULT_TAG-$PLATFORM $TARGET_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION-$PLATFORM

      # create <major>.<minor>.<patch> (f.e. 4.0.0)
      docker tag $TARGET_IMAGE_NAME:$DEFAULT_TAG-$PLATFORM $TARGET_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-$PLATFORM

      # push all the created tags
      docker push $TARGET_IMAGE_NAME:stable-$PLATFORM
      docker push $TARGET_IMAGE_NAME:latest-$PLATFORM
      docker push $TARGET_IMAGE_NAME:$IMAGE_TAG-$PLATFORM
      docker push $TARGET_IMAGE_NAME:$MAJOR_VERSION-$PLATFORM
      docker push $TARGET_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION-$PLATFORM
      docker push $TARGET_IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-$PLATFORM
    }

    if [ -n "$FORCE_VERSION_TAG_PUSH" ] && [ "$FORCE_VERSION_TAG_PUSH" -eq "1" ]; then
      echo "Force-enabled version tag push."
      _push
    elif [ -n "$FORCE_VERSION_TAG_PUSH" ] && [ "$FORCE_VERSION_TAG_PUSH" -eq "0" ]; then
      echo "Force-disabled version tag push. Not pushing any other tags."
    elif (git diff HEAD^ ${VERSION_FILE} | tail -n 1 | grep -v '.dev'); then
      echo "Pushing version tags, version has changed in last commit."
      _push
    else
      echo "Not pushing any other tags, version has not changed in last commit."
    fi
}

function cmd-push-manifests() {
    _enforce_image_name
    _enforce_main_branch
    _enforce_no_fork
    _enforce_docker_credentials
    _set_version_defaults

    # login to DockerHub
    docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD

    # create the multiarch manifest
    docker manifest create $IMAGE_NAME:$DEFAULT_TAG --amend $IMAGE_NAME:$DEFAULT_TAG-amd64 --amend $IMAGE_NAME:$DEFAULT_TAG-arm64

    # push default tag
    docker manifest push $IMAGE_NAME:$DEFAULT_TAG

    function _push() {
      # create explicitly set image tag (via $IMAGE_TAG)
      docker manifest create $IMAGE_NAME:$IMAGE_TAG \
        --amend $IMAGE_NAME:$IMAGE_TAG-amd64 \
        --amend $IMAGE_NAME:$IMAGE_TAG-arm64

      # always create "latest" tag on version push
      docker manifest create $IMAGE_NAME:latest \
        --amend $IMAGE_NAME:latest-amd64 \
        --amend $IMAGE_NAME:latest-arm64

      # create "stable" tag
      docker manifest create $IMAGE_NAME:stable \
        --amend $IMAGE_NAME:stable-amd64 \
        --amend $IMAGE_NAME:stable-arm64

      # create <major> tag (f.e. 4)
      docker manifest create $IMAGE_NAME:$MAJOR_VERSION \
        --amend $IMAGE_NAME:$MAJOR_VERSION-amd64 \
        --amend $IMAGE_NAME:$MAJOR_VERSION-arm64

      # create <major>.<minor> (f.e. 4.0)
      docker manifest create $IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION \
        --amend $IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION-amd64 \
        --amend $IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION-arm64

      # create <major>.<minor>.<patch> (f.e. 4.0.0)
      docker manifest create $IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION \
        --amend $IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-amd64 \
        --amend $IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-arm64

      # push all the created tags
      docker manifest push $IMAGE_NAME:$IMAGE_TAG
      docker manifest push $IMAGE_NAME:stable
      docker manifest push $IMAGE_NAME:latest
      docker manifest push $IMAGE_NAME:$MAJOR_VERSION
      docker manifest push $IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION
      docker manifest push $IMAGE_NAME:$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION
    }

    if [ -n "$FORCE_VERSION_TAG_PUSH" ] && [ "$FORCE_VERSION_TAG_PUSH" -eq "1" ]; then
      echo "Force-enabled version tag push."
      _push
    elif [ -n "$FORCE_VERSION_TAG_PUSH" ] && [ "$FORCE_VERSION_TAG_PUSH" -eq "0" ]; then
      echo "Force-disabled version tag push. Not pushing any other tags."
    elif (git diff HEAD^ ${VERSION_FILE} | tail -n 1 | grep -v '.dev'); then
      echo "Pushing version tags, version has changed in last commit."
      _push
    else
      echo "Not pushing any other tags, version has not changed in last commit."
    fi
}



##############
## Commands ##
##############

function main() {
    [[ $# -lt 1 ]] && { usage; exit 1; }

    command_name=$1
    shift

    # invoke command
    case $command_name in
        "build")               cmd-build "$@" ;;
        "save")                cmd-save "$@" ;;
        "load")                cmd-load "$@" ;;
        "push")                cmd-push "$@" ;;
        "push-manifests")      cmd-push-manifests "$@" ;;
        "help")                usage && exit 0 ;;
        *)                     usage && exit 1 ;;
    esac
}

main "$@"
