#!/usr/bin/env bats

setup_file() {
  # mock the docker binary and just pint the command
  function docker() {
    echo "docker $@"
  }
  export -f docker
}

@test "help command output" {
  run bin/docker-helper.sh help
  [ "$status" -eq 0 ]
}

@test "non-zero exit on unknown command" {
  run bin/docker-helper.sh unknown
  [ "$status" -ne 0 ]
}

@test "build fails on missing IMAGE_NAME" {
  run bin/docker-helper.sh build
  [ "$status" -ne 0 ]
}

# build

@test "build creates image from custom Dockerfile" {
  export IMAGE_NAME="localstack/test"
  export DOCKERFILE="tests/bin/files/Dockerfile"
  export VERSION_FILE="tests/bin/files/VERSION"
  run bin/docker-helper.sh build
  [ "$status" -eq 0 ]
  [[ "$output" =~ "-f tests/bin/files/Dockerfile" ]]
}

# save

@test "save fails without platform" {
  export IMAGE_NAME="localstack/test"
  run bin/docker-helper.sh save
  [ "$status" -ne 0 ]
}

@test "save calls docker save" {
  export IMAGE_NAME="localstack/test"
  export PLATFORM="amd64"
  export IMAGE_FILENAME="$(mktemp)"
  export GITHUB_OUTPUT="$(mktemp)"

  run bin/docker-helper.sh save
  [ "$status" -eq 0 ]
  # our mocking actually only exports the command to stdin, so the IMAGE_FILENAME will actually contain the command
  cat $IMAGE_FILENAME | grep -v "docker save"
  cat $IMAGE_FILENAME | grep -v "$IMAGE_NAME"
  cat $IMAGE_FILENAME | grep -v "docker-image-$PLATFORM.tar.gz"
  # check that it sets the github output
  cat $GITHUB_OUTPUT | grep -v "SAVED_IMAGE_FILENAME="
}

# load

@test "load fails without platform" {
  export IMAGE_NAME="localstack/test"
  run bin/docker-helper.sh load
  [ "$status" -ne 0 ]
}

@test "load calls docker load" {
  export IMAGE_NAME="localstack/test"
  export PLATFORM="amd64"
  run bin/docker-helper.sh load
  [ "$status" -eq 0 ]
  # check for parts of the output
  [[ "$output" =~ "docker load" ]]
  [[ "$output" =~ "docker-image-$PLATFORM.tar" ]]
}

# push

@test "push fails on non-default branch" {
  export MAIN_BRANCH="non-existing-branch"
  export IMAGE_NAME="localstack/test"
  export PLATFORM=amd64
  run bin/docker-helper.sh push
  [ "$status" -ne 0 ]
  [[ "$output" =~ "is not non-existing-branch" ]]
}

@test "push fails without PLATFORM" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  run bin/docker-helper.sh push
  [ "$status" -ne 0 ]
  [[ "$output" =~ "PLATFORM is missing" ]]
}

@test "push pushes built image wo versions" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  export PLATFORM=arm64
  export FORCE_VERSION_TAG_PUSH=0
  export VERSION_FILE="$BATS_TEST_DIRNAME/files/VERSION"
  run bin/docker-helper.sh push
  [ "$status" -eq 0 ]
  [[ "$output" =~ "docker push $IMAGE_NAME:latest-$PLATFORM" ]]
  [[ "$output" =~ "Not pushing any other tags" ]]
  ! [[ "$output" =~ "docker push $IMAGE_NAME:0-$PLATFORM" ]]
  ! [[ "$output" =~ "docker push $IMAGE_NAME:0.0-$PLATFORM" ]]
  ! [[ "$output" =~ "docker push $IMAGE_NAME:0.0.1-$PLATFORM" ]]
  ! [[ "$output" =~ "docker push $IMAGE_NAME:stable-$PLATFORM" ]]
}

@test "push pushes built image w versions" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  export PLATFORM=arm64
  export FORCE_VERSION_TAG_PUSH=1
  export VERSION_FILE="$BATS_TEST_DIRNAME/files/VERSION"
  run bin/docker-helper.sh push
  [ "$status" -eq 0 ]
  [[ "$output" =~ "docker push $IMAGE_NAME:latest-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:0-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:0.0-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:0.0.1-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:stable-$PLATFORM" ]]
}

@test "push pushes built image w custom IMAGE_TAG and DEFAULT_TAG" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  export PLATFORM=arm64
  export FORCE_VERSION_TAG_PUSH=1
  export DEFAULT_TAG="custom-default-tag"
  export IMAGE_TAG=1.2.3
  run bin/docker-helper.sh push
  [ "$status" -eq 0 ]
  [[ "$output" =~ "docker push $IMAGE_NAME:custom-default-tag-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:latest-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:1-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:1.2-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:1.2.3-$PLATFORM" ]]
  [[ "$output" =~ "docker push $IMAGE_NAME:stable-$PLATFORM" ]]
}

# push-manifests

@test "push-manifests works without FORCE_VERSION_TAG_PUSH" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  export VERSION_FILE="$BATS_TEST_DIRNAME/files/VERSION"
  run bin/docker-helper.sh push-manifests
  [ "$status" -eq 0 ]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:latest" ]]
}

@test "push-manifests pushes built image wo versions" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  export VERSION_FILE="$BATS_TEST_DIRNAME/files/VERSION"
  export FORCE_VERSION_TAG_PUSH=0
  run bin/docker-helper.sh push-manifests
  [ "$status" -eq 0 ]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:latest" ]]
  [[ "$output" =~ "Not pushing any other tags" ]]
  ! [[ "$output" =~ "docker manifest push $IMAGE_NAME:0" ]]
  ! [[ "$output" =~ "docker manifest push $IMAGE_NAME:0.0" ]]
  ! [[ "$output" =~ "docker manifest push $IMAGE_NAME:0.0.1" ]]
  ! [[ "$output" =~ "docker manifest push $IMAGE_NAME:stable" ]]
}

@test "push-manifests pushes built image w versions" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  export VERSION_FILE="$BATS_TEST_DIRNAME/files/VERSION"
  export FORCE_VERSION_TAG_PUSH=1
  run bin/docker-helper.sh push-manifests
  [ "$status" -eq 0 ]
  [[ "$output" =~ "docker manifest create $IMAGE_NAME:latest --amend $IMAGE_NAME:latest-amd64 --amend $IMAGE_NAME:latest-arm64" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:$IMAGE_TAG" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:latest" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:0" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:0.0" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:0.0.1" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:stable" ]]
}

@test "push-manifests pushes built image w custom IMAGE_TAG and DEFAULT_TAG" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  export DEFAULT_TAG="custom-default-tag"
  export IMAGE_TAG=1.2.3
  export FORCE_VERSION_TAG_PUSH=1
  run bin/docker-helper.sh push-manifests
  [ "$status" -eq 0 ]
  [[ "$output" =~ "docker manifest create $IMAGE_NAME:custom-default-tag --amend $IMAGE_NAME:custom-default-tag-amd64 --amend $IMAGE_NAME:custom-default-tag-arm64" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:$IMAGE_TAG" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:custom-default-tag" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:latest" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:1" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:1.2" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:1.2.3" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:stable" ]]
}

@test "push-manifests always pushes latest tag w versions" {
  export IMAGE_NAME="localstack/test"
  export MAIN_BRANCH="`git branch --show-current`"
  export DOCKER_USERNAME=test
  export DOCKER_PASSWORD=test
  export VERSION_FILE="$BATS_TEST_DIRNAME/files/VERSION"
  export DEFAULT_TAG="dev"
  export FORCE_VERSION_TAG_PUSH=1
  run bin/docker-helper.sh push-manifests
  [ "$status" -eq 0 ]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:stable" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:latest" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:dev" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:0" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:0.0" ]]
  [[ "$output" =~ "docker manifest push $IMAGE_NAME:0.0.1" ]]
}