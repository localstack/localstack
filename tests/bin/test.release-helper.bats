#!/usr/bin/env bats

setup_file() {
  # mock the git binary and just print the command
  function git() {
    echo "git $@"
  }
  export -f git

  # mock python3 / setuptools
  function python3() {
    echo "$TEST_SPECIFIC_VERSION"
  }
  export -f python3
}

_setup_tmp_dependency_file() {
  TMP_DIR=$(mktemp -d -t "release-helper-tmp-dep-file-XXXX")
  cp $BATS_TEST_DIRNAME/../../pyproject.toml $TMP_DIR
  echo "$TMP_DIR/pyproject.toml"
}

@test "help command output" {
  run bin/release-helper.sh help

  [ "$status" -eq 0 ]
}

@test "non-zero exit on unknown command" {
  run bin/release-helper.sh unknown

  [ "$status" -ne 0 ]
}

@test "get-ver prints a correct version" {
  export TEST_SPECIFIC_VERSION="3.6.1.dev45+g15cb62bd5.d20240814"

  run bin/release-helper.sh get-ver

  [ "$status" -eq 0 ]
  [[ "$output" == "3.6.1.dev45+g15cb62bd5.d20240814" ]]
}

@test "set-dep-ver sets dependency version in dependency file" {
  export DEPENDENCY_FILE=$(_setup_tmp_dependency_file)

  run bin/release-helper.sh set-dep-ver "botocore" "==0.0.0"

  [ "$status" -eq 0 ]
  echo $DEPENDENCY_FILE
  cat $DEPENDENCY_FILE | grep "botocore==0.0.0"
}

@test "github-outputs appends metadata to GITHUB_OUTPUT" {
  export GITHUB_OUTPUT=$(mktemp)
  export TEST_SPECIFIC_VERSION="3.6.1.dev45+g15cb62bd5.d20240814"
  run bin/release-helper.sh github-outputs "patch"

  cat $GITHUB_OUTPUT
  [ "$status" -eq 0 ]
  cat $GITHUB_OUTPUT | grep "current=3.6.1.dev45+g15cb62bd5.d20240814"
  cat $GITHUB_OUTPUT | grep "release=3.6.1"
  cat $GITHUB_OUTPUT | grep "develop=3.6.2.dev"
  cat $GITHUB_OUTPUT | grep "boundary=3.7"
}

@test "explain-steps command output" {
  export TEST_SPECIFIC_VERSION="3.6.1.dev45+g15cb62bd5.d20240814"
  run bin/release-helper.sh explain-steps "minor"

  [ "$status" -eq 0 ]
}

@test "pip-download-retry succeeds on successful 'pip download' call" {
  # TODO
  echo "TODO"
}

@test "git-commit-release only creates tag if nothing to commit" {
  # TODO
  echo "TODO"
}

@test "git-commit-release creates commit and tag if dependency file is changed" {
  # TODO
  echo "TODO"
}

@test "git-commit-increment fails if there is nothing to commit" {
  # TODO git-commit-increment really only creates a commit with the dependnecy file
  #      -> It should not even be called if it's not necessary
  echo "TODO"
}
