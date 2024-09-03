#!/usr/bin/env bats

setup_file() {
  # mock the git binary and just print the command
  function git() {
    echo "git $@"
  }
  export -f git

  # mock python3 / pip + setuptools_scm
  function python3() {
    case $2 in
    "setuptools_scm")
      # setuptools_scm returns out test version
      echo "$TEST_SPECIFIC_VERSION"
      ;;
    "pip")
      # pip exits with $TEST_PIP_EXIT_CODE
      echo "python3 $@"
      if [ -n "${TEST_PIP_FAIL-}" ]; then
        return 1
      fi
      ;;
    *)
      # everything else just prints the command
      echo "python3 $@"
    esac
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
  export TEST_SPECIFIC_VERSION="3.6.1.dev45"

  run bin/release-helper.sh get-ver

  [ "$status" -eq 0 ]
  [[ "$output" == "3.6.1.dev45" ]]
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
  export TEST_SPECIFIC_VERSION="3.6.1.dev45"
  run bin/release-helper.sh github-outputs "patch"

  cat $GITHUB_OUTPUT
  [ "$status" -eq 0 ]
  cat $GITHUB_OUTPUT | grep "current=3.6.1.dev45"
  cat $GITHUB_OUTPUT | grep "release=3.6.1"
  cat $GITHUB_OUTPUT | grep "develop=3.6.2.dev"
  cat $GITHUB_OUTPUT | grep "boundary=3.7"
}

@test "explain-steps command output" {
  export TEST_SPECIFIC_VERSION="3.6.1.dev45"
  run bin/release-helper.sh explain-steps "minor"

  [ "$status" -eq 0 ]
}

@test "pip-download-retry succeeds on successful 'pip download' call" {
  run bin/release-helper.sh pip-download-retry "testdep" "0.0.1"

  [ "$status" -eq 0 ]
}

@test "git-commit-release creates (potentially empty) commit and tag" {
  run bin/release-helper.sh git-commit-release "1.0.0"

  [ "$status" -eq 0 ]
  [[ "$output" =~ "git commit --allow-empty -m release version 1.0.0" ]]
  [[ "$output" =~ "git tag -a v1.0.0" ]]
}

@test "git-commit-increment creates (potentially empty) commit" {
  run bin/release-helper.sh git-commit-increment

  [ "$status" -eq 0 ]
  [[ "$output" =~ "git commit --allow-empty -m prepare next development iteration" ]]
}

@test "get-ver throws error when setuptools-scm is not installed" {
  export TEST_PIP_FAIL=1

  run bin/release-helper.sh get-ver
  [ "$status" -eq 1 ]
  [[ "$output" =~ "ERROR" ]]
}
