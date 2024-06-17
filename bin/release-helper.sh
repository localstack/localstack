#!/usr/bin/env bash

set -e

VERSION_FILE=${VERSION_FILE-VERSION}
VERSION_PY=${VERSION_PY-"**/version.py"}
DEPENDENCY_FILE=${DEPENDENCY_FILE-pyproject.toml}

function usage() {
    echo "A set of commands that facilitate release automation"
    echo ""
    echo "USAGE"
    echo "  release-helper <command> [options]"
    echo ""
    echo "Commands:"
    echo "  github-outputs <patch|minor|major>"
    echo "      print version number outputs for github actions"
    echo ""
    echo "  explain-steps <patch|minor|major>"
    echo "      print a list of steps that should be executed for the release type"
    echo ""
    echo "  get-ver"
    echo "      prints the current version number in the version file"
    echo ""
    echo "  next-dev-ver"
    echo "      prints the next development release version from the current version"
    echo ""
    echo "  set-ver <version>"
    echo "      sets the version number in the version file"
    echo "      example: set-ver 0.15.0"
    echo ""
    echo "  set-dep-ver <dep> <range>"
    echo "      set the dependency version in the dependency file"
    echo "      example: set-dep-ver 'localstack-ext' '==0.15.0'"
    echo ""
    echo "  pip-download-retry <dep> <version>"
    echo "      blocks until the given version of the given dependency becomes downloadable by pip"
    echo "      example: pip-download-retry 'localstack-ext' '0.15.0'"
    echo ""
    echo "  git-commit-release <version>"
    echo "      creates a tag and release commit for the given version"
    echo ""
    echo "  git-commit-increment"
    echo "      creates a commit for the next development iteration"
    echo ""
    echo "  help"
    echo "      show this message"
}

function get_current_version() {
    cat ${VERSION_FILE}
}

function remove_ver_suffix() {
    awk -F. '{ print $1 "." $2 "." $3 }'
}

function increment_dev() {
    awk -F. -v time="$(date -u +%Y%m%d%H%M%S)" '{ print $1 "." $2 "." $3 ".dev" time }'
}

function add_dev_suffix() {
    awk -F. '{ print $1 "." $2 "." $3 ".dev" }'
}

function increment_patch() {
    awk -F. '{ print $1 "." $2 "." $3 + 1 }'
}

function increment_minor() {
    awk -F. '{ print $1 "." $2 + 1 "." 0 }'
}

function increment_major() {
    awk -F. '{ print $1 + 1 "." 0 "." 0 }'
}

function verify_valid_version() {
    read ver
    echo $ver | egrep "^([0-9]+)\.([0-9]+)(\.[0-9]+)?" > /dev/null || { echo "invalid version string '$ver'"; exit 1; }
}

function release_env_compute() {
    case $1 in
        "patch")
            RELEASE_VER=$(get_current_version | remove_ver_suffix)
            ;;
        "minor")
            RELEASE_VER=$(get_current_version | increment_minor)
            ;;
        "major")
            RELEASE_VER=$(get_current_version | increment_major)
            ;;
        *)
            echo "unknown release type '$1'"
            exit 1
            ;;
    esac

    export CURRENT_VER=$(get_current_version)
    export RELEASE_VER=${RELEASE_VER}
    export DEVELOP_VER=$(echo ${RELEASE_VER} | increment_patch | add_dev_suffix)
    # uses only the minor version. for 1.0.1 -> patch the boundary would be 1.1
    export BOUNDARY_VER=$(echo ${DEVELOP_VER} | increment_minor | cut -d'.' -f-2)

    release_env_validate || { echo "invalid release environment"; exit 1; }
}

function release_env_validate() {
    echo ${CURRENT_VER} | verify_valid_version
    echo ${RELEASE_VER} | verify_valid_version
    echo ${DEVELOP_VER} | verify_valid_version
    echo ${BOUNDARY_VER} | verify_valid_version
}

function explain_release_steps() {
    echo "- bump VERSION: ${CURRENT_VER} -> ${RELEASE_VER}"
    echo "- set synced dependencies to ==${RELEASE_VER}"
    echo "- perform release"
    echo "  - git commit -a -m 'Release version ${RELEASE_VER}'"
    echo "  - make publish"
    echo "  - git tag -a 'v${RELEASE_VER}' -m 'Release version ${RELEASE_VER}'"
    echo "  - git push && git push --tags"
    echo "- bump VERSION: ${RELEASE_VER} -> ${DEVELOP_VER}"
    echo "- set synced dependencies to >=${DEVELOP_VER},<${BOUNDARY_VER}"
    echo "- prepare development iteration"
    echo "  - git commit -a -m 'Prepare next development iteration'"
    echo "  - git push"
}

function print_github_outputs() {
    echo "current=${CURRENT_VER}" >> $GITHUB_OUTPUT
    echo "release=${RELEASE_VER}" >> $GITHUB_OUTPUT
    echo "develop=${DEVELOP_VER}" >> $GITHUB_OUTPUT
    echo "boundary=${BOUNDARY_VER}" >> $GITHUB_OUTPUT
}

# commands

function cmd-get-ver() {
    [[ $# -eq 0 ]] || { usage; exit 1; }
    get_current_version
}

function cmd-next-dev-ver() {
    [[ $# -eq 0 ]] || { usage; exit 1; }
    get_current_version | increment_dev
}

function cmd-set-ver() {
    [[ $# -eq 1 ]] || { usage; exit 1; }

    echo $1 > ${VERSION_FILE}
}

function cmd-set-dep-ver() {
    [[ $# -eq 2 ]] || { usage; exit 1; }

    dep=$1
    ver=$2

    egrep -h "^(\s*\"?)(${dep})(\[[a-zA-Z0-9,\-]+\])?(>=|==|<=)([^\"]*)(\")?(,)?$" ${DEPENDENCY_FILE} || { echo "dependency ${dep} not found in ${DEPENDENCY_FILE}"; return 1; }
    sed -i -r "s/^(\s*\"?)(${dep})(\[[a-zA-Z0-9,\-]+\])?(>=|==|<=)([^\"]*)(\")?(,)?$/\1\2\3${ver}\6\7/g" ${DEPENDENCY_FILE}
}

function cmd-github-outputs() {
    release_env_compute $1
    print_github_outputs
}

function cmd-explain-steps() {
    release_env_compute $1
    explain_release_steps
}

function cmd-pip-download-retry() {
    [[ $# -eq 2 ]] || { usage; exit 1; }

    dep=$1
    ver=$2

    export pip_download_tmpdir="$(mktemp -d)"
    trap 'rm -rf -- "$pip_download_tmpdir"' EXIT

    while ! pip download -d ${pip_download_tmpdir} --no-deps --pre "${dep}==${ver}" &> /dev/null; do
        sleep 5
    done
}

function cmd-git-commit-release() {
    [[ $# -eq 1 ]] || { usage; exit 1; }

    echo $1 || verify_valid_version

    for file in ${VERSION_FILE} ${VERSION_PY} ${DEPENDENCY_FILE}; do
            git add "$file" || echo "did not add file '$file' to commit"
    done
    git commit -m "release version ${1}"
    git tag -a "v${1}" -m "Release version ${1}"
}

function cmd-git-commit-increment() {
    for file in ${VERSION_FILE} ${VERSION_PY} ${DEPENDENCY_FILE}; do
            [ -e "$file" ] && git add "$file"
    done
    git commit -m "prepare next development iteration"
}

function main() {
    [[ $# -lt 1 ]] && { usage; exit 1; }

    command_name=$1
    shift

    # invoke command
    case $command_name in
        "get-ver")              cmd-get-ver "$@" ;;
        "next-dev-ver")         cmd-next-dev-ver "$@" ;;
        "set-ver")              cmd-set-ver "$@" ;;
        "set-dep-ver")          cmd-set-dep-ver "$@" ;;
        "github-outputs")       cmd-github-outputs "$@" ;;
        "explain-steps")        cmd-explain-steps "$@" ;;
        "pip-download-retry")   cmd-pip-download-retry "$@" ;;
        "git-commit-release")   cmd-git-commit-release "$@" ;;
        "git-commit-increment") cmd-git-commit-increment "$@" ;;
        "help")                 usage && exit 0 ;;
        *)                      usage && exit 1 ;;
    esac
}

main "$@"
