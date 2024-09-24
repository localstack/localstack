#!/usr/bin/env bash

set -e

COMMON_DIR=$1
cd $COMMON_DIR

for scenario in */ ; do
  [ -L "${scenario%/}" ] && continue
  cd "$scenario"
  FULL_SCENARIO_PATH=`pwd`

  for runtime in */ ; do
    [ -L "${runtime%/}" ] && continue

    BUILD_PATH="$FULL_SCENARIO_PATH/$runtime"
    echo -n "Making ${scenario}.${runtime} in ${BUILD_PATH}: "
    cd "$BUILD_PATH"

    # skip if the zip file exists, otherwise run the makefile
    [ -f "handler.zip" ] && echo "found handler.zip before building => skip building" && continue
    echo -n "building ..."
    # MAYBE: consider printing build logs only if the build fails (using CircleCI SSH seems easier for now)
    make build >/dev/null

    # if no zipfile, package build folder
    [ -f "handler.zip" ] && echo "found handler.zip after building => skip packaging" && continue
    echo -n "packaging handler.zip ..."
    cd ./build && zip -r ../handler.zip . && cd -
    echo "DONE ${scenario}.${runtime}"
  done

  cd $COMMON_DIR
done
