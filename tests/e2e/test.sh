#!/bin/bash

TESTS_TO_RUN=$(find . -name "test_*.sh");

# Start new LocalStack containers for every test
for line in $TESTS_TO_RUN; do
  docker rm -f localstack_main > /dev/null 2>&1
  FORCE_NONINTERACTIVE=true make docker-mount-run &

  while ! curl --connect-timeout 1 http://localhost:4566/ 2>/dev/null | grep 'running'; do
    sleep 20
  done

  RESULT_OUTPUT=$($line 2>/dev/null);
  RESULT_CODE=$?;

  echo "$RESULT_OUTPUT"
  docker rm -f localstack_main > /dev/null 2>&1

  if [[ $RESULT_CODE -ne 0 ]]; then
    exit 1;
  fi
done

# When container is terminated it may throw an error and hang
# the stout, to fix that, we are adding a delay with exit code 0
sleep 5;
exit 0;