#!/bin/bash

set -e

# use UTC timestamp as version
timestamp=$(date -u +%Y%m%d%H%M%S)

echo "$timestamp" >> VERSION

echo "release $(cat VERSION)? (press CTRL+C to abort)"
read
make publish
