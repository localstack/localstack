#!/bin/bash

set -e

# use UTC timestamp as version
timestamp=$(date -u +%Y%m%d%H%M%S)
sed -i -r "s/^([0-9]+\.[0-9]+\.[0-9]+\.dev).*/\1${timestamp}/" VERSION

echo "release $(cat VERSION)? (press CTRL+C to abort)"
read
make publish
