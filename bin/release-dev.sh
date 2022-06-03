#!/bin/bash

set -e

# use UTC timestamp as version
ver=$(date -u +%Y%m%d%H%M%S)

sed -i -r "s/^__version__ = \"(.*\.dev)\"/__version__ = \"\1${ver}\"/" localstack/__init__.py


echo "release $(cat localstack/__init__.py | grep '__version__')? (press CTRL+C to abort)"
read
make publish
