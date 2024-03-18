#!/bin/bash

set -e

# use UTC timestamp as version
ver=$(date -u +%Y%m%d%H%M%S)

sed -i -r "s/^VERSION\s*=\s*\"(.*\.dev)\"/VERSION = \"\1${ver}\"/" localstack/constants.py


echo "release $(grep -oP '^VERSION\s*=\s*"\K[^"]+' localstack/constants.py)? (press CTRL+C to abort)"
read
make publish
