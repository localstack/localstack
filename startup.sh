#!/bin/bash

make infra > /tmp/infra.log 2>&1 &
make web > /tmp/dashboard.log 2>&1 &
