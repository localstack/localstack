<p align="center">
  <img src="https://raw.githubusercontent.com/localstack/localstack/master/docs/localstack-readme-banner.svg" alt="LocalStack - A fully functional local cloud stack">
</p>

<p align="center">
  <a href="https://circleci.com/gh/localstack/localstack"><img alt="CircleCI" src="https://img.shields.io/circleci/build/gh/localstack/localstack/master?logo=circleci"></a>
  <a href="https://coveralls.io/github/localstack/localstack?branch=master"><img alt="Coverage Status" src="https://coveralls.io/repos/github/localstack/localstack/badge.svg?branch=master"></a>
  <a href="https://pypi.org/project/localstack/"><img alt="PyPI Version" src="https://img.shields.io/pypi/v/localstack?color=blue"></a>
  <a href="https://hub.docker.com/r/localstack/localstack"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/localstack/localstack"></a>
  <a href="https://pypi.org/project/localstack"><img alt="PyPi downloads" src="https://static.pepy.tech/badge/localstack"></a>
  <a href="#backers"><img alt="Backers on Open Collective" src="https://opencollective.com/localstack/backers/badge.svg"></a>
  <a href="#sponsors"><img alt="Sponsors on Open Collective" src="https://opencollective.com/localstack/sponsors/badge.svg"></a>
  <a href="https://img.shields.io/pypi/l/localstack.svg"><img alt="PyPI License" src="https://img.shields.io/pypi/l/localstack.svg"></a>
  <a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
  <a href="https://github.com/astral-sh/ruff"><img alt="Ruff" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json"></a>
  <a href="https://twitter.com/localstack"><img alt="Twitter" src="https://img.shields.io/twitter/url/http/shields.io.svg?style=social"></a>
</p>

# What is LocalStack?

[LocalStack](https://localstack.cloud) is a cloud service emulator that runs in a single container on your laptop or in your CI environment. With LocalStack, you can run your AWS applications or Lambdas entirely on your local machine without connecting to a remote cloud provider! Whether you are testing complex CDK applications or Terraform configurations, or just beginning to learn about AWS services, LocalStack helps speed up and simplify your testing and development workflow.

LocalStack supports a growing number of AWS services, like AWS Lambda, S3, Dynamodb, Kinesis, SQS, SNS, and many more! You can find a comprehensive list of supported APIs on our [☑️ Feature Coverage](https://docs.localstack.cloud/user-guide/aws/feature-coverage/) page.

LocalStack also provides additional features to make your life as a cloud developer easier! Check out LocalStack's [User Guides](https://docs.localstack.cloud/user-guide/) for more information.

## Usage

Please make sure that you have a working [Docker environment](https://docs.docker.com/get-docker/) on your machine before moving on. You can check if Docker is correctly configured on your machine by executing `docker info` in your terminal. If it does not report an error (but shows information on your Docker system), you’re good to go.

### Docker CLI

You can directly start the LocalStack container using the Docker CLI. This method requires more manual steps and configuration, but it gives you more control over the container settings.

You can start the Docker container simply by executing the following docker run command:

```console
$ docker run --rm -it -p 4566:4566 -p 4510-4559:4510-4559 localstack/localstack
```

Create an s3 bucket with LocalStack's [`awslocal`](https://docs.localstack.cloud/user-guide/integrations/aws-cli/#localstack-aws-cli-awslocal) CLI:

```
$ awslocal s3api create-bucket --bucket sample-bucket
$ awslocal s3api list-buckets
```

**Notes**

- This command reuses the image if it’s already on your machine, i.e. it will **not** pull the latest image automatically from Docker Hub.

- This command does not bind all ports that are potentially used by LocalStack, nor does it mount any volumes. When using Docker to manually start LocalStack, you will have to configure the container on your own (see [`docker-compose.yml`](https://github.com/localstack/localstack/blob/master/docker-compose.yml) and [Configuration](https://docs.localstack.cloud/references/configuration/)). This could be seen as the “expert mode” of starting LocalStack. If you are looking for a simpler method of starting LocalStack, please use the [LocalStack CLI](https://docs.localstack.cloud/getting-started/installation/#localstack-cli).

### Docker Compose

You can start LocalStack with [Docker Compose](https://docs.docker.com/compose/) by configuring a `docker-compose.yml file`. Currently, docker-compose version 1.9.0+ is supported.

```
version: "3.8"

services:
  localstack:
    container_name: "${LOCALSTACK_DOCKER_NAME:-localstack-main}"
    image: localstack/localstack
    ports:
      - "127.0.0.1:4566:4566"            # LocalStack Gateway
      - "127.0.0.1:4510-4559:4510-4559"  # external services port range
    environment:
      # LocalStack configuration: https://docs.localstack.cloud/references/configuration/
      - DEBUG=${DEBUG:-0}
    volumes:
      - "${LOCALSTACK_VOLUME_DIR:-./volume}:/var/lib/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
```

Start the container by running the following command:

```console
$ docker-compose up
```

Create a queue using SQS with LocalStack's [`awslocal`](https://docs.localstack.cloud/user-guide/integrations/aws-cli/#localstack-aws-cli-awslocal) CLI:

```
$ awslocal sqs create-queue --queue-name test-queue
$ awslocal sqs list-queues
```

**Notes**

- This command pulls the current nightly build from the `master` branch (if you don’t have the image locally) and **not** the latest supported version. If you want to use a specific version, set the appropriate localstack image tag at `services.localstack.image` in the `docker-compose.yml` file (for example `localstack/localstack:<version>`).

- This command reuses the image if it’s already on your machine, i.e. it will **not** pull the latest image automatically from Docker Hub.

- Mounting the Docker socket `/var/run/docker.sock` as a volume is required for the Lambda service. Check out the [Lambda providers](https://docs.localstack.cloud/user-guide/aws/lambda/) documentation for more information.

Please note that there are a few pitfalls when configuring your stack manually via docker-compose (e.g., required container name, Docker network, volume mounts, and environment variables). We recommend using the LocalStack CLI to validate your configuration, which will print warning messages in case it detects any potential misconfigurations:

```console
$ localstack config validate
```

## Base Image Tags

We do push a set of different image tags for the LocalStack Docker images. When using LocalStack, you can decide which tag you want to use.These tags have different semantics and will be updated on different occasions:

- `latest` (default)
  - This is our default tag.
    It refers to the latest commit which has been fully tested using our extensive integration test suite.
  - This also entails changes that are part of major releases, which means that this tag can contain breaking changes.
  - This tag should be used if you want to stay up-to-date with the latest changes.
- `stable`
  - This tag refers to the latest tagged release.
    It will be updated with every release of LocalStack.
  - This also entails major releases, which means that this tag can contain breaking changes.
  - This tag should be used if you want to stay up-to-date with releases, but don't necessarily need the latest and greatest changes right away.
- `<major>` (e.g. `3`)
  - These tags can be used to refer to the latest release of a specific major release.
    It will be updated with every minor and patch release within this major release.
  - This tag should be used if you want to avoid any potential breaking changes.
- `<major>.<minor>` (e.g. `3.0`)
  - These tags can be used to refer to the latest release of a specific minor release.
    It will be updated with every patch release within this minor release.
  - This tag can be used if you want to avoid any bigger changes, like new features, but still want to update to the latest bugfix release.
- `<major>.<minor>.<patch>` (e.g. `3.0.2`)
  - These tags can be used if you want to use a very specific release.
    It will not be updated.
  - This tag can be used if you really want to avoid any changes to the image (not even minimal bug fixes).

## Where to get help

Get in touch with the LocalStack Team to report 🐞 [issues](https://github.com/localstack/localstack/issues/new/choose),upvote 👍 [feature requests](https://github.com/localstack/localstack/issues?q=is%3Aissue+is%3Aopen+sort%3Areactions-%2B1-desc+),🙋🏽 ask [support questions](https://docs.localstack.cloud/getting-started/help-and-support/),or 🗣️ discuss local cloud development:

- [LocalStack Slack Community](https://localstack.cloud/contact/)
- [LocalStack Discussion Page](https://discuss.localstack.cloud/)
- [LocalStack GitHub Issue tracker](https://github.com/localstack/localstack/issues)
- [Getting Started - FAQ](https://docs.localstack.cloud/getting-started/faq/)

## License

Copyright (c) 2017-2024 LocalStack maintainers and contributors.

Copyright (c) 2016 Atlassian and others.

This version of LocalStack is released under the Apache License, Version 2.0 (see [LICENSE](https://github.com/localstack/localstack/blob/master/LICENSE.txt)). By downloading and using this software you agree to the [End-User License Agreement (EULA)](https://github.com/localstack/localstack/blob/master/doc/end_user_license_agreement).
