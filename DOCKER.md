
# Quick reference

<p align="center">
  Maintained by <a href="https://www.localstack.cloud/">LocalStack</a>,  with contributions from our  <a href="https://www.localstack.cloud/" target="_blank">community</a> </p>
<p align="center">
  <a href="https://docs.localstack.cloud" target="_blank">📖 Docs</a> •
  <a href="https://app.localstack.cloud" target="_blank">💻 Pro version</a> •
  <a href="https://docs.localstack.cloud/references/coverage/" target="_blank">☑️ LocalStack coverage</a>
</p>

**Where to get help?**

Get in touch with the LocalStack Team to report 🐞 [issues](https://github.com/localstack/localstack/issues/new/choose),upvote 👍 [feature requests](https://github.com/localstack/localstack/issues?q=is%3Aissue+is%3Aopen+sort%3Areactions-%2B1-desc+),🙋🏽 ask [support questions](https://docs.localstack.cloud/getting-started/help-and-support/),or 🗣️ discuss local cloud development:

- [LocalStack Slack Community](https://localstack.cloud/contact/)
- [LocalStack Discussion Page](https://discuss.localstack.cloud/)
- [LocalStack GitHub Issue tracker](https://github.com/localstack/localstack/issues)

**Supported base image tags:** 

- `latest-` , `stable-` and `3.xx-` tags. Versioned tags contain their version, the `latest-` tags contain the latest release and `stable-` tags contain  stable  release.

**Supported Architectures:** [[more info](https://docs.localstack.cloud/references/arm64-support/)]
- [`amd64`](https://hub.docker.com/r/localstack/localstack/tags?page=1&name=amd64), [`arm64v8`](https://hub.docker.com/r/localstack/localstack/tags?page=1&name=arm64) 
  
**Source of this description:**  
 [github.com/localstack/localstack](https://github.com/localstack/localstack) 

# What is LocalStack?

<p align="center">
  <img src="https://raw.githubusercontent.com/localstack/localstack/master/doc/localstack-readme-banner.svg" alt="LocalStack - A fully functional local cloud stack">
</p>

[LocalStack](https://localstack.cloud) is a cloud service emulator that runs in a single container on your laptop or in your CI environment. With LocalStack, you can run your AWS applications or Lambdas entirely on your local machine without connecting to a remote cloud provider! Whether you are testing complex CDK applications or Terraform configurations, or just beginning to learn about AWS services, LocalStack helps speed up and simplify your testing and development workflow.

LocalStack supports a growing number of AWS services, like AWS Lambda, S3, Dynamodb, Kinesis, SQS, SNS, and many more! The [Pro version of LocalStack](https://localstack.cloud/pricing) supports additional APIs and advanced features. You can find a comprehensive list of supported APIs on our [☑️ Feature Coverage](https://docs.localstack.cloud/user-guide/aws/feature-coverage/) page.

LocalStack also provides additional features to make your life as a cloud developer easier! Check out LocalStack's [User Guides](https://docs.localstack.cloud/user-guide/) for more information.

## How to use this image
Please make sure that you have a working [docker environment](https://docs.docker.com/get-docker/) on your machine before moving on. You can check if docker is correctly configured on your machine by executing `docker info` in your terminal. If it does not report an error (but shows information on your Docker system), you’re good to go.

###Starting LocalStack with Docker 

You can directly start the LocalStack container using the Docker CLI. This method requires more manual steps and configuration, but it gives you more control over the container settings.

You can start the Docker container simply by executing the following docker run command:

**For the community version:**
```console
$ docker run --rm -it -p 4566:4566 -p 4510-4559:4510-4559 localstack/localstack
```
**For the pro version:**

```console
$ docker run --rm -it -p 4566:4566 -p 4510-4559:4510-4559 -e LOCALSTACK_AUTH_TOKEN=${LOCALSTACK_AUTH_TOKEN:?} localstack/localstack-pro
```

**Notes**
  - This command pulls the current nightly build from the master branch (if you don’t have the image locally) and not the latest supported version. If you want to use a specific version of LocalStack, use the appropriate tag: `docker run --rm -it -p 4566:4566 -p 4510-4559:4510-4559 localstack/localstack:<tag>`. Check-out the [LocalStack releases](https://github.com/localstack/localstack/releases) to know more about specific LocalStack versions.

- If you are using LocalStack with an [auth token](https://docs.localstack.cloud/getting-started/auth-token/), you need to specify the image tag as `localstack/localstack-pro` in your Docker setup. Going forward, `localstack/localstack-pro` image will contain our Pro-supported services and APIs.

- This command reuses the image if it’s already on your machine, i.e. it will **not** pull the latest image automatically from Docker Hub.

- This command does not bind all ports that are potentially used by LocalStack, nor does it mount any volumes. When using Docker to manually start LocalStack, you will have to configure the container on your own (see [docker-compose-pro.yml](https://github.com/localstack/localstack/blob/master/docker-compose-pro.yml) and [Configuration](https://docs.localstack.cloud/references/configuration/)). This could be seen as the “expert mode” of starting LocalStack. If you are looking for a simpler method of starting LocalStack, please use the [LocalStack CLI](https://docs.localstack.cloud/getting-started/installation/#localstack-cli).

- To facilitate interoperability, configuration variables can be prefixed with `LOCALSTACK_` in docker. For instance, setting `LOCALSTACK_PERSISTENCE=1` is equivalent to `PERSISTENCE=1`.

- To configure an auth token, refer to the [auth token](https://docs.localstack.cloud/getting-started/auth-token/) documentation.

###Starting LocalStack with Docker-Compose

You can start LocalStack with [Docker Compose](https://docs.docker.com/compose/) by configuring a `docker-compose.yml file`. Currently, docker-compose version 1.9.0+ is supported.

Prerequisites [docker](https://docs.docker.com/get-docker/) and [docker-compose](https://docs.docker.com/compose/install/)

**For the community version:**

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

**For the pro version:**

```
version: "3.8"

services:
  localstack:
    container_name: "${LOCALSTACK_DOCKER_NAME:-localstack-main}"
    image: localstack/localstack-pro  # required for Pro
    ports:
      - "127.0.0.1:4566:4566"            # LocalStack Gateway
      - "127.0.0.1:4510-4559:4510-4559"  # external services port range
      - "127.0.0.1:443:443"              # LocalStack HTTPS Gateway (Pro)
    environment:
      # Activate LocalStack Pro: https://docs.localstack.cloud/getting-started/auth-token/
      - LOCALSTACK_AUTH_TOKEN=${LOCALSTACK_AUTH_TOKEN:?}  # required for Pro
      # LocalStack configuration: https://docs.localstack.cloud/references/configuration/
      - DEBUG=${DEBUG:-0}
      - PERSISTENCE=${PERSISTENCE:-0}
    volumes:
      - "${LOCALSTACK_VOLUME_DIR:-./volume}:/var/lib/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
```

Start the container by running the following command:

```console
$ docker-compose up
```

**Notes**
- This command pulls the current nightly build from the `master` branch (if you don’t have the image locally) and **not** the latest supported version. If you want to use a specific version, set the appropriate localstack image tag at `services.localstack.image` in the `docker-compose.yml` file (for example `localstack/localstack:<version>`).

- If you are using LocalStack with an [auth token](https://docs.localstack.cloud/getting-started/auth-token/), you need to specify the image tag as `localstack/localstack-pro` in the `docker-compose.yml` file. Going forward, `localstack/localstack-pro` image will contain our Pro-supported services and APIs.

- This command reuses the image if it’s already on your machine, i.e. it will **not** pull the latest image automatically from Docker Hub.

- Mounting the Docker socket `/var/run/docker.sock` as a volume is required for the Lambda service. Check out the [Lambda providers](https://docs.localstack.cloud/user-guide/aws/lambda/) documentation for more information.

- To facilitate interoperability, configuration variables can be prefixed with `LOCALSTACK_` in docker. For instance, setting `LOCALSTACK_PERSISTENCE=1` is equivalent to `PERSISTENCE=1`.

- If using the Docker default bridge network using `network_mode: bridge`, container name resolution will not work inside your containers. Please consider removing it, if this functionality is needed.

- To configure an auth token, refer to the [auth token](https://docs.localstack.cloud/getting-started/auth-token/) documentation.

Please note that there are a few pitfalls when configuring your stack manually via docker-compose (e.g., required container name, Docker network, volume mounts, and environment variables). We recommend using the LocalStack CLI to validate your configuration, which will print warning messages in case it detects any potential misconfigurations:

```console
$ localstack config validate
```
## License

Copyright (c) 2017-2024 LocalStack maintainers and contributors.

Copyright (c) 2016 Atlassian and others.

This version of LocalStack is released under the Apache License, Version 2.0 (see [LICENSE](LICENSE.txt)). By downloading and using this software you agree to the [End-User License Agreement (EULA)](doc/end_user_license_agreement). To know about the external software we use, look at our [third party software tools](doc/third-party-software-tools/README.md) page.
