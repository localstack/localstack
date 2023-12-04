<p align="center">
:zap: Join the <a href="https://localstack.cloud/insiders/">LocalStack Insiders program</a> to help us shape the future of LocalStack! Test drive new features & engage in conversations with us so we can learn from your use cases :zap:
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/localstack/localstack/master/doc/localstack-readme-banner.svg" alt="LocalStack - A fully functional local cloud stack">
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
  <a href="https://twitter.com/localstack"><img alt="Twitter" src="https://img.shields.io/twitter/url/http/shields.io.svg?style=social"></a>
</p>

<p align="center">
  LocalStack provides an easy-to-use test/mocking framework for developing cloud applications.
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#installing">Install</a> •
  <a href="#example">Example</a> •
  <a href="#running">Run</a> •
  <a href="#usage">Usage</a> •
  <a href="#releases">Releases</a> •
  <a href="#contributing">Contributing</a>
  <br/>
  <a href="https://docs.localstack.cloud" target="_blank">📖 Docs</a> •
  <a href="https://app.localstack.cloud" target="_blank">💻 Pro version</a> •
  <a href="https://docs.localstack.cloud/references/coverage/" target="_blank">☑️ LocalStack coverage</a>
</p>

---

# Overview

[LocalStack](https://localstack.cloud) is a cloud service emulator that runs in a single container on your laptop or in your CI environment. With LocalStack, you can run your AWS applications or Lambdas entirely on your local machine without connecting to a remote cloud provider! Whether you are testing complex CDK applications or Terraform configurations, or just beginning to learn about AWS services, LocalStack helps speed up and simplify your testing and development workflow.

LocalStack supports a growing number of AWS services, like AWS Lambda, S3, Dynamodb, Kinesis, SQS, SNS, and many more! The [Pro version of LocalStack](https://localstack.cloud/pricing) supports additional APIs and advanced features. You can find a comprehensive list of supported APIs on our [☑️ Feature Coverage](https://docs.localstack.cloud/user-guide/aws/feature-coverage/) page.

LocalStack also provides additional features to make your life as a cloud developer easier! Check out LocalStack's [Cloud Developer Tools](https://docs.localstack.cloud/user-guide/tools/) for more information.

## Installation
The quickest way get started with LocalStack is by using the LocalStack CLI.
It allows you to start and manage the LocalStack Docker container from your command line.
Please make sure that you have a working [`docker` environment](https://docs.docker.com/get-docker/) on your machine before moving on.

### Brew (MacOS or Linux with Homebrew)
Install the LocalStack CLI by using our [official LocalStack Brew Tap](https://github.com/localstack/homebrew-tap):
```
brew install localstack/tap/localstack-cli
```

### Binary download (MacOS, Linux, Windows)
If you do not have Brew on your machine, you can directly download the pre-built LocalStack CLI binary for your system:
- Download the latest release for your platform on [localstack/localstack-cli](https://github.com/localstack/localstack-cli/releases/latest).
- Extract the archive to a folder in your `PATH` variable:
  - MacOS / Linux: ```sudo tar xvzf ~/Downloads/localstack-cli-*-darwin-*-onefile.tar.gz -C /usr/local/bin```

### Python package (MacOS, Linux, Windows)
LocalStack is built with Python.
You can directly install the LocalStack CLI in your Python environment using `pip`.

#### Prerequisites

* `python` (Python 3.8 up to 3.11 supported)

#### Installation
```
python3 -m pip install localstack
```

This installs the `localstack-cli` which is used to run the Docker image that hosts the LocalStack runtime. The `awslocal` CLI for interacting with the local AWS services is installed separately. See the [`awslocal` documentation](https://docs.localstack.cloud/user-guide/integrations/aws-cli/#localstack-aws-cli-awslocal) for installation instructions.

> **Important**: Do not use `sudo` or run as `root` user. LocalStack must be installed and started entirely under a local non-root user. If you have problems with permissions in macOS High Sierra, install with `pip install --user localstack`

## Example

Start LocalStack inside a Docker container by running:

```
 % localstack start -d

     __                     _______ __             __
    / /   ____  _________ _/ / ___// /_____ ______/ /__
   / /   / __ \/ ___/ __ `/ /\__ \/ __/ __ `/ ___/ //_/
  / /___/ /_/ / /__/ /_/ / /___/ / /_/ /_/ / /__/ ,<
 /_____/\____/\___/\__,_/_//____/\__/\__,_/\___/_/|_|

 💻 LocalStack CLI 2.3.0

[20:22:20] starting LocalStack in Docker mode 🐳
[20:22:21] detaching
```

You can query the status of respective services on LocalStack by running:

```
% localstack status services
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Service                  ┃ Status      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ acm                      │ ✔ available │
│ apigateway               │ ✔ available │
│ cloudformation           │ ✔ available │
│ cloudwatch               │ ✔ available │
│ config                   │ ✔ available │
│ dynamodb                 │ ✔ available │
...
```

To use SQS, a fully managed distributed message queuing service, on LocalStack, run:

```shell
% awslocal sqs create-queue --queue-name sample-queue
{
    "QueueUrl": "http://localhost:4566/000000000000/sample-queue"
}
```

Learn more about [LocalStack AWS services](https://docs.localstack.cloud/references/coverage/) and using them with LocalStack's `awslocal` CLI.

## Running

You can run LocalStack through the following options:

- [LocalStack CLI](https://docs.localstack.cloud/getting-started/installation/#localstack-cli)
- [Docker](https://docs.localstack.cloud/getting-started/installation/#docker)
- [Docker Compose](https://docs.localstack.cloud/getting-started/installation/#docker-compose)
- [Helm](https://docs.localstack.cloud/getting-started/installation/#helm)

## Usage

To start using LocalStack, check out our documentation at <https://docs.localstack.cloud>.

- [LocalStack Configuration](https://docs.localstack.cloud/references/configuration/)
- [LocalStack in CI](https://docs.localstack.cloud/user-guide/ci/)
- [LocalStack Integrations](https://docs.localstack.cloud/user-guide/integrations/)
- [LocalStack Tools](https://docs.localstack.cloud/user-guide/tools/)
- [Understanding LocalStack](https://docs.localstack.cloud/references/)
- [Troubleshoot](doc/troubleshoot/README.md)

To use LocalStack with a graphical user interface, you can use the following UI clients:

* [Commandeer desktop app](https://getcommandeer.com)
* [DynamoDB Admin Web UI](https://www.npmjs.com/package/dynamodb-admin)

## Releases

Please refer to [GitHub releases](https://github.com/localstack/localstack/releases) to see the complete list of changes for each release. For extended release notes, please refer to the [LocalStack Discuss](https://discuss.localstack.cloud/c/announcement/5).

## Contributing

If you are interested in contributing to LocalStack:

- Start by reading our [contributing guide](CONTRIBUTING.md).
- Check out our [developer guide](https://docs.localstack.cloud/contributing/).
- Navigate our codebase and [open issues](https://github.com/localstack/localstack/issues).

We are thankful for all the contributions and feedback we receive.

## Get in touch

To get in touch with LocalStack team for bugs/feature requests, support questions or general discussions, please use:

- [LocalStack Slack Community](https://localstack.cloud/contact/)
- [LocalStack Discussion Page](https://discuss.localstack.cloud/)
- [LocalStack GitHub Issue tracker](https://github.com/localstack/localstack/issues)

### Contributors

We are thankful to all the people who have contributed to this project.

<a href="https://github.com/localstack/localstack/graphs/contributors"><img src="https://opencollective.com/localstack/contributors.svg?width=890" /></a>

### Backers

We are also grateful to all our backers who have donated to the project. You can become a backer on [Open Collective](https://opencollective.com/localstack#backer).

<a href="https://opencollective.com/localstack#backers" target="_blank"><img src="https://opencollective.com/localstack/backers.svg?width=890"></a>

### Sponsors

You can also support this project by becoming a sponsor on [Open Collective](https://opencollective.com/localstack#sponsor). Your logo will show up here along with a link to your website.

<a href="https://opencollective.com/localstack/sponsor/0/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/0/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/1/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/1/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/2/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/2/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/3/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/3/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/4/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/4/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/5/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/5/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/6/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/6/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/7/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/7/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/8/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/8/avatar.svg"></a>
<a href="https://opencollective.com/localstack/sponsor/9/website" target="_blank"><img src="https://opencollective.com/localstack/sponsor/9/avatar.svg"></a>

## License

Copyright (c) 2017-2023 LocalStack maintainers and contributors.

Copyright (c) 2016 Atlassian and others.

This version of LocalStack is released under the Apache License, Version 2.0 (see [LICENSE](LICENSE.txt)). By downloading and using this software you agree to the [End-User License Agreement (EULA)](doc/end_user_license_agreement). To know about the external software we use, look at our [third party software tools](doc/third-party-software-tools/README.md) page.
