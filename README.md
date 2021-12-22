<p align="center">
  <img src="https://raw.githubusercontent.com/localstack/localstack/master/doc/localstack-readme-header.png" alt="LocalStack - A fully functional local cloud stack">
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
  <a href="https://twitter.com/_localstack"><img alt="Twitter" src="https://img.shields.io/twitter/url/http/shields.io.svg?style=social"></a>
</p>

<p align="center">
  <i>LocalStack</i> provides an easy-to-use test/mocking framework for developing Cloud applications.
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#installing">Install</a> •
  <a href="#example">Example</a> •
  <a href="#running">Run</a> •
  <a href="#usage">Usage</a> •
  <a href="#change-log">Changelog</a> •
  <a href="#contributing">Contributing</a>
  <br>–<br>
  <a href="https://docs.localstack.cloud" target="_blank">📖 Docs</a> •
  <a href="https://app.localstack.cloud" target="_blank">💻 Pro version</a> •
  <a href="https://docs.localstack.cloud/aws/feature-coverage/" target="_blank">☑️ Feature coverage</a> •
  <a href="#announcements">📢 Announcements</a>
</p>

---

# Overview

[LocalStack 💻](https://localstack.cloud) is a cloud service emulator that runs in a single container on your laptop or in your CI environment. With LocalStack, you can run your AWS applications or Lambdas entirely on your local machine without connecting to a remote cloud provider! Whether you are testing complex CDK applications or Terraform configurations, or just beginning to learn about AWS services, LocalStack helps speed up and simplify your testing and development workflow.

LocalStack supports a growing number of AWS services, like AWS Lambda, S3, Dynamodb, Kinesis, SQS, SNS, and **many** more! The [**Pro version** of LocalStack](https://localstack.cloud/pricing) supports additional APIs and advanced features. You can find a comprehensive list of supported APIs on our [☑️ Feature Coverage](https://docs.localstack.cloud/aws/feature-coverage/) page.

LocalStack also provides additional features to make your life as a cloud developer easier! Check out LocalStack's [Cloud Developer Tools](https://docs.localstack.cloud/tools/) for more information.

## Requirements

* `python` (Python 3.6 up to 3.9 supported)
* `pip` (Python package manager)
* `Docker`

## Installing

The easiest way to install LocalStack is via `pip`:

```
pip install localstack
```

**Note**: Please do **not** use `sudo` or the `root` user - LocalStack should be installed and started entirely under a local non-root user. If you have problems with permissions in MacOS X Sierra, install with `pip install --user localstack`

It installs the `localstack-cli` which is used to run the Docker image that hosts the LocalStack runtime. 

## Example

Start LocalStack inside a Docker container by running:

```
 % localstack start -d

     __                     _______ __             __
    / /   ____  _________ _/ / ___// /_____ ______/ /__
   / /   / __ \/ ___/ __ `/ /\__ \/ __/ __ `/ ___/ //_/
  / /___/ /_/ / /__/ /_/ / /___/ / /_/ /_/ / /__/ ,<
 /_____/\____/\___/\__,_/_//____/\__/\__,_/\___/_/|_|

 💻 LocalStack CLI 0.13.0.11

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

To use SQS, a fully managed distributed message queuing service, on LocalStack run:

```shell
% awslocal sqs create-queue --queue-name sample-queue
{
    "QueueUrl": "http://localhost:4566/000000000000/sample-queue"
}
```

Learn more about [LocalStack AWS services](https://docs.localstack.cloud/aws/) and using them with LocalStack's `awslocal` CLI.

## Running

You can run LocalStack through the following options:

- [LocalStack CLI](https://docs.localstack.cloud/get-started/#localstack-cli)
- [Docker](https://docs.localstack.cloud/get-started/#docker)
- [Docker Compose](https://docs.localstack.cloud/get-started/#docker-compose)
- [Helm](https://docs.localstack.cloud/get-started/#helm)

## Usage

To start using LocalStack, check out our documentation on [docs.localstack.cloud](https://docs.localstack.cloud).

- [LocalStack Configuration](https://docs.localstack.cloud/localstack/configuration/)
- [LocalStack in CI](https://docs.localstack.cloud/ci/)
- [LocalStack Integrations](https://docs.localstack.cloud/integrations/)
- [LocalStack Tools](https://docs.localstack.cloud/tools/)
- [Understanding LocalStack](https://docs.localstack.cloud/localstack/)
- [Troubleshoot](doc/troubleshoot/README.md)

To use LocalStack with a graphical user interface, you can use the following UI clients:

* [Commandeer desktop app](https://getcommandeer.com)
* [DynamoDB Admin Web UI](https://www.npmjs.com/package/dynamodb-admin)

## Change Log

Please refer to [`CHANGELOG.md`](CHANGELOG.md) to see the complete list of changes for each release.

## Contributing

If you are interested in contributing to LocalStack:

- Start by reading our [contributing guide](CONTRIBUTING.md).
- Check out our [developer guide](https://docs.localstack.cloud/developer-guide/).
- Look through our [roadmap](https://roadmap.localstack.cloud/).
- Navigate our codebase and [open issues](https://github.com/localstack/localstack/issues).

We are thankful for all the contributions and feedback we receive.

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

Copyright (c) 2017-2021 LocalStack maintainers and contributors.

Copyright (c) 2016 Atlassian and others.

This version of LocalStack is released under the Apache License, Version 2.0 (see LICENSE.txt).
By downloading and using this software you agree to the
[End-User License Agreement (EULA)](doc/end_user_license_agreement).

We build on a number of third-party software tools, including the following:

Third-Party software      |   License
--------------------------|-----------------------
**Python/pip modules:**   |
airspeed                  | BSD License
amazon_kclpy              | Amazon Software License
boto3                     | Apache License 2.0
coverage                  | Apache License 2.0
docopt                    | MIT License
elasticsearch             | Apache License 2.0
flask                     | BSD License
flask_swagger             | MIT License
jsonpath-rw               | Apache License 2.0
moto                      | Apache License 2.0
requests                  | Apache License 2.0
subprocess32              | PSF License
**Node.js/npm modules:**  |
kinesalite                | MIT License
**Other tools:**          |
Elasticsearch             | Apache License 2.0
local-kms                 | MIT License
kinesis-mock              | MIT License

# Announcements

* **2021-09-24**: **We're hiring again!** - We are expanding our team, and looking for full-stack Python engineers, technical writers, and more, to help us take LocalStack to the next level! Check out our [jobs board](https://localstack.cloud/jobs)!
* **2021-04-24**: **We're hiring!** - If you love what we're doing at LocalStack, check out our [jobs board](https://localstack.cloud/jobs) and shoot us an email with your CV/background/portfolio. We look forward to hearing from you!
* **2020-12-28**: Check out the LocalStack Pro **feature roadmap** here: https://roadmap.localstack.cloud - please help us prioritize our backlog by creating and upvoting feature requests. Looking forward to getting your feedback!
* **2020-09-15**: A major (breaking) change has been merged in PR #2905 - starting with releases after `v0.11.5`, all services are now exposed via the edge service (port 4566) only! Please update your client configurations to use this new endpoint.
* **2019-10-09**: **LocalStack Pro is out!** We're incredibly excited to announce the launch of LocalStack Pro - the enterprise version of LocalStack with additional APIs and advanced features. Check out the free trial at https://localstack.cloud
* **2018-01-10**: **Help wanted!** Please [fill out this survey](https://lambdastudy.typeform.com/to/kDUvvy?source=localstack-github) to support a research study on the usage of Serverless and Function-as-a-Service (FaaS) services, conducted at the Chalmers University of Technology. The survey only takes 5-10 minutes of your time. Many thanks for your participation!!
  * The result from this study can be found [here](https://research.chalmers.se/en/publication/508147)
* **2017-08-27**: **We need your support!** LocalStack is growing fast, we now have thousands of developers using the platform regularly. Last month we have recorded a staggering 100k test runs, with 25k+ DynamoDB tables, 20k+ SQS queues, 15k+ Kinesis streams, 13k+ S3 buckets, and 10k+ Lambda functions created locally - for 0$ costs (more details to be published soon). Bug and feature requests are pouring in, and we now need some support from _you_ to keep the open-source version actively maintained. Please check out [Open Collective](https://opencollective.com/localstack) and become a [backer](https://github.com/localstack/localstack#backers) or [supporter](https://github.com/localstack/localstack#backers) of the project today! Thanks, everybody for contributing. ♥
* **2017-07-20**: Please note: Starting with version `0.7.0`, the Docker image will be pushed
and kept up to date under the **new name** `localstack/localstack`. (This means that you may
have to update your CI configurations.) Please refer to the updated
**[End-User License Agreement (EULA)](doc/end_user_license_agreement)** for the new versions.
The old Docker image (`atlassianlabs/localstack`) is still available but will not be maintained
any longer.
