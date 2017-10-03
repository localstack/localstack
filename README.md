[![Build Status](https://travis-ci.org/localstack/localstack.png)](https://travis-ci.org/localstack/localstack) [![Backers on Open Collective](https://opencollective.com/localstack/backers/badge.svg)](#backers) [![Sponsors on Open Collective](https://opencollective.com/localstack/sponsors/badge.svg)](#sponsors) [![Coverage Status](https://coveralls.io/repos/github/atlassian/localstack/badge.svg?branch=master)](https://coveralls.io/github/atlassian/localstack?branch=master)
[![Gitter](https://img.shields.io/gitter/room/localstack/Platform.svg)](https://gitter.im/localstack/Platform)
[![PyPI Version](https://badge.fury.io/py/localstack.svg)](https://badge.fury.io/py/localstack)
[![PyPI License](https://img.shields.io/pypi/l/localstack.svg)](https://img.shields.io/pypi/l/localstack.svg)
[![Code Climate](https://codeclimate.com/github/atlassian/localstack/badges/gpa.svg)](https://codeclimate.com/github/atlassian/localstack)
[![Twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/_localstack)

# LocalStack - A fully functional local AWS cloud stack

![LocalStack](https://github.com/localstack/localstack/raw/master/localstack/dashboard/web/img/localstack.png)

*LocalStack* provides an easy-to-use test/mocking framework for developing Cloud applications.

Currently, the focus is primarily on supporting the AWS cloud stack.

# Announcements

* **2017-08-27**: **We need your support!** LocalStack is growing fast, we now have thousands of developers using the platform on a regular basis. Last month we have recorded a staggering 100k test runs, with 25k+ DynamoDB tables, 20k+ SQS queues, 15k+ Kinesis streams, 13k+ S3 buckets, and 10k+ Lambda functions created locally - for 0$ costs (more details to be published soon). Bug and feature requests are pouring in, and we now need some support from _you_ to keep the open source version actively maintained. Please check out [Open Collective](https://opencollective.com/localstack) and become a [backer](https://github.com/localstack/localstack#backers) or [supporter](https://github.com/localstack/localstack#backers) of the project today! Thanks everybody for contributing. ♥
* **2017-07-20**: Please note: Starting with version `0.7.0`, the Docker image will be pushed
and kept up to date under the **new name** `localstack/localstack`. (This means that you may
have to update your CI configurations.) Please refer to the updated
**[End-User License Agreement (EULA)](doc/end_user_license_agreement)** for the new versions.
The old Docker image (`atlassianlabs/localstack`) is still available but will not be maintained
any longer.

# Overview

*LocalStack* spins up the following core Cloud APIs on your local machine:

* **API Gateway** at http://localhost:4567
* **Kinesis** at http://localhost:4568
* **DynamoDB** at http://localhost:4569
* **DynamoDB Streams** at http://localhost:4570
* **Elasticsearch** at http://localhost:4571
* **S3** at http://localhost:4572
* **Firehose** at http://localhost:4573
* **Lambda** at http://localhost:4574
* **SNS** at http://localhost:4575
* **SQS** at http://localhost:4576
* **Redshift** at http://localhost:4577
* **ES (Elasticsearch Service)** at http://localhost:4578
* **SES** at http://localhost:4579
* **Route53** at http://localhost:4580
* **CloudFormation** at http://localhost:4581
* **CloudWatch** at http://localhost:4582
* **SSM** at http://localhost:4583


Additionally, *LocalStack* provides a powerful set of tools to interact with the cloud services, including
a fully featured KCL Kinesis client with Python binding, simple setup/teardown integration for nosetests, as
well as an Environment abstraction that allows to easily switch between local and remote Cloud execution.

## Why *LocalStack*?

*LocalStack* builds on existing best-of-breed mocking/testing tools, most notably
[kinesalite](https://github.com/mhart/kinesalite)/[dynalite](https://github.com/mhart/dynalite)
and [moto](https://github.com/spulec/moto). While these tools are *awesome* (!), they lack functionality
for certain use cases. *LocalStack* combines the tools, makes them interoperable, and adds important
missing functionality on top of them:

* **Error injection:** *LocalStack* allows to inject errors frequently occurring in real Cloud environments,
  for instance `ProvisionedThroughputExceededException` which is thrown by Kinesis or DynamoDB if the amount of
  read/write throughput is exceeded.
* **Actual HTTP REST services**: All services in *LocalStack* allow actual HTTP connections on a TCP port. In contrast,
  moto uses boto client proxies that are injected into all methods annotated with `@mock_sqs`. These client proxies
  do not perform an actual REST call, but rather call a local mock service method that lives in the same process as
  the test code.
* **Language agnostic**: Although *LocalStack* is written in Python, it works well with arbitrary programming
  languages and environments, due to the fact that we are using the actual REST APIs via HTTP.
* **Isolated processes**: All services in *LocalStack* run in separate processes. The overhead of additional
  processes is negligible, and the entire stack can easily be executed on any developer machine and CI server.
  In moto, components are often hard-wired in RAM (e.g., when forwarding a message on an SNS topic to an SQS queue,
  the queue endpoint is looked up in a local hash map). In contrast, *LocalStack* services live in isolation
  (separate processes available via HTTP), which fosters true decoupling and more closely resembles the real
  cloud environment.
* **Pluggable services**: All services in *LocalStack* are easily pluggable (and replaceable), due to the fact that
  we are using isolated processes for each service. This allows us to keep the framework up-to-date and select
  best-of-breed mocks for each individual service.


## Requirements

* `make`
* `python` (both Python 2.x and 3.x supported)
* `pip` (python package manager)
* `npm` (node.js package manager)
* `java`/`javac` (Java 8 runtime environment and compiler)
* `mvn` (Maven, the build system for Java)

## Installing

The easiest way to install *LocalStack* is via `pip`:

```
pip install localstack
```

Once installed, run the infrastructure using the following command:
```
localstack start
```

**Note**: Please do **not** use `sudo` or the `root` user - *LocalStack*
should be installed and started entirely under a local non-root user.

## Running in Docker

You can also spin up *LocalStack* in Docker:

```
localstack start --docker
```

Or using docker-compose (you need to clone the repository first):

```
docker-compose up
```

(Note that on MacOS you may have to run `TMPDIR=/private$TMPDIR docker-compose up` if
`$TMPDIR` contains a symbolic link that cannot be mounted by Docker.)

## Configurations

You can pass the following environment variables to LocalStack:

* `SERVICES`: Comma-separated list of service names and (optional) ports they should run on.
  If no port is specified, a default port is used. Service names basically correspond to the
  [service names of the AWS CLI](http://docs.aws.amazon.com/cli/latest/reference/#available-services)
  (`kinesis`, `lambda`, `sqs`, etc), although LocalStack only supports a subset of them.
  Example value: `kinesis,lambda:4569,sqs:4570` to start Kinesis on the default port,
  Lambda on port 4569, and SQS on port 4570.
* `DEFAULT_REGION`: AWS region to use when talking to the API (defaults to `us-east-1`).
* `HOSTNAME`: Name of the host to expose the services internally (defaults to `localhost`).
  Use this to customize the framework-internal communication, e.g., if services are
  started in different containers using docker-compose.
* `HOSTNAME_EXTERNAL`: Name of the host to expose the services externally (defaults to `localhost`).
  This host is used, e.g., when returning queue URLs from the SQS service to the client.
* `USE_SSL`: Whether to use `https://...` URLs with SSL encryption (defaults to `false`).
* `KINESIS_ERROR_PROBABILITY`: Decimal value between 0.0 (default) and 1.0 to randomly
  inject `ProvisionedThroughputExceededException` errors into Kinesis API responses.
* `DYNAMODB_ERROR_PROBABILITY`: Decimal value between 0.0 (default) and 1.0 to randomly
  inject `ProvisionedThroughputExceededException` errors into DynamoDB API responses.
* `LAMBDA_EXECUTOR`: Method to use for executing Lambda functions. Valid values are `local` (run
  the code in a temporary directory on the local machine) or `docker` (run code in a separate
  Docker container). In the latter case, if *LocalStack* itself is started inside Docker, then
  the `docker` command needs to be available inside the container (usually requires to run the
  container in privileged mode). Default is `docker`, fallback to `local` if Docker is not available.
* `LAMBDA_REMOTE_DOCKER`:
    - when set to `false` (default): your lambda functions definitions will be passed to the container by
      mounting the volume (potentially faster) It is mandatory to have the Docker client and the Docker
      host on the same machine
    - when set to `true`: your lambda functions definitions will be passed to the container by
      copying the zip file (potentially slower). It allows for remote execution, where the host
      and the client are not on the same machine
* `DATA_DIR`: Local directory for saving persistent data (currently only supported for these services:
  Kinesis, DynamoDB, Elasticsearch). Set it to `/tmp/localstack/data` to enable persistence
  (`/tmp/localstack` is mounted into the Docker container), leave blank to disable
  persistence (default).
* `PORT_WEB_UI`: Port for the Web user interface (dashboard). Default is `8080`.
* `<SERVICE>_BACKEND`: Custom endpoint URL to use for a specific service, where `<SERVICE>` is the uppercase
  service name (currently works for: `APIGATEWAY`, `CLOUDFORMATION`, `DYNAMODB`, `ELASTICSEARCH`,
  `KINESIS`, `S3`, `SNS`, `SQS`). This allows to easily integrate third-party services into LocalStack.

Additionally, the following *read-only* environment variables are available:

* `LOCALSTACK_HOSTNAME`: Name of the host where LocalStack services are available.
  This is needed in order to access the services from within your Lambda functions
  (e.g., to store an item to DynamoDB or S3 from Lambda).
  The variable `LOCALSTACK_HOSTNAME` is available for both, local Lambda execution
  (`LAMBDA_EXECUTOR=local`) and execution inside separate Docker containers (`LAMBDA_EXECUTOR=docker`).

## Accessing the infrastructure via CLI or code

You can point your `aws` CLI to use the local infrastructure, for example:

```
aws --endpoint-url=http://localhost:4568 kinesis list-streams
{
    "StreamNames": []
}
```

**NEW**: Check out [awslocal](https://github.com/localstack/awscli-local), a thin CLI wrapper that runs commands directly against *LocalStack* (no need to
specify `--endpoint-url` anymore). Install it via `pip install awscli-local`, and then use it as follows:

```
awslocal kinesis list-streams
{
    "StreamNames": []
}
```

**UPDATE**: Use the environment variable `$LOCALSTACK_HOSTNAME` to determine the target host
inside your Lambda function. See [Configurations](#Configurations) section for more details.

### Client Libraries

* Python: https://github.com/localstack/localstack-python-client
  * alternatively, you can also use `boto3` and use the `endpoint_url` parameter when creating a connection
* (more coming soon...)

## Integration with nosetests

If you want to use *LocalStack* in your integration tests (e.g., nosetests), simply fire up the
infrastructure in your test setup method and then clean up everything in your teardown method:

```
from localstack.services import infra

def setup():
    infra.start_infra(async=True)

def teardown():
    infra.stop_infra()

def my_app_test():
    # here goes your test logic
```

See the example test file `tests/test_integration.py` for more details.

## Integration with Java/JUnit

In order to use *LocalStack* with Java, the project ships with a simple JUnit runner. Take a look
at the example JUnit test in `ext/java`. When you run the test, all dependencies are automatically
downloaded and installed to a temporary directory in your system.

```
...
import cloud.localstack.LocalstackTestRunner;
import cloud.localstack.TestUtils;

@RunWith(LocalstackTestRunner.class)
public class MyCloudAppTest {

  @Test
  public void testLocalS3API() {
    AmazonS3 s3 = TestUtils.getClientS3()
    List<Bucket> buckets = s3.listBuckets();
    ...
  }

}
```

The *LocalStack* JUnit test runner is published as an artifact in Maven Central.
Simply add the following dependency to your `pom.xml` file:

```
<dependency>
    <groupId>cloud.localstack</groupId>
    <artifactId>localstack-utils</artifactId>
    <version>0.1.4</version>
</dependency>
```

### Troubleshooting

* If you're using AWS Java libraries with Kinesis, please, refer to [CBOR protocol issues with the Java SDK guide](https://github.com/mhart/kinesalite#cbor-protocol-issues-with-the-java-sdk) how to disable CBOR protocol which is not supported by kinesalite.

* Accessing local S3 from Java: To avoid domain name resolution issues, you need to enable **path style access** on your client:
```
s3.setS3ClientOptions(S3ClientOptions.builder().setPathStyleAccess(true).build());
// There is also an option to do this if you're using any of the client builder classes:
AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard();
builder.withPathStyleAccessEnabled(true);
...
```

* Mounting the temp. directory: Note that on MacOS you may have to run `TMPDIR=/private$TMPDIR docker-compose up` if
`$TMPDIR` contains a symbolic link that cannot be mounted by Docker.
(See details here: https://bitbucket.org/atlassian/localstack/issues/40/getting-mounts-failed-on-docker-compose-up)

* If you are deploying within OpenShift, please be aware: the pod must run as `root`, and the user must have capabilities added to the running pod, in order to allow Elasticsearch to be run as the non-root `localstack` user.

* The environment variable `no_proxy` is rewritten by *LocalStack*.
(Internal requests will go straight via localhost, bypassing any proxy configuration).

## Developing

If you pull the repo in order to extend/modify LocalStack, run this command to install
all the dependencies:

```
make install
```

This will install the required pip dependencies in a local Python virtualenv directory
`.venv` (your global python packages will remain untouched), as well as some node modules
in `./localstack/node_modules/`. Depending on your system, some pip/npm modules may require
additional native libs installed.

The Makefile contains a target to conveniently run the local infrastructure for development:

```
make infra
```

Check out the
[developer guide](https://github.com/localstack/localstack/tree/master/doc/developer_guides) which
contains a few instructions on how to get started with developing (and debugging) features for
LocalStack.

## Testing

The project contains a set of unit and integration tests that can be kicked off via a make
target:

```
make test
```

## Web Dashboard

The projects also comes with a simple Web dashboard that allows to view the deployed AWS
components and the relationship between them.

```
localstack web
```

## Change Log

* v0.8.1: Improvements in Lambda API: publish-version, list-version, function aliases; use single map with Lambda function details; workaround for SQS .fifo queues; add test for S3 upload; initial support for SSM; fix regex to replace SQS queue URL hostnames; update linter (single quotes); use `docker.for.mac.localhost` to connect to LocalStack from Docker on Mac; fix b64 encoding for Java Lambdas; fix path of moto_server command
* v0.8.0: Fix request data in `GenericProxyHandler`; add `$PORT_WEB_UI` and `$HOSTNAME_EXTERNAL` configs; API Gateway path parameters; enable flake8 linting; add config for service backend URLs; use ElasticMQ instead of moto for SQS; expose `$LOCALSTACK_HOSTNAME`; custom environment variable support for Lambda; improve error logging and installation for Java/JUnit; add support for S3 REST Object POST
* v0.7.5: Fix issue with incomplete parallel downloads; bypass http_proxy for internal requests; use native Python code to unzip archives; download KCL client libs only for testing and not on pip install
* v0.7.4: Refactor CLI and enable plugins; support unicode names for S3; fix SQS names containing a dot character; execute Java Lambda functions in Docker containers; fix DynamoDB error handling; update docs
* v0.7.3: Extract proxy listeners into (sub-)classes; put java libs into a single "fat" jar; fix issue with non-daemonized threads; refactor code to start flask services
* v0.7.2: Fix DATA_DIR config when running in Docker; fix Maven dependencies; return 'ConsumedCapacity' from DynamoDB get-item; use Queue ARN instead of URL for S3 bucket notifications
* v0.7.1: Fix S3 API to GET bucket notifications; release Java artifacts to Maven Central; fix S3 file access from Spark; create DDB stream on UpdateTable; remove AUI dependency, optimize size of Docker image
* v0.7.0: Support for Kinesis in CloudFormation; extend and integrate Java tests in CI; publish Docker image under new name; update READMEs and license agreements
* v0.6.2: Major refactoring of installation process, lazy loading of dependencies
* v0.6.1: Add CORS headers; platform compatibility fixes (remove shell commands and sh module); add CloudFormation validate-template; fix Lambda execution in Docker; basic domain handling in ES API; API Gateway authorizers
* v0.6.0: Load services as plugins; fix service default ports; fix SQS->SNS and MD5 of message attributes; fix Host header for S3
* v0.5.5: Enable SSL encryption for all service endpoints (`USE_SSL` config); create Docker base image; fix issue with DATA_DIR
* v0.5.4: Remove hardcoded /tmp/ for Windows-compat.; update CLI and docs; fix S3/SNS notifications; disable Elasticsearch compression
* v0.5.3: Add CloudFormation support for serverless / API Gateway deployments; fix installation via pypi; minor fix for Java (passing of environment variables)
* v0.5.0: Extend DynamoDB Streams API; fix keep-alive connection for S3; fix deadlock in nested Lambda executions; add integration SNS->Lambda; CloudFormation serverless example; replace dynalite with DynamoDBLocal; support Lambda execution in remote Docker container; fix CloudWatch metrics for Lambda invocation errors
* v0.4.3: Initial support for CloudWatch metrics (for Lambda functions); HTTP forwards for API Gateway; fix S3 message body signatures; download Lambda archive from S3 bucket; fix/extend ES tests
* v0.4.2: Initial support for Java Lambda functions; CloudFormation deployments; API Gateway tests
* v0.4.1: Python 3 compatibility; data persistence; add seq. numbers in Kinesis events; limit Elasticsearch memory
* v0.4.0: Execute Lambda functions in Docker containers; CORS headers for S3
* v0.3.11: Add Route53, SES, CloudFormation; DynamoDB fault injection; UI tweaks; refactor config
* v0.3.10: Add initial support for S3 bucket notifications; fix subprocess32 installation
* v0.3.9: Make services/ports configurable via $SERVICES; add tests for Firehose+S3
* v0.3.8: Fix Elasticsearch via local bind and proxy; refactoring; improve error logging
* v0.3.5: Fix lambda handler name; fix host name for S3 API; install web libs on pip install
* v0.3.4: Fix file permissions in build; fix and add UI to Docker image; add stub of ES API
* v0.3.3: Add version tags to Docker images
* v0.3.2: Add support for Redshift API; code refactoring
* v0.3.1: Add Dockerfile and push image to Docker Hub
* v0.3.0: Add simple integration for JUnit; improve process signal handling
* v0.2.11: Refactored the AWS assume role function
* v0.2.10: Added AWS assume role functionality.
* v0.2.9: Kinesis error response formatting
* v0.2.7: Throw Kinesis errors randomly
* v0.2.6: Decouple SNS/SQS: intercept SNS calls and forward to subscribed SQS queues
* v0.2.5: Return error response from Kinesis if flag is set
* v0.2.4: Allow Lambdas to use __file__ (import from file instead of exec'ing)
* v0.2.3: Improve Kinesis/KCL auto-checkpointing (leases in DDB)
* v0.2.0: Speed up installation time by lazy loading libraries
* v0.1.19: Pass shard_id in records sent from KCL process
* v0.1.16: Minor restructuring and refactoring (create separate kinesis_util.py)
* v0.1.14: Fix AWS tokens when creating Elasticsearch client
* v0.1.11: Add startup/initialization notification for KCL process
* v0.1.10: Bump version of amazon_kclpy to 1.4.1
* v0.1.9: Add initial support for SQS/SNS
* v0.1.8: Fix installation of JARs in amazon_kclpy if localstack is installed transitively
* v0.1.7: Bump version of amazon_kclpy to 1.4.0
* v0.1.6: Add travis-ci and coveralls configuration
* v0.1.5: Refactor Elasticsearch utils; fix bug in method to delete all ES indexes
* v0.1.4: Enhance logging; extend java KCL credentials provider (support STS assumed roles)
* v0.1.2: Add configurable KCL log output
* v0.1.0: Initial release

## Contributing

We welcome feedback, bug reports, and pull requests!

For pull requests, please stick to the following guidelines:

* Add tests for any new features and bug fixes. Ideally, each PR should increase the test coverage.
* Follow the existing code style (e.g., indents). A PEP8 code linting target is included in the Makefile.
* Put a reasonable amount of comments into the code.
* Separate unrelated changes into multiple pull requests.
* 1 commit per PR: Please squash/rebase multiple commits into one single commit (to keep the history clean).

Please note that by contributing any code or documentation to this repository (by
raising pull requests, or otherwise) you explicitly agree to
the [**Contributor License Agreement**](doc/contributor_license_agreement).

## Contributors

This project exists thanks to all the people who contribute.
<a href="graphs/contributors"><img src="https://opencollective.com/localstack/contributors.svg?width=890" /></a>


## Backers

Thank you to all our backers! 🙏 [[Become a backer](https://opencollective.com/localstack#backer)]

<a href="https://opencollective.com/localstack#backers" target="_blank"><img src="https://opencollective.com/localstack/backers.svg?width=890"></a>


## Sponsors

Support this project by becoming a sponsor. Your logo will show up here with a link to your website. [[Become a sponsor](https://opencollective.com/localstack#sponsor)]

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

Copyright (c) 2017 *LocalStack* maintainers and contributors.

Copyright (c) 2016 Atlassian and others.

This version of *LocalStack* is released under the Apache License, Version 2.0 (see LICENSE.txt).
By downloading and using this software you agree to the
[End-User License Agreement (EULA)](doc/end_user_license_agreement).

We build on a number of third-party software tools, with the following licenses:

Third-Party software		| 	License
----------------------------|-----------------------
**Python/pip modules:**		|
airspeed					| BSD License
amazon_kclpy				| Amazon Software License
boto3						| Apache License 2.0
coverage					| Apache License 2.0
docopt						| MIT License
elasticsearch				| Apache License 2.0
flask						| BSD License
flask_swagger				| MIT License
jsonpath-rw					| Apache License 2.0
moto						| Apache License 2.0
nose						| GNU LGPL
pep8						| Expat license
requests					| Apache License 2.0
subprocess32				| PSF License
**Node.js/npm modules:**	|
kinesalite					| MIT License
**Other tools:**			|
Elasticsearch 				| Apache License 2.0
