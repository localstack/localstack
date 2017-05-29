[![Build Status](https://travis-ci.org/atlassian/localstack.png)](https://travis-ci.org/atlassian/localstack)
[![Coverage Status](https://coveralls.io/repos/github/atlassian/localstack/badge.svg?branch=master)](https://coveralls.io/github/atlassian/localstack?branch=master)
[![PyPI Version](https://badge.fury.io/py/localstack.svg)](https://badge.fury.io/py/localstack)
[![PyPI License](https://img.shields.io/pypi/l/localstack.svg)](https://img.shields.io/pypi/l/localstack.svg)
[![Code Climate](https://codeclimate.com/github/atlassian/localstack/badges/gpa.svg)](https://codeclimate.com/github/atlassian/localstack)

# LocalStack - A fully functional local AWS cloud stack

![LocalStack](https://i.imgsafe.org/fe38108cd6.png)

**Please note: The main version of this repository is https://bitbucket.org/atlassian/localstack, please raise PRs against that repo.**

*LocalStack* provides an easy-to-use test/mocking framework for developing Cloud applications.

Currently, the focus is primarily on supporting the AWS cloud stack.

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
  best-of-breed mocks for each individual service (e.g., kinesalite is much more advanced than its moto counterpart).


## Requirements

* `make`
* `python` (both Python 2.x and 3.x supported)
* `pip` (python package manager)
* `npm` (node.js package manager)
* `java`/`javac` (Java runtime environment and compiler)
* `mvn` (Maven, the build system for Java)

## Installing

The easiest way to install *LocalStack* is via `pip`:

```
pip install localstack
```

## Running in Docker

You can also spin up *LocalStack* without any installation requirements, using Docker:

```
make docker-run
```

Or using docker-compose:

```
docker-compose up
```

## Configurations

You can pass the following environment variables to LocalStack:

* `SERVICES`: Comma-separated list of service names and (optional) ports they should run on.
  If no port is specified, a default port is used. Service names basically correspond to the
  [service names of the AWS CLI](http://docs.aws.amazon.com/cli/latest/reference/#available-services)
  (`kinesis`, `lambda`, `sqs`, etc), although LocalStack only supports a subset of them.
  Example value: `kinesis,lambda:4569,sqs:4570` to start Kinesis on the default port,
  Lambda on port 4569, and SQS on port 4570.
* `DEFAULT_REGION`: AWS region to use when talking to the API (defaults to `us-east-1`).
* `HOSTNAME`: If you need to expose your services on a specific host
  (defaults to `localhost`).
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

## Testing

The project comes with a set of unit and integration tests which can be kicked off via a make
target:

```
make test
```

## Running the infrastructure

The Makefile contains a target to conveniently run the local infrastructure.

```
make infra
```

Then you can point your `aws` CLI to use the local infrastructure, for example:

```
aws --endpoint-url=http://localhost:4568 kinesis list-streams
{
    "StreamNames": []
}
```

If you are accessing the cloud APIs from within yout Python code, you can also use `boto3` and use
the `endpoint_url` parameter to connect to the respective service on `localhost`.
See `localstack.utils.aws.aws_stack` for convenience methods to connect to the local services.

## Integration with nosetests

If you want to use *LocalStack* in your integration tests (e.g., nosetests), simply fire up the
infrastructure in your test setup method and then clean up everything in your teardown method:

```
from localstack.mock import infra

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
@RunWith(LocalstackTestRunner.class)
public class MyCloudAppTest {

  @Test
  public void testLocalS3API() {
    AmazonS3 s3 = new AmazonS3Client(...);
    s3.setEndpoint(LocalstackTestRunner.getEndpointS3());
    List<Bucket> buckets = s3.listBuckets();
    ...
  }

}
```

The *LocalStack* JUnit test runner is published as a Maven artifact in the Bitbucket repository.
Simply add the following configuration to your `pom.xml` file:

```
<project ...>
  ...
  <dependencies>
    ...
    <dependency>
      <groupId>com.atlassian</groupId>
      <artifactId>localstack-utils</artifactId>
      <version>1.0-SNAPSHOT</version>
    </dependency>
  </dependencies>

  <repositories>
    <repository>
      <id>localstack-repo</id>
      <url>https://bitbucket.org/atlassian/localstack/raw/mvn/release</url>
    </repository>
  </repositories>

</project>
```

### Troubleshooting

If you're using AWS Java libraries with Kinesis, please, refer to [CBOR protocol issues with the Java SDK guide](https://github.com/mhart/kinesalite#cbor-protocol-issues-with-the-java-sdk) how to disable CBOR protocol which is not supported by kinesalite.

## Web Dashboard

The projects also comes with a simple Web dashboard that allows to view the
deployed AWS components and the relationship between them.

```
make install-web
make web
```

## Change Log

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

Please note that we need to collect a signed **Contributors License Agreement** from each
individual developer who contributes code to this repository. Please refer to the following links:

* [https://developer.atlassian.com/opensource/](https://developer.atlassian.com/opensource/)
* [https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d)

## License

Copyright (c) 2016 Atlassian and others.

*LocalStack* is released under the Apache License, Version 2.0 (see LICENSE.txt).

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
sh							| MIT License
subprocess32				| PSF License
**Node.js/npm modules:**	|
dynalite					| MIT License
kinesalite					| MIT License
**Other tools:**			|
Elasticsearch 				| Apache License 2.0
