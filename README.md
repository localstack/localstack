[![Build Status](https://travis-ci.org/localstack/localstack.svg)](https://travis-ci.org/localstack/localstack) [![Backers on Open Collective](https://opencollective.com/localstack/backers/badge.svg)](#backers) [![Sponsors on Open Collective](https://opencollective.com/localstack/sponsors/badge.svg)](#sponsors) [![Coverage Status](https://coveralls.io/repos/github/localstack/localstack/badge.svg?branch=master)](https://coveralls.io/github/localstack/localstack?branch=master)
[![Gitter](https://img.shields.io/gitter/room/localstack/Platform.svg)](https://gitter.im/localstack/Platform)
[![PyPI Version](https://badge.fury.io/py/localstack.svg)](https://badge.fury.io/py/localstack)
[![PyPI License](https://img.shields.io/pypi/l/localstack.svg)](https://img.shields.io/pypi/l/localstack.svg)
[![Code Climate](https://codeclimate.com/github/localstack/localstack/badges/gpa.svg)](https://codeclimate.com/github/localstack/localstack)
[![Twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/_localstack)

# LocalStack - A fully functional local AWS cloud stack

![LocalStack](https://github.com/localstack/localstack/raw/master/localstack/dashboard/web/img/localstack.png)

*LocalStack* provides an easy-to-use test/mocking framework for developing Cloud applications.

Currently, the focus is primarily on supporting the AWS cloud stack.

# Announcements

* **2019-10-09**: **LocalStack Pro is out!** We're incredibly excited to announce the launch of LocalStack Pro - the enterprise version of LocalStack with additional APIs and advanced features. Check out the free trial at https://localstack.cloud
* **2018-01-10**: **Help wanted!** Please [fill out this survey](https://lambdastudy.typeform.com/to/kDUvvy?source=localstack-github) to support a research study on the usage of Serverless and Function-as-a-Service (FaaS) services, conducted at Chalmers University of Technology. The survey only takes 5-10 minutes of your time. Many thanks for your participation!!
  * The result from this study can be found [here](https://research.chalmers.se/en/publication/508147)
* **2017-08-27**: **We need your support!** LocalStack is growing fast, we now have thousands of developers using the platform on a regular basis. Last month we have recorded a staggering 100k test runs, with 25k+ DynamoDB tables, 20k+ SQS queues, 15k+ Kinesis streams, 13k+ S3 buckets, and 10k+ Lambda functions created locally - for 0$ costs (more details to be published soon). Bug and feature requests are pouring in, and we now need some support from _you_ to keep the open source version actively maintained. Please check out [Open Collective](https://opencollective.com/localstack) and become a [backer](https://github.com/localstack/localstack#backers) or [supporter](https://github.com/localstack/localstack#backers) of the project today! Thanks everybody for contributing. ♥
* **2017-07-20**: Please note: Starting with version `0.7.0`, the Docker image will be pushed
and kept up to date under the **new name** `localstack/localstack`. (This means that you may
have to update your CI configurations.) Please refer to the updated
**[End-User License Agreement (EULA)](doc/end_user_license_agreement)** for the new versions.
The old Docker image (`atlassianlabs/localstack`) is still available but will not be maintained
any longer.

# Overview

LocalStack spins up the following core Cloud APIs on your local machine:

* **API Gateway** at http://localhost:4567
* **Kinesis** at http://localhost:4568
* **DynamoDB** at http://localhost:4569
* **DynamoDB Streams** at http://localhost:4570
* **S3** at http://localhost:4572
* **Firehose** at http://localhost:4573
* **Lambda** at http://localhost:4574
* **SNS** at http://localhost:4575
* **SQS** at http://localhost:4576
* **Redshift** at http://localhost:4577
* **Elasticsearch Service** at http://localhost:4578
* **SES** at http://localhost:4579
* **Route53** at http://localhost:4580
* **CloudFormation** at http://localhost:4581
* **CloudWatch** at http://localhost:4582
* **SSM** at http://localhost:4583
* **SecretsManager** at http://localhost:4584
* **StepFunctions** at http://localhost:4585
* **CloudWatch Logs** at http://localhost:4586
* **EventBridge (CloudWatch Events)** at http://localhost:4587
* **STS** at http://localhost:4592
* **IAM** at http://localhost:4593
* **EC2** at http://localhost:4597
* **KMS** at http://localhost:4599

In addition to the above, the [**Pro version** of LocalStack](https://localstack.cloud/#pricing) supports additional APIs and advanced features, including:
* **AppSync**
* **Athena**
* **CloudFront**
* **Cognito**
* **ECS/EKS**
* **ElastiCache**
* **EMR**
* **IoT**
* **Lambda Layers**
* **RDS**
* **XRay**
* **Interactive UIs to manage resources**
* **Test report dashboards**
* ...and much, much more to come!

## Why LocalStack?

LocalStack builds on existing best-of-breed mocking/testing tools, most notably
[kinesalite](https://github.com/mhart/kinesalite)/[dynalite](https://github.com/mhart/dynalite)
and [moto](https://github.com/spulec/moto). While these tools are *awesome* (!), they lack functionality
for certain use cases. LocalStack combines the tools, makes them interoperable, and adds important
missing functionality on top of them:

* **Error injection:** LocalStack allows to inject errors frequently occurring in real Cloud environments,
  for instance `ProvisionedThroughputExceededException` which is thrown by Kinesis or DynamoDB if the amount of
  read/write throughput is exceeded.
* **Isolated processes**: All services in LocalStack run in separate processes. The overhead of additional
  processes is negligible, and the entire stack can easily be executed on any developer machine and CI server.
  In moto, components are often hard-wired in RAM (e.g., when forwarding a message on an SNS topic to an SQS queue,
  the queue endpoint is looked up in a local hash map). In contrast, LocalStack services live in isolation
  (separate processes available via HTTP), which fosters true decoupling and more closely resembles the real
  cloud environment.
* **Pluggable services**: All services in LocalStack are easily pluggable (and replaceable), due to the fact that
  we are using isolated processes for each service. This allows us to keep the framework up-to-date and select
  best-of-breed mocks for each individual service.


## Requirements

* `python` (both Python 2.x and 3.x supported)
* `pip` (python package manager)
* `Docker`

## Installing

The easiest way to install LocalStack is via `pip`:

```
pip install localstack
```

**Note**: Please do **not** use `sudo` or the `root` user - LocalStack
should be installed and started entirely under a local non-root user. If you have problems
with permissions in MacOS X Sierra, install with `pip install --user localstack`

## Running in Docker

By default, LocalStack gets started inside a Docker container using this command:

```
localstack start
```

(Note that on MacOS you may have to run `TMPDIR=/private$TMPDIR localstack start --docker` if
`$TMPDIR` contains a symbolic link that cannot be mounted by Docker.)

### Using `docker-compose`

You can also use the `docker-compose.yml` file from the repository and use this command (currently requires `docker-compose` version 2.1+):

```
docker-compose up
```

(Note that on MacOS you may have to run `TMPDIR=/private$TMPDIR docker-compose up` if
`$TMPDIR` contains a symbolic link that cannot be mounted by Docker.)

Use on existing docker-compose project. Add in existing services. The project can be found in docker hub, no need to download or clone source:

```
version: '2.1'
services:
...
  localstack:
    image: localstack/localstack
    ports:
      - "4567-4599:4567-4599"
      - "${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
    environment:
      - SERVICES=${SERVICES- }
      - DEBUG=${DEBUG- }
      - DATA_DIR=${DATA_DIR- }
      - PORT_WEB_UI=${PORT_WEB_UI- }
      - LAMBDA_EXECUTOR=${LAMBDA_EXECUTOR- }
      - KINESIS_ERROR_PROBABILITY=${KINESIS_ERROR_PROBABILITY- }
      - DOCKER_HOST=unix:///var/run/docker.sock
    volumes:
      - "${TMPDIR:-/tmp/localstack}:/tmp/localstack"
```

To facilitate interoperability, configuration variables can be prefixed with `LOCALSTACK_` in docker. For instance, setting `LOCALSTACK_SERVICES=s3` is equivalent to `SERVICES=s3`.

## Starting locally (non-Docker mode)

Alternatively, the infrastructure can be spun up on the local host machine (without using Docker) using the following command:

```
localstack start --host
```

(Note that this will require [additional dependencies](#Developing), and currently is not supported on some operating systems, including Windows.)

LocalStack will attempt to automatically fetch the missing dependencies when you first start it up in "host" mode; alternatively, you can use the `full` profile to install all dependencies at `pip` installation time:

```
pip install "localstack[full]"
```

## Configurations

You can pass the following environment variables to LocalStack:

* `SERVICES`: Comma-separated list of service names and (optional) ports they should run on.
  If no port is specified, a default port is used. Service names basically correspond to the
  [service names of the AWS CLI](http://docs.aws.amazon.com/cli/latest/reference/#available-services)
  (`kinesis`, `lambda`, `sqs`, etc), although LocalStack only supports a subset of them.
  Example value: `kinesis,lambda:4569,sqs:4570` to start Kinesis on the default port,
  Lambda on port 4569, and SQS on port 4570. In addition, the following shorthand values can be
  specified to run a predefined ensemble of services:
  - `serverless`: run services often used for Serverless apps (`iam`, `lambda`, `dynamodb`, `apigateway`, `s3`, `sns`)
* `DEFAULT_REGION`: AWS region to use when talking to the API (defaults to `us-east-1`).
* `HOSTNAME`: Name of the host to expose the services internally (defaults to `localhost`).
  Use this to customize the framework-internal communication, e.g., if services are
  started in different containers using docker-compose.
* `HOSTNAME_EXTERNAL`: Name of the host to expose the services externally (defaults to `localhost`).
  This host is used, e.g., when returning queue URLs from the SQS service to the client.
* `<SERVICE>_PORT`: Port number to bind a specific service to (defaults to service ports above).
* `<SERVICE>_PORT_EXTERNAL`: Port number to expose a specific service externally (defaults to service ports above). `SQS_PORT_EXTERNAL`, for example, is used when returning queue URLs from the SQS service to the client.
* `USE_SSL`: Whether to use `https://...` URLs with SSL encryption (defaults to `false`).
* `KINESIS_ERROR_PROBABILITY`: Decimal value between 0.0 (default) and 1.0 to randomly
  inject `ProvisionedThroughputExceededException` errors into Kinesis API responses.
* `KINESIS_SHARD_LIMIT`: Integer value (defaults to `100`) or `Infinity` (to disable), in which to kinesalite will start throwing exceptions to mimick the [default shard limit](https://docs.aws.amazon.com/streams/latest/dev/service-sizes-and-limits.html).
* `KINESIS_LATENCY`: Integer value (defaults to `500`) or `0` (to disable), in which to kinesalite will delay returning a response in order to mimick latency from a live AWS call.
* `DYNAMODB_ERROR_PROBABILITY`: Decimal value between 0.0 (default) and 1.0 to randomly
  inject `ProvisionedThroughputExceededException` errors into DynamoDB API responses.
* `LAMBDA_EXECUTOR`: Method to use for executing Lambda functions. Possible values are:
    - `local`: run Lambda functions in a temporary directory on the local machine
    - `docker`: run each function invocation in a separate Docker container
    - `docker-reuse`: create one Docker container per function and reuse it across invocations

  For `docker` and `docker-reuse`, if LocalStack itself is started inside Docker, then
  the `docker` command needs to be available inside the container (usually requires to run the
  container in privileged mode). Default is `docker`, fallback to `local` if Docker is not available.
* `LAMBDA_REMOTE_DOCKER` determines whether Lambda code is copied or mounted into containers.
  Possible values are:
    - `true` (default): your Lambda function definitions will be passed to the container by
      copying the zip file (potentially slower). It allows for remote execution, where the host
      and the client are not on the same machine.
    - `false`: your Lambda function definitions will be passed to the container by mounting a
      volume (potentially faster). This requires to have the Docker client and the Docker
      host on the same machine.
* `LAMBDA_DOCKER_NETWORK`: Optional Docker network for the container running your lambda function.
* `LAMBDA_CONTAINER_REGISTRY` Use an alternative docker registry to pull lambda execution containers (default: `lambci/lambda`).
* `LAMBDA_REMOVE_CONTAINERS`: Whether to remove containers after Lambdas finished executing (default: `true`).
* `DATA_DIR`: Local directory for saving persistent data (currently only supported for these services:
  Kinesis, DynamoDB, Elasticsearch, S3). Set it to `/tmp/localstack/data` to enable persistence
  (`/tmp/localstack` is mounted into the Docker container), leave blank to disable
  persistence (default).
* `PORT_WEB_UI`: Port for the Web user interface (dashboard). Default is `8080`.
* `<SERVICE>_BACKEND`: Custom endpoint URL to use for a specific service, where `<SERVICE>` is the uppercase
  service name (currently works for: `APIGATEWAY`, `CLOUDFORMATION`, `DYNAMODB`, `ELASTICSEARCH`,
  `KINESIS`, `S3`, `SNS`, `SQS`). This allows to easily integrate third-party services into LocalStack.
* `FORCE_NONINTERACTIVE`: when running with Docker, disables the `--interactive` and `--tty` flags. Useful when running headless.
* `DOCKER_FLAGS`: Allows to pass custom flags (e.g., volume mounts) to "docker run" when running LocalStack in Docker.
* `DOCKER_CMD`: Shell command used to run Docker containers, e.g., set to `"sudo docker"` to run as sudo (default: `docker`).
* `START_WEB`: Flag to control whether the Web API should be started in Docker (values: `0`/`1`; default: `1`).
* `LAMBDA_FALLBACK_URL`: Fallback URL to use when a non-existing Lambda is invoked. Either records invocations in DynamoDB (value `dynamodb://<table_name>`) or forwards invocations as a POST request (value `http(s)://...`).
* `EXTRA_CORS_ALLOWED_HEADERS`: Comma-separated list of header names to be be added to `Access-Control-Allow-Headers` CORS header
* `EXTRA_CORS_EXPOSE_HEADERS`: Comma-separated list of header names to be be added to `Access-Control-Expose-Headers` CORS header
* `LAMBDA_JAVA_OPTS`: Allow passing custom JVM options (e.g., `-Xmx512M`) to Java Lambdas executed in Docker. Use `_debug_port_` placeholder to configure the debug port (e.g., `-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=_debug_port_`).


Additionally, the following *read-only* environment variables are available:

* `LOCALSTACK_HOSTNAME`: Name of the host where LocalStack services are available.
  This is needed in order to access the services from within your Lambda functions
  (e.g., to store an item to DynamoDB or S3 from Lambda).
  The variable `LOCALSTACK_HOSTNAME` is available for both, local Lambda execution
  (`LAMBDA_EXECUTOR=local`) and execution inside separate Docker containers (`LAMBDA_EXECUTOR=docker`).

### Dynamically updating configuration at runtime

Each of the service APIs listed [above](https://github.com/localstack/localstack#overview) defines
a backdoor API under the path `/?_config_` which allows to dynamically update configuration variables
defined in [`config.py`](https://github.com/localstack/localstack/blob/master/localstack/config.py).

For example, to dynamically set `KINESIS_ERROR_PROBABILITY=1` at runtime, use the following command:
```
curl -v -d '{"variable":"KINESIS_ERROR_PROBABILITY","value":1}' 'http://localhost:4568/?_config_'
```

### Service health checks

The service health check endpoint `http://localhost:8080/health` provides basic information about the status of each service (e.g., `{"s3":"running","es":"starting"}`). By default, the endpoint returns cached values that are determined during startup - the status values can be refreshed by adding the `reload` query parameter: `http://localhost:8080/health?reload`.

### Initializing a fresh instance

When a container is started for the first time, it will execute files with extensions .sh that are found in `/docker-entrypoint-initaws.d`. Files will be executed in alphabetical order. You can easily create aws resources on localstack using `awslocal` (or `aws`) cli tool in the initialization scripts.

## Using custom SSL certificates (for `USE_SSL=1`)

If you need to use your own SSL Certificate and keep it persistent and not use the random automatic generated Certificate, you can place into the localstack temporary directory :

```
/tmp/localstack/
```

the three named files below :

```bash
server.test.pem
server.test.pem.crt
server.test.pem.key
```

- the file `server.test.pem` must contains your key file content, your certificate and chain certificate files contents (do a cat in this order)
 - the file `server.test.pem.crt` must contains your certificate and chains files contents (do a 'cat' in this order)
- the file server.test.pem.key must contains your key file content

### Using USE_SSL and own persistent certificate with docker-compose

Typically with docker-compose you can add into docker-compose.yml this volume to the localstack services :

```
volumes:
      - "${PWD}/ls_tmp:/tmp/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"
```

local directory **ls_tmp** must contains the three files (server.test.pem, server.test.pem.crt, server.test.pem.key)

## Accessing the infrastructure via CLI or code

You can point your `aws` CLI to use the local infrastructure, for example:

```
aws --endpoint-url=http://localhost:4568 kinesis list-streams
{
    "StreamNames": []
}
```

**NEW**: Check out [awslocal](https://github.com/localstack/awscli-local), a thin CLI wrapper
that runs commands directly against LocalStack (no need to specify `--endpoint-url` anymore).
Install it via `pip install awscli-local`, and then use it as follows:

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

If you want to use LocalStack in your integration tests (e.g., nosetests), simply fire up the
infrastructure in your test setup method and then clean up everything in your teardown method:

```
from localstack.services import infra

def setup():
    infra.start_infra(asynchronous=True)

def teardown():
    infra.stop_infra()

def my_app_test():
    # here goes your test logic
```

See the example test file `tests/integration/test_integration.py` for more details.

## Integration with Serverless

You can use the [`serverless-localstack`](https://www.npmjs.com/package/serverless-localstack) plugin to easily run [Serverless](https://serverless.com/framework/) applications on LocalStack.
For more information, please check out the plugin repository here:
https://github.com/localstack/serverless-localstack

## Integration with Terraform

You can use [Terraform](https://www.terraform.io) to provision your resources locally. Please refer to the Terraform AWS Provider docs [here](https://www.terraform.io/docs/providers/aws/guides/custom-service-endpoints.html#localstack) on how to configure the API endpoints on `localhost`.

## Using local code with Lambda

In order to mount a local folder, ensure that `LAMBDA_REMOTE_DOCKER` is set to `false` then set the S3 bucket name to `__local__` and the S3 key to your local path:

```
awslocal lambda create-function --function-name myLambda \
    --code S3Bucket="__local__",S3Key="/my/local/lambda/folder" \
    --handler index.myHandler \
    --runtime nodejs8.10 \
    --role whatever
```

## Integration with Java/JUnit

In order to use LocalStack with Java, the project ships with a simple JUnit runner, see sample below.

```
...
import cloud.localstack.LocalstackTestRunner;
import cloud.localstack.TestUtils;
import cloud.localstack.docker.annotation.LocalstackDockerProperties;

@RunWith(LocalstackTestRunner.class)
@LocalstackDockerProperties(services = { "s3", "sqs", "kinesis:77077" })
public class MyCloudAppTest {

  @Test
  public void testLocalS3API() {
    AmazonS3 s3 = TestUtils.getClientS3()
    List<Bucket> buckets = s3.listBuckets();
    ...
  }
}
```

For more details and a complete list of configuration parameters, please refer to the [LocalStack Java Utils](https://github.com/localstack/localstack-java-utils) repository.

## Troubleshooting

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

* If you run into file permission issues on `pip install` under Mac OS (e.g., `Permission denied: '/Library/Python/2.7/site-packages/six.py'`), then you may have to re-install `pip` via Homebrew (see [this discussion thread](https://github.com/localstack/localstack/issues/260#issuecomment-334458631)). Alternatively, try installing
with the `--user` flag: `pip install --user localstack`


* If you are deploying within OpenShift, please be aware: the pod must run as `root`, and the user must have capabilities added to the running pod, in order to allow Elasticsearch to be run as the non-root `localstack` user.

* The environment variable `no_proxy` is rewritten by LocalStack.
(Internal requests will go straight via localhost, bypassing any proxy configuration).

* For troubleshooting LocalStack start issues, you can check debug logs by running `DEBUG=1 localstack start`

* In case you get errors related to node/nodejs, you may find (this issue comment: https://github.com/localstack/localstack/issues/227#issuecomment-319938530) helpful.

* If you are using AWS Java libraries and need to disable SSL certificate checking, add `-Dcom.amazonaws.sdk.disableCertChecking` to the java invocation.

## Developing

### Requirements for developing or starting locally

To develop new features, or to start the stack locally (outside of Docker), the following additional tools are required:

* `make`
* `npm` (node.js package manager)
* `java`/`javac` (Java 8 runtime environment and compiler)
* `mvn` (Maven, the build system for Java)

### Development Environment

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

## Other UI Clients

* [Commandeer desktop app](https://getcommandeer.com)
* [DynamoDB Admin Web UI](https://www.npmjs.com/package/dynamodb-admin)

## Change Log

Please refer to [`CHANGELOG.md`](CHANGELOG.md) to see the complete list of changes for each release.

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
<a href="https://github.com/localstack/localstack/graphs/contributors"><img src="https://opencollective.com/localstack/contributors.svg?width=890" /></a>


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

## Stargazers over time

[![Stargazers over time](https://starchart.cc/localstack/localstack.svg)](https://starchart.cc/localstack/localstack)

## License

Copyright (c) 2017-2020 LocalStack maintainers and contributors.

Copyright (c) 2016 Atlassian and others.

This version of LocalStack is released under the Apache License, Version 2.0 (see LICENSE.txt).
By downloading and using this software you agree to the
[End-User License Agreement (EULA)](doc/end_user_license_agreement).

We build on a number of third-party software tools, including the following:

Third-Party software      | 	License
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
