<p align="center">
  <img src="https://raw.githubusercontent.com/localstack/localstack/master/doc/localstack-readme-header.png" alt="LocalStack - A fully functional local cloud stack">
</p>

<p align="center">
  <a href="https://circleci.com/gh/localstack/localstack"><img alt="CircleCI" src="https://img.shields.io/circleci/build/gh/localstack/localstack/master?logo=circleci"></a>
  <a href="https://coveralls.io/github/localstack/localstack?branch=master"><img alt="Coverage Status" src="https://coveralls.io/repos/github/localstack/localstack/badge.svg?branch=master"></a>
  <a href="https://pypi.org/project/localstack/"><img alt="PyPI Version" src="https://img.shields.io/pypi/v/localstack?color=blue"></a>
  <a href="https://hub.docker.com/r/localstack/localstack"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/localstack/localstack"></a>
  <a href="#backers"><img alt="Backers on Open Collective" src="https://opencollective.com/localstack/backers/badge.svg"></a>
  <a href="#sponsors"><img alt="Sponsors on Open Collective" src="https://opencollective.com/localstack/sponsors/badge.svg"></a>
  <a href="https://img.shields.io/pypi/l/localstack.svg"><img alt="PyPI License" src="https://img.shields.io/pypi/l/localstack.svg"></a>
  <a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
  <!--<a href="https://twitter.com/_localstack"><img alt="Twitter" src="https://img.shields.io/twitter/url/http/shields.io.svg?style=social"></a>-->
</p>

<p align="center">
  <i>LocalStack</i> provides an easy-to-use test/mocking framework for developing Cloud applications.
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#installing">Install</a> •
  <a href="#running">Run</a> •
  <a href="#configuration">Configure</a> •
  <a href="#interact-with-localstack">Play</a>
  <br>–<br>
  <a href="https://docs.localstack.cloud" target="_blank">📖 Docs</a> •
  <a href="https://app.localstack.cloud" target="_blank">💻 Pro version</a> •
  <a href="https://github.com/localstack/localstack/blob/master/doc/feature_coverage.md" target="_blank">☑️ Feature coverage</a> •
  <a href="#announcements">📢 Announcements</a>
</p>

---

# Overview

[LocalStack 💻](https://localstack.cloud) is a cloud service emulator that runs in a single container on your laptop or in your CI environment.
With LocalStack, you can run your AWS applications or Lambdas entirely on your local machine without connecting to a remote cloud provider!
Whether you are testing complex CDK applications or Terraform configurations, or just beginning to learn about AWS services,
LocalStack helps speed up and simplify your testing and development workflow.

LocalStack supports a growing number of AWS services, like AWS Lambda, S3, Dynamodb, Kinesis, SQS, SNS, and **many** more!
The [**Pro version** of LocalStack](https://localstack.cloud/pricing) supports additional APIs and advanced features.
You can find a comprehensive list of supported APIs on our [☑️ Feature Coverage](https://github.com/localstack/localstack/blob/master/doc/feature_coverage.md) page.

LocalStack also provides additional features to make your life as a cloud developer easier!
Check out LocalStack's [Cloud Developer Tools](#localstack-cloud-developer-tools).

## Requirements

* `python` (Python 3.6 up to 3.9 supported)
* `pip` (Python package manager)
* `Docker`

## Installing

The easiest way to install LocalStack is via `pip`:

```
pip install localstack
```

**Note**: Please do **not** use `sudo` or the `root` user - LocalStack
should be installed and started entirely under a local non-root user. If you have problems
with permissions in MacOS X Sierra, install with `pip install --user localstack`

## Running

By default, LocalStack is started inside a Docker container by running:

```
localstack start
```

(Note that on MacOS you may have to run `TMPDIR=/private$TMPDIR localstack start --docker` if
`$TMPDIR` contains a symbolic link that cannot be mounted by Docker.)

**Note**: From 2020-07-11 onwards, the default image `localstack/localstack` in Docker Hub refers to the "light version", which has some large dependency files like Elasticsearch removed (and lazily downloads them, if required). (Note that the `localstack/localstack-light` image alias may get removed in the future). In case you need the full set of dependencies, the `localstack/localstack-full` image can be used instead. Please also refer to the `USE_LIGHT_IMAGE` configuration below.

**Note**: By default, LocalStack uses the image tagged `latest` that is cached on your machine, and will **not** pull the latest image automatically from Docker Hub (i.e., the image needs to be pulled manually if needed).

**Note**: Although we strongly recommend to use Docker, the infrastructure can also be spun up directly on the host machine using the `--host` startup flag. Note that this will require [additional dependencies](#developing), and is not supported on some operating systems, including Windows.

### Using `docker`

You can also use docker directly and use the following command to get started with localstack

```
docker run --rm -it -p 4566:4566 -p 4571:4571 localstack/localstack
```

Note that this will pull the current nighty build from the master branch and **not** the latest supported version.

to run a throw-away container without any external volumes. To start a subset of services use `-e "SERVICES=dynamodb,s3"`.

### Using `docker-compose`

You can also use the `docker-compose.yml` file from the repository and use this command (currently requires `docker-compose` version 1.9.0+):

```
docker-compose up
```

(Note that on MacOS you may have to run `TMPDIR=/private$TMPDIR docker-compose up` if
`$TMPDIR` contains a symbolic link that cannot be mounted by Docker.)

To facilitate interoperability, configuration variables can be prefixed with `LOCALSTACK_` in docker. For instance, setting `LOCALSTACK_SERVICES=s3` is equivalent to `SERVICES=s3`.

### Using Helm

You can use [Helm](https://helm.sh/) to install LocalStack in a Kubernetes cluster by running these commands
(the Helm charts are maintained in [this repo](https://github.com/localstack/helm-charts)):

```
helm repo add localstack-repo https://helm.localstack.cloud

helm upgrade --install localstack localstack-repo/localstack
```

## Configuration

You can pass the following environment variables to LocalStack.

### Core Configurations

* `SERVICES`: Comma-separated list of service names (APIs) to start up. Service names basically correspond
  to the [service names of the AWS CLI](http://docs.aws.amazon.com/cli/latest/reference/#available-services)
  (`kinesis`, `lambda`, `sqs`, etc), although LocalStack only supports a subset of them.
  Example value: `kinesis,lambda,sqs` to start Kinesis, Lambda, and SQS.
  In addition, the following shorthand values can be specified to run a predefined ensemble of services:
  - `serverless`: run services often used for Serverless apps (`iam`, `lambda`, `dynamodb`, `apigateway`, `s3`, `sns`)
* `EDGE_BIND_HOST`: Address the edge service binds to. (default: `127.0.0.1`, in docker containers `0.0.0.0`)
* `EDGE_PORT`: Port number for the edge service, the main entry point for all API invocations (default: `4566`).
* `HOSTNAME`: Name of the host to expose the services internally (default: `localhost`).
  Use this to customize the framework-internal communication, e.g., if services are
  started in different containers using docker-compose.
* `HOSTNAME_EXTERNAL`: Name of the host to expose the services externally (default: `localhost`).
  This host is used, e.g., when returning queue URLs from the SQS service to the client.
* `DEBUG`: Flag to increase log level and print more verbose logs (useful for troubleshooting issues)
* `<SERVICE>_PORT_EXTERNAL`: Port number to expose a specific service externally (defaults to service ports above). `SQS_PORT_EXTERNAL`, for example, is used when returning queue URLs from the SQS service to the client.
* `IMAGE_NAME`: Specific name and tag of LocalStack Docker image to use, e.g., `localstack/localstack:0.11.0` (default: `localstack/localstack`).
* `USE_LIGHT_IMAGE`: Whether to use the light-weight Docker image (default: `1`). Overwritten by `IMAGE_NAME`.
* `TMPDIR`: Temporary folder on the host running the CLI and inside the LocalStack container (default: `/tmp`).
* `HOST_TMP_FOLDER`: Temporary folder on the host that gets mounted as `$TMPDIR/localstack` into the LocalStack container. Required only for Lambda volume mounts when using `LAMBDA_REMOTE_DOCKER=false`.
* `DATA_DIR`: Local directory for saving persistent data (currently only supported for these services:
  Kinesis, DynamoDB, Elasticsearch, S3, Secretsmanager, SSM, SQS, SNS). Set it to `/tmp/localstack/data` to enable persistence
  (`/tmp/localstack` is mounted into the Docker container), leave blank to disable
  persistence (default).
* `PERSISTENCE_SINGLE_FILE`: Specify if persistence files should be combined.  (default: `true`).
* `<SERVICE>_BACKEND`: Custom endpoint URL to use for a specific service, where `<SERVICE>` is the uppercase
  service name (currently works for: `APIGATEWAY`, `CLOUDFORMATION`, `DYNAMODB`, `ELASTICSEARCH`,
  `KINESIS`, `S3`, `SNS`, `SQS`). This allows to easily integrate third-party services into LocalStack. You can take a look at an [elasticsearch example here](https://github.com/localstack/localstack/tree/master/doc/external_services_integration/elasticsearch/HOWTO.md).
* `FORCE_NONINTERACTIVE`: when running with Docker, disables the `--interactive` and `--tty` flags. Useful when running headless.
* `DOCKER_FLAGS`: Allows to pass custom flags (e.g., volume mounts) to "docker run" when running LocalStack in Docker.
* `DOCKER_CMD`: Shell command used to run Docker containers, e.g., set to `"sudo docker"` to run as sudo (default: `docker`).
* `MAIN_CONTAINER_NAME`: Specify the main docker container name (default: `localstack_main`).
* `INIT_SCRIPTS_PATH`: Specify the path to the initializing files with extensions .sh that are found default in `/docker-entrypoint-initaws.d`.
* `LS_LOG`: Specify the log level('trace', 'debug', 'info', 'warn', 'error', 'warning') currently overrides the `DEBUG` configuration. Enable `LS_LOG=trace` to print detailed request/response messages (or `LS_LOG=trace-internal` to include internal calls as well).

An example passing the above environment variables to LocalStack to start Kinesis, Lambda, Dynamodb and SQS:

```
SERVICES=kinesis,lambda,sqs,dynamodb DEBUG=1 localstack start
```

### Lambda Configurations

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
      host on the same machine. Also, `HOST_TMP_FOLDER` must be set properly, and a volume
      mount like `${HOST_TMP_FOLDER}:/tmp/localstack` needs to be configured if you're using
      docker-compose.
* `BUCKET_MARKER_LOCAL`: Optional bucket name for running lambdas locally.
* `LAMBDA_CODE_EXTRACT_TIME`: Time in seconds to wait at max while extracting Lambda code. By default it is `25` seconds for limiting the execution time to avoid client/network timeout issues.
* `LAMBDA_DOCKER_NETWORK`: Optional Docker network for the container running your lambda function.
* `LAMBDA_DOCKER_DNS`: Optional DNS server for the container running your lambda function.
* `LAMBDA_DOCKER_FLAGS`: Additional flags passed to Lambda Docker `run`/`create` commands (e.g., useful for specifying custom volume mounts). Does only support environment, volume, port and add-host flags (with `-e KEY=VALUE`, `-v host:container`, `-p host:container`, `--add-host domain:ip` respectively)
* `LAMBDA_CONTAINER_REGISTRY` Use an alternative docker registry to pull lambda execution containers (default: `lambci/lambda`).
* `LAMBDA_REMOVE_CONTAINERS`: Whether to remove containers after Lambdas finished executing (default: `true`).
* `LAMBDA_FALLBACK_URL`: Fallback URL to use when a non-existing Lambda is invoked. Either records invocations in DynamoDB (value `dynamodb://<table_name>`) or forwards invocations as a POST request (value `http(s)://...`).
* `LAMBDA_FORWARD_URL`: URL used to forward all Lambda invocations (useful to run Lambdas via an external service).
* `LAMBDA_JAVA_OPTS`: Allow passing custom JVM options (e.g., `-Xmx512M`) to Java Lambdas executed in Docker. Use `_debug_port_` placeholder to configure the debug port (e.g., `-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=_debug_port_`).
* `HOSTNAME_FROM_LAMBDA`: Endpoint host under which APIs are accessible from Lambda containers (optional). This can be useful in docker-compose stacks to use the local container hostname (e.g., `HOSTNAME_FROM_LAMBDA=localstack`) if neither IP address nor container name of the main container are available (e.g., in CI). Often used in combination with `LAMBDA_DOCKER_NETWORK`.

### Service-Specific Configurations

* `DYNAMODB_ERROR_PROBABILITY`: Decimal value between 0.0 (default) and 1.0 to randomly inject `ProvisionedThroughputExceededException` errors into DynamoDB API responses.
* `DYNAMODB_HEAP_SIZE`: Sets the JAVA EE maximum memory size for dynamodb values are (integer)m for MB, (integer)G for GB default(256m), full table scans require more memory
* `KINESIS_ERROR_PROBABILITY`: Decimal value between 0.0 (default) and 1.0 to randomly
  inject `ProvisionedThroughputExceededException` errors into Kinesis API responses.
* `KINESIS_INITIALIZE_STREAMS`: A comma-delimited string of stream names, its corresponding shard count and an optional region to initialize during startup. If the region is not provided, the default region is used. For example: "my-first-stream:1,my-other-stream:2:us-west-2,my-last-stream:1" Only works
with the `kinesis-mock` KINESIS_PROVIDER.
* `KINESIS_LATENCY`: Integer value of milliseconds (default: `500`) or `0` (to disable), causing the Kinesis API to delay returning a response in order to mimick latency from a live AWS call.
* `KINESIS_SHARD_LIMIT`: Integer value (default: `100`) or `Infinity` (to disable), causing the Kinesis API to start throwing exceptions to mimick the [default shard limit](https://docs.aws.amazon.com/streams/latest/dev/service-sizes-and-limits.html).
* `STEPFUNCTIONS_LAMBDA_ENDPOINT`: URL to use as the Lambda service endpoint in Step Functions. By default this is the LocalStack Lambda endpoint. Use `default` to select the original AWS Lambda endpoint.

### Security Configurations

Please be aware that the following configurations may have severe security implications!

* `ENABLE_CONFIG_UPDATES`: Whether to enable dynamic configuration updates at runtime, see [here](#dynamically-updating-configuration-at-runtime) (default: 0).
* `DISABLE_CORS_CHECKS`: Whether to disable all CSRF mitigations (default: 0).
* `DISABLE_CUSTOM_CORS_S3`: Whether to disable CORS override by S3 (default: 0).
* `DISABLE_CUSTOM_CORS_APIGATEWAY`: Whether to disable CORS override by apigateway (default: 0).
* `EXTRA_CORS_ALLOWED_ORIGINS`: Comma-separated list of origins that are allowed to communicate with localstack.
* `EXTRA_CORS_ALLOWED_HEADERS`: Comma-separated list of header names to be be added to `Access-Control-Allow-Headers` CORS header
* `EXTRA_CORS_EXPOSE_HEADERS`: Comma-separated list of header names to be be added to `Access-Control-Expose-Headers` CORS header

### Providers Configurations

Some of the services can be configured to switch to a particular provider:

* `KINESIS_PROVIDER`: Valid options are `kinesis-mock` (default) and `kinesalite`.
* `KMS_PROVIDER`: Valid options are `moto` (default) and `local-kms`.
* `SQS_PROVIDER`: Valid options are `moto` (default) and `elasticmq`.

### Miscellaneous Configurations

* `EDGE_FORWARD_URL`: Optional target URL to forward all edge requests to (e.g., for distributed deployments).
* `IGNORE_ES_DOWNLOAD_ERRORS`: Whether to ignore errors (e.g., network/SSL) when downloading Elasticsearch plugins.
* `MOCK_UNIMPLEMENTED`: Whether to return mocked success responses (instead of 501 errors) for currently unimplemented API methods.
* `OVERRIDE_IN_DOCKER`: Overrides the check whether LocalStack is executed within a docker container. If set to true, LocalStack assumes it runs in a docker container. Should not be set unless necessary.
* `SKIP_INFRA_DOWNLOADS`: Whether to skip downloading additional infrastructure components (e.g., specific Elasticsearch versions).

### Debugging Configurations

The following environment configurations can be useful for debugging:
* `DEVELOP`: Starts a debugpy server before starting LocalStack services
* `DEVELOP_PORT`: Port number for debugpy server
* `WAIT_FOR_DEBUGGER`: Forces LocalStack to wait for a debugger to start the services

The following environment configurations are *deprecated*:
* `DEFAULT_REGION`: AWS region to use when talking to the API (needs to be activated via `USE_SINGLE_REGION=1`). Deprecated and inactive as of version 0.12.17 - LocalStack now has full multi-region support.
* `USE_SSL`: Whether to use `https://...` URLs with SSL encryption (default: `false`). Deprecated as of version 0.11.3 - each service endpoint now supports multiplexing HTTP/HTTPS traffic over the same port.
* `USE_SINGLE_REGION`: Whether to use the legacy single-region mode, defined via `DEFAULT_REGION`.

Additionally, the following *read-only* environment variables are available:

* `LOCALSTACK_HOSTNAME`: Name of the host where LocalStack services are available.
  Use this hostname as endpoint (e.g., `http://${LOCALSTACK_HOSTNAME}:4566`) in order
  to **access the services from within your Lambda functions**
  (e.g., to store an item to DynamoDB or S3 from a Lambda).

### Verifying your docker-compose configuration using the command line

You can use the `localstack config validate` command to check for common mis-configurations.

By default it validates `docker-compose.yml`, the target file can be specified using the `--file` argument, e.g.,:
```
localstack config validate --file=localstack-docker-compose.yml
```

### Dynamically updating configuration at runtime

Each of the service APIs listed [above](https://github.com/localstack/localstack#overview) defines
a backdoor API under the path `/?_config_` which allows to dynamically update configuration variables
defined in [`config.py`](https://github.com/localstack/localstack/blob/master/localstack/config.py).

You need to enable this endpoint by setting `ENABLE_CONFIG_UPDATES=1` (the backdoor API is disabled by default, for security reasons).

For example, to dynamically set `KINESIS_ERROR_PROBABILITY=1` at runtime, use the following command:
```
curl -v -d '{"variable":"KINESIS_ERROR_PROBABILITY","value":1}' 'http://localhost:4566/?_config_'
```

### Service health checks

The service `/health` check endpoint on the edge port (`http://localhost:4566/health` by default) provides basic information about the status of each service (e.g., `{"s3":"running","es":"starting"}`). By default, the endpoint returns cached values that are determined during startup - the status values can be refreshed by adding the `reload` query parameter: `http://localhost:4566/health?reload`.

### Initializing a fresh instance

When a container is started for the first time, it will execute files with extensions .sh that are found in `/docker-entrypoint-initaws.d` or an alternate path defined in `INIT_SCRIPTS_PATH`. Files will be executed in alphabetical order. You can easily create aws resources on localstack using `awslocal` (or `aws`) cli tool in the initialization scripts.

## Interact with LocalStack

There are a number of ways you or your applications can interact with LocalStack.
To try LocalStack, the AWS CLI is a good starting point, however you can also use Terraform, [CDK](https://github.com/localstack/aws-cdk-local), AWS client libraries, and many other tools from the AWS ecosystem.

### AWS CLI

You can point your `aws` CLI (and other similar tools) to use LocalStack by configuring the service endpoint, for example:

```
aws --endpoint-url=http://localhost:4566 kinesis list-streams
{
    "StreamNames": []
}
```

Use the below command to install `aws CLI`, if not installed already.

```
pip install awscli
```
#### Setting up local region and credentials to run LocalStack

aws requires the region and the credentials to be set in order to run the aws commands. Create the default configuration & the credentials. Below key will ask for the Access key id, secret Access Key, region & output format.

```
aws configure --profile default

# Config & credential file will be created under ~/.aws folder
```
**NOTE**: Please use `test` as Access key id and secret Access Key to make S3 presign url work. We have added presign url signature verification algorithm to validate the presign url and its expiration. You can configure credentials into the system environment using `export` command in the linux/Mac system. You also can add credentials in `~/.aws/credentials` file directly.

```
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
```

### awslocal

[awslocal](https://github.com/localstack/awscli-local) is a thin CLI wrapper
that runs commands directly against LocalStack (no need to specify `--endpoint-url` anymore).
Install it via `pip install awscli-local`, and then use it as follows:

```bash
awslocal kinesis list-streams
{
    "StreamNames": []
}
```

**UPDATE**: Use the environment variable `$LOCALSTACK_HOSTNAME` to determine the target host
inside your Lambda function. See [Configuration](#configuration) section for more details.

### AWS CLI v2 with Docker and LocalStack

By default, the container running [amazon/aws-cli](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-docker.html) is isolated from `0.0.0.0:4566` on the host machine, that means that aws-cli cannot reach localstack through your shell.

To ensure that the two docker containers can communicate create a network on the docker engine:

```bash
$ docker network create localstack
0c9cb3d37b0ea1bfeb6b77ade0ce5525e33c7929d69f49c3e5ed0af457bdf123
```
Then modify the `docker-compose.yml` specifying the network to use:

```yml
networks:
  default:
    external:
      name: "localstack"
```

Run AWS Cli v2 docker container using this network (example):

```bash
$ docker run --network localstack --rm -it amazon/aws-cli --endpoint-url=http://localstack:4566 lambda list-functions
{
    "Functions": []
}
```

If you use AWS CLI v2 from a docker container often, create an alias:

```bash
$ alias laws='docker run --network localstack --rm -it amazon/aws-cli --endpoint-url=http://localstack:4566'
```

So you can type:

```bash
$ laws lambda list-functions
{
    "Functions": []
}
```

### Client Libraries

* Python: https://github.com/localstack/localstack-python-client
  * alternatively, you can also use `boto3` and use the `endpoint_url` parameter when creating a connection
* .NET: https://github.com/localstack-dotnet/localstack-dotnet-client
  * alternatively, you can also use `AWS SDK for .NET` and change `ClientConfig` properties when creating a service client.
* (more coming soon...)

### Invoking API Gateway

To invoke the path `/my/path` of an API Gateway with ID `id123` in stage `prod`, you can use the special hostname/URL syntax below:

```
$ curl http://id123.execute-api.localhost.localstack.cloud:4566/prod/my/path
```

Alternatively, if your system is facing issues resolving the custom DNS name, you can use this URL pattern instead:
```
$ curl http://localhost:4566/restapis/id123/prod/_user_request_/my/path
```

## Integrations

You can use your favorite cloud development frameworks with LocalStack.
We also provide a set of tools to integrate LocalStack into your automated tests.

### Serverless Framework

You can use the [`serverless-localstack`](https://www.npmjs.com/package/serverless-localstack) plugin to easily run [Serverless](https://serverless.com/framework/) applications on LocalStack.
For more information, please check out the plugin repository here:
https://github.com/localstack/serverless-localstack

### AWS Cloud Development Kit

You can run your [CDK](https://aws.amazon.com/cdk/) applications against LocalStack using our [cdklocal](https://github.com/localstack/aws-cdk-local) wrapper.

### Terraform

You can use [Terraform](https://www.terraform.io) to provision your resources locally.
Please refer to the Terraform AWS Provider docs [here](https://www.terraform.io/docs/providers/aws/guides/custom-service-endpoints.html#localstack) on how to configure the API endpoints on `localhost`.

### Pulumi

[Pulumi](https://www.pulumi.com) is a modern IaC framework that can also run against LocalStack using our [pulumi-local](https://github.com/localstack/pulumi-local) wrapper.

### Thundra

You can monitor and debug your AWS Lambda functions with [Thundra](https://thundra.io).
Currently only **Node.js**, **Python** and **Java** Lambdas are supported in this integration - support for other runtimes (.NET, Go) is coming soon.

Simply obtain a Thundra API key [here](https://console.thundra.io/onboarding/serverless)
and add Thundra API key as environment variable (`THUNDRA_APIKEY`) into your Lambda functions's environment variables:
- #### AWS SAM
```yaml
Resources:
  MyFunction:
    Type: AWS::Serverless::Function
    Properties:
      // other function properties
      Environment:
        Variables:
          // other environment variables
          THUNDRA_APIKEY: <YOUR-THUNDRA-API-KEY>
```
- #### AWS CDK
```js
const myFunction = new Function(this, "MyFunction", {
    ..., // other function properties
    environment: {
        ..., // other environment variables
        THUNDRA_APIKEY: <MY-THUNDRA-API-KEY>
    }
});
```
- #### Serverless Framework
```yaml
functions:
  MyFunction:
    // other function properties
    environment:
      // other environment variables
      THUNDRA_APIKEY: <YOUR-THUNDRA-API-KEY>
```

After invoking your AWS Lambda function you can inspect the invocations/traces in the [Thundra Console](https://console.thundra.io) (more details in the Thundra docs [here](https://apm.docs.thundra.io)).

For a complete example, you may check our blog post [Test Monitoring for LocalStack Apps with Thundra](https://localstack.cloud/blog/2021-09-16-test-monitoring-for-localstack-apps)
and access the project [here](https://github.com/thundra-io/thundra-demo-localstack-java).

### pytest

If you want to use LocalStack in your integration tests (e.g., pytest), simply fire up the
infrastructure in your test setup method and then clean up everything in your teardown method:

```python
from localstack.services import infra

def setup():
    infra.start_infra(asynchronous=True)

def teardown():
    infra.stop_infra()

def my_app_test():
    # here goes your test logic
```

See the example test file `tests/integration/test_integration.py` for more details.

### Java and JUnit

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

## LocalStack Cloud Developer Tools

LocalStack provides a number of tools that are designed to make local testing and development of cloud applications easier and more efficient.

### Hot-deploying Lambda code

Instead of re-deploying a Lambda every time your code changes, you can mount the source folder of your lambda directly.
First, ensure that `LAMBDA_REMOTE_DOCKER` is set to `false`.
Then, set the S3 bucket name to `__local__` or `BUCKET_MARKER_LOCAL` if it is set, and the S3 key to your local source folder path:

```
awslocal lambda create-function --function-name myLambda \
    --code S3Bucket="__local__",S3Key="/my/local/lambda/folder" \
    --handler index.myHandler \
    --runtime nodejs8.10 \
    --role whatever
```

### Custom API Gateway IDs

To provide custom IDs for API Gateway REST API, you can specify `tags={"_custom_id_":"myid123"}` on creation of an API Gateway REST API, to assign it the custom ID `"myid123"` (can be useful to have a static API GW endpoint URL for testing).

**Note:** When using `LAMBDA_REMOTE_DOCKER=false`, make sure to properly set the `HOST_TMP_FOLDER` environment variable for the LocalStack container (see Configuration section above).


## Advanced topics

### Using custom SSL certificates

To use your own SSL certificate instead of the randomly generated certificate, you can place a file `server.test.pem` into the LocalStack temporary directory (`$TMPDIR/localstack`, or `/tmp/localstack` by default). The file `server.test.pem` must contain the key file, as well as the certificate file content:

```
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```

### Using custom SSL certificates with docker-compose

Typically, with docker-compose you can add into docker-compose.yml this volume to the LocalStack services:

```
  volumes:
    - "${PWD}/ls_tmp:/tmp/localstack"
    - "/var/run/docker.sock:/var/run/docker.sock"
```

The local directory `/ls_tmp` must contains the three files (server.test.pem, server.test.pem.crt, server.test.pem.key)

## Troubleshooting

* If you're using AWS Java libraries with Kinesis, please, refer to [CBOR protocol issues with the Java SDK guide](https://github.com/mhart/kinesalite#cbor-protocol-issues-with-the-java-sdk) how to disable CBOR protocol which is not supported by kinesalite.

* Accessing local S3: To avoid domain name resolution issues, you need to enable **path style access** on your S3 SDK client. Most AWS SDKs provide a config to achieve that, e.g., for Java:
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

* If you're seeing Lambda errors like `Cannot find module ...` when using `LAMBDA_REMOTE_DOCKER=false`, make sure to properly set the `HOST_TMP_FOLDER` environment variable and mount the temporary folder from the host into the LocalStack container.

* If you run into file permission issues on `pip install` under Mac OS (e.g., `Permission denied: '/Library/Python/2.7/site-packages/six.py'`), then you may have to re-install `pip` via Homebrew (see [this discussion thread](https://github.com/localstack/localstack/issues/260#issuecomment-334458631)). Alternatively, try installing
with the `--user` flag: `pip install --user localstack`

* If you are deploying within OpenShift, please be aware: the pod must run as `root`, and the user must have capabilities added to the running pod, in order to allow Elasticsearch to be run as the non-root `localstack` user.

* If you are experiencing slow performance with Lambdas in Mac OS, you could either (1) try [mounting local code directly into the Lambda container](https://github.com/localstack/localstack#using-local-code-with-lambda), or (2) disable mounting the temporary directory into the LocalStack container in docker-compose. (See also https://github.com/localstack/localstack/issues/2515)

* The environment variable `no_proxy` is rewritten by LocalStack. (Internal requests will go straight via localhost, bypassing any proxy configuration).

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
* `moto`(for testing)
* `docker-compose` (for running the localstack using docker-compose)
* `mock` (for unit testing)
* `pytest` (for unit testing)
* `pytest-cov` (to check the unit-testing coverage)

### Building the Docker image

Please note that there are a few commands we need to run on the host to prepare the local environment for the Docker build - specifically, downloading some dependencies like the StepFunctions local binary. Therefore, simply running `docker build .` in a fresh clone of the repo may not work.

We generally recommend using this command to build the Docker image locally (works on Linux/MacOS):
```
make docker-build
```

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
make start
```

#### Code style

We use the [Black](https://github.com/psf/black) code formatter to keep code formatting consistent.
Before checking in your code, make sure to run `make format` and `make lint`.
You can also initialize the pre-commit hooks into your local repository with `make init-precommit`.

#### Starting LocalStack using Vagrant (Centos 8)
This is similar to `make docker-mount-run`, but instead of docker centos VM will be started and source code will be mounted inside.

##### Pre-requirements
- Vagrant
- `vagrant plugin install vagrant-vbguest`

##### Starting Vagrant
- `make vagrant-start` (be ready to provide system password)

##### Using Vagrant
- `vagrant ssh`
- `sudo -s`
- `cd /localstack`
- `SERVICES=dynamodb DEBUG=1 make docker-mount-run`

##### Stopping Vagrant
- `make vagrant-stop` or `vagrant halt`

##### Deleting Vagrant VM
- `vagrant destroy`

Check out the
[developer guide](https://github.com/localstack/localstack/tree/master/doc/developer_guides) which
contains a few instructions on how to get started with developing (and debugging) features for
LocalStack.

### Testing

The project contains a set of unit and integration tests that can be kicked off via a make
target:

```
make test
```

to run a specific test, you can use the `TEST_PATH` variable, for example:

```
TEST_PATH='tests/unit/sns_test.py' make test
```

### Code coverage

Pull requests should ideally increase the [test coverage](https://coveralls.io/github/localstack/localstack).
You can run the tests and collect a coverage report locally:

```
# To run the particular test file (sample)
TEST_PATH='tests/unit/sns_test.py' make test-coverage

# To check the coverage in the console
coverage report

# To check the coverage as html (output will be redirected to the html folder)
coverage html
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
* Follow the existing code style. Run `make format` and `make lint` before checking in your code.
* Put a reasonable amount of comments into the code.
* Fork localstack on your GitHub user account, do your changes there and then create a PR against main localstack repository.
* Separate unrelated changes into multiple pull requests.

Please note that by contributing any code or documentation to this repository (by
raising pull requests, or otherwise) you explicitly agree to
the [**Contributor License Agreement**](doc/contributor_license_agreement).

## Contributors

This project exists thanks to all the people who contribute.
<a href="https://github.com/localstack/localstack/graphs/contributors"><img src="https://opencollective.com/localstack/contributors.svg?width=890" /></a>


## Backers

Thank you to all our backers! 🙏 [Become a backer](https://opencollective.com/localstack#backer).

<a href="https://opencollective.com/localstack#backers" target="_blank"><img src="https://opencollective.com/localstack/backers.svg?width=890"></a>


## Sponsors

Support this project by becoming a sponsor.
Your logo will show up here with a link to your website.
[Become a sponsor](https://opencollective.com/localstack#sponsor).

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
