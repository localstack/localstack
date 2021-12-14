# Configuration

You can pass the following environment variables to LocalStack.

## Core Configurations

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
  `KINESIS`, `S3`, `SNS`, `SQS`). This allows to easily integrate third-party services into LocalStack.
* `FORCE_NONINTERACTIVE`: when running with Docker, disables the `--interactive` and `--tty` flags. Useful when running headless.
* `DOCKER_FLAGS`: Allows to pass custom flags (e.g., volume mounts) to "docker run" when running LocalStack in Docker.
* `DOCKER_CMD`: Shell command used to run Docker containers, e.g., set to `"sudo docker"` to run as sudo (default: `docker`).
* `MAIN_CONTAINER_NAME`: Specify the main docker container name (default: `localstack_main`).
* `INIT_SCRIPTS_PATH`: Specify the path to the initializing files with extensions .sh that are found default in `/docker-entrypoint-initaws.d`.
* `LS_LOG`: Specify the log level('trace', 'debug', 'info', 'warn', 'error', 'warning') currently overrides the `DEBUG` configuration. Enable `LS_LOG=trace` to print detailed request/response messages (or `LS_LOG=trace-internal` to include internal calls as well).

An example passing the above environment variables to LocalStack to start Kinesis, Lambda, Dynamodb and SQS:

```shell
SERVICES=kinesis,lambda,sqs,dynamodb DEBUG=1 localstack start
```

## Lambda Configurations

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

## Service-Specific Configurations

* `DYNAMODB_ERROR_PROBABILITY`: Decimal value between 0.0 (default) and 1.0 to randomly inject `ProvisionedThroughputExceededException` errors into DynamoDB API responses.
* `DYNAMODB_HEAP_SIZE`: Sets the JAVA EE maximum memory size for dynamodb values are (integer)m for MB, (integer)G for GB default(256m), full table scans require more memory
* `KINESIS_ERROR_PROBABILITY`: Decimal value between 0.0 (default) and 1.0 to randomly
  inject `ProvisionedThroughputExceededException` errors into Kinesis API responses.
* `KINESIS_INITIALIZE_STREAMS`: A comma-delimited string of stream names, its corresponding shard count and an optional region to initialize during startup. If the region is not provided, the default region is used. For example: "my-first-stream:1,my-other-stream:2:us-west-2,my-last-stream:1" Only works
with the `kinesis-mock` KINESIS_PROVIDER.
* `KINESIS_LATENCY`: Integer value of milliseconds (default: `500`) or `0` (to disable), causing the Kinesis API to delay returning a response in order to mimick latency from a live AWS call.
* `KINESIS_SHARD_LIMIT`: Integer value (default: `100`) or `Infinity` (to disable), causing the Kinesis API to start throwing exceptions to mimick the [default shard limit](https://docs.aws.amazon.com/streams/latest/dev/service-sizes-and-limits.html).
* `STEPFUNCTIONS_LAMBDA_ENDPOINT`: URL to use as the Lambda service endpoint in Step Functions. By default this is the LocalStack Lambda endpoint. Use `default` to select the original AWS Lambda endpoint.

## Security Configurations

Please be aware that the following configurations may have severe security implications!

* `ENABLE_CONFIG_UPDATES`: Whether to enable dynamic configuration updates at runtime, see [here](#dynamically-updating-configuration-at-runtime) (default: 0).
* `DISABLE_CORS_CHECKS`: Whether to disable all CSRF mitigations (default: 0).
* `DISABLE_CUSTOM_CORS_S3`: Whether to disable CORS override by S3 (default: 0).
* `DISABLE_CUSTOM_CORS_APIGATEWAY`: Whether to disable CORS override by apigateway (default: 0).
* `EXTRA_CORS_ALLOWED_ORIGINS`: Comma-separated list of origins that are allowed to communicate with localstack.
* `EXTRA_CORS_ALLOWED_HEADERS`: Comma-separated list of header names to be added to `Access-Control-Allow-Headers` CORS header
* `EXTRA_CORS_EXPOSE_HEADERS`: Comma-separated list of header names to be added to `Access-Control-Expose-Headers` CORS header

## Providers Configurations

Some of the services can be configured to switch to a particular provider:

* `KINESIS_PROVIDER`: Valid options are `kinesis-mock` (default) and `kinesalite`.
* `KMS_PROVIDER`: Valid options are `moto` (default) and `local-kms`.
* `SQS_PROVIDER`: Valid options are `moto` (default) and `elasticmq`.

## Miscellaneous Configurations

* `EDGE_FORWARD_URL`: Optional target URL to forward all edge requests to (e.g., for distributed deployments).
* `IGNORE_ES_DOWNLOAD_ERRORS`: Whether to ignore errors (e.g., network/SSL) when downloading Elasticsearch plugins.
* `MOCK_UNIMPLEMENTED`: Whether to return mocked success responses (instead of 501 errors) for currently unimplemented API methods.
* `OVERRIDE_IN_DOCKER`: Overrides the check whether LocalStack is executed within a docker container. If set to true, LocalStack assumes it runs in a docker container. Should not be set unless necessary.
* `SKIP_INFRA_DOWNLOADS`: Whether to skip downloading additional infrastructure components (e.g., specific Elasticsearch versions).
* `DISABLE_EVENTS`: Whether to disable publishing LocalStack events.

## Debugging Configurations

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

## Verifying your docker-compose configuration using the command line

You can use the `localstack config validate` command to check for common mis-configurations.

By default it validates `docker-compose.yml`, the target file can be specified using the `--file` argument, e.g.,:

```shell
localstack config validate --file=localstack-docker-compose.yml
```

## Dynamically updating configuration at runtime

Each of the service APIs listed [above](https://github.com/localstack/localstack#overview) defines
a backdoor API under the path `/?_config_` which allows to dynamically update configuration variables
defined in [`config.py`](https://github.com/localstack/localstack/blob/master/localstack/config.py).

You need to enable this endpoint by setting `ENABLE_CONFIG_UPDATES=1` (the backdoor API is disabled by default, for security reasons).

For example, to dynamically set `KINESIS_ERROR_PROBABILITY=1` at runtime, use the following command:

```shell
curl -v -d '{"variable":"KINESIS_ERROR_PROBABILITY","value":1}' 'http://localhost:4566/?_config_'
```

## Service health checks

The service `/health` check endpoint on the edge port (`http://localhost:4566/health` by default) provides basic information about the status of each service (e.g., `{"s3":"running","es":"starting"}`). By default, the endpoint returns cached values that are determined during startup - the status values can be refreshed by adding the `reload` query parameter: `http://localhost:4566/health?reload`.

## Initializing a fresh instance

When a container is started for the first time, it will execute files with extensions .sh that are found in `/docker-entrypoint-initaws.d` or an alternate path defined in `INIT_SCRIPTS_PATH`. Files will be executed in alphabetical order. You can easily create aws resources on localstack using `awslocal` (or `aws`) cli tool in the initialization scripts.
