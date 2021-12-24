# Interact with LocalStack

There are a number of ways you or your applications can interact with LocalStack. To try LocalStack, the AWS CLI is a good starting point, however you can also use Terraform, [CDK](https://github.com/localstack/aws-cdk-local), AWS client libraries, and many other tools from the AWS ecosystem.

## AWS CLI

You can point your `aws` CLI (and other similar tools) to use LocalStack by configuring the service endpoint, for example:

```shell
aws --endpoint-url=http://localhost:4566 kinesis list-streams
{
    "StreamNames": []
}
```

Use the below command to install `aws CLI`, if not installed already.

```shell
pip install awscli
```

## Setting up local region and credentials to run LocalStack

aws requires the region and the credentials to be set in order to run the aws commands. Create the default configuration & the credentials. Below key will ask for the Access key id, secret Access Key, region & output format.

```shell
aws configure --profile default

# Config & credential file will be created under ~/.aws folder
```

**NOTE**: Please use `test` as Access key id and secret Access Key to make S3 presign url work. We have added presign url signature verification algorithm to validate the presign url and its expiration. You can configure credentials into the system environment using `export` command in the linux/Mac system. You also can add credentials in `~/.aws/credentials` file directly.

```shell
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
```

## awslocal

[awslocal](https://github.com/localstack/awscli-local) is a thin CLI wrapper that runs commands directly against LocalStack (no need to specify `--endpoint-url` anymore). Install it via `pip install awscli-local`, and then use it as follows:

```shell
awslocal kinesis list-streams
{
    "StreamNames": []
}
```

**UPDATE**: Use the environment variable `$LOCALSTACK_HOSTNAME` to determine the target host inside your Lambda function. See [Configuration](#configuration) section for more details.

## AWS CLI v2 with Docker and LocalStack

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

```shell
$ docker run --network localstack --rm -it amazon/aws-cli --endpoint-url=http://localstack:4566 lambda list-functions
{
    "Functions": []
}
```

If you use AWS CLI v2 from a docker container often, create an alias:

```shell
$ alias laws='docker run --network localstack --rm -it amazon/aws-cli --endpoint-url=http://localstack:4566'
```

So you can type:

```shell
$ laws lambda list-functions
{
    "Functions": []
}
```

## Client Libraries

* Python: https://github.com/localstack/localstack-python-client
  * alternatively, you can also use `boto3` and use the `endpoint_url` parameter when creating a connection
* .NET: https://github.com/localstack-dotnet/localstack-dotnet-client
  * alternatively, you can also use `AWS SDK for .NET` and change `ClientConfig` properties when creating a service client.
* (more coming soon...)

## Invoking API Gateway

To invoke the path `/my/path` of an API Gateway with ID `id123` in stage `prod`, you can use the special hostname/URL syntax below:

```shell
$ curl http://id123.execute-api.localhost.localstack.cloud:4566/prod/my/path
```

Alternatively, if your system is facing issues resolving the custom DNS name, you can use this URL pattern instead:

```shell
$ curl http://localhost:4566/restapis/id123/prod/_user_request_/my/path
```
