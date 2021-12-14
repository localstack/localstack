# Integration

You can use your favorite cloud development frameworks with LocalStack. We also provide a set of tools to integrate LocalStack into your automated tests.

## Serverless Framework

You can use the [`serverless-localstack`](https://www.npmjs.com/package/serverless-localstack) plugin to easily run [Serverless](https://serverless.com/framework/) applications on LocalStack. For more information, please check out the plugin repository here: https://github.com/localstack/serverless-localstack

## AWS Cloud Development Kit

You can run your [CDK](https://aws.amazon.com/cdk/) applications against LocalStack using our [cdklocal](https://github.com/localstack/aws-cdk-local) wrapper.

## Terraform

You can use [Terraform](https://www.terraform.io) to provision your resources locally. Please refer to the Terraform AWS Provider docs [here](https://www.terraform.io/docs/providers/aws/guides/custom-service-endpoints.html#localstack) on how to configure the API endpoints on `localhost`.

## Pulumi

[Pulumi](https://www.pulumi.com) is a modern IaC framework that can also run against LocalStack using our [pulumi-local](https://github.com/localstack/pulumi-local) wrapper.

## Thundra

You can monitor and debug your AWS Lambda functions with [Thundra](https://thundra.io). Currently only **Node.js**, **Python** and **Java** Lambdas are supported in this integration - support for other runtimes (.NET, Go) is coming soon.

Simply obtain a Thundra API key [here](https://console.thundra.io/onboarding/serverless) and add Thundra API key as environment variable (`THUNDRA_APIKEY`) into your Lambda functions's environment variables:

- ### AWS SAM
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

- ### AWS CDK
```js
const myFunction = new Function(this, "MyFunction", {
    ..., // other function properties
    environment: {
        ..., // other environment variables
        THUNDRA_APIKEY: <MY-THUNDRA-API-KEY>
    }
});
```

- ### Serverless Framework
```yaml
functions:
  MyFunction:
    // other function properties
    environment:
      // other environment variables
      THUNDRA_APIKEY: <YOUR-THUNDRA-API-KEY>
```

After invoking your AWS Lambda function you can inspect the invocations/traces in the [Thundra Console](https://console.thundra.io) (more details in the Thundra docs [here](https://apm.docs.thundra.io)).

For a complete example, you may check our blog post [Test Monitoring for LocalStack Apps with Thundra](https://localstack.cloud/blog/2021-09-16-test-monitoring-for-localstack-apps) and access the project [here](https://github.com/thundra-io/thundra-demo-localstack-java).

## pytest

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

## Java and JUnit

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
