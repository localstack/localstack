# Multi-account and Multi-region Testing

LocalStack has multi-account and multi-region support. This document contains some tips to make sure that your contributions are compatible with this functionality.

## Overview

For cross-account inter-service access, specify a role with which permissions the source service makes a request to the target service to access another service's resource.
This role should be in the source account.
When writing an AWS validated test case, you need to properly configure IAM roles.

For example:
The test case [`test_apigateway_with_step_function_integration`](https://github.com/localstack/localstack/blob/628b96b44a4fc63d880a4c1238a4f15f5803a3f2/tests/aws/services/apigateway/test_apigateway_basic.py#L999) specifies a [role](https://github.com/localstack/localstack/blob/628b96b44a4fc63d880a4c1238a4f15f5803a3f2/tests/aws/services/apigateway/test_apigateway_basic.py#L1029-L1034) which has permissions to access the target step function account.
```python
role_arn = create_iam_role_with_policy(
    RoleName=f"sfn_role-{short_uid()}",
    PolicyName=f"sfn-role-policy-{short_uid()}",
    RoleDefinition=STEPFUNCTIONS_ASSUME_ROLE_POLICY,
    PolicyDefinition=APIGATEWAY_LAMBDA_POLICY,
)
```

For cross-account inter-service access, you can create the client using `connect_to.with_assumed_role(...)`.
For example:
```python
connect_to.with_assumed_role(
    role_arn="role-arn",
    service_principal=ServicePrincial.service_name,
    region_name=region_name,
).lambda_
```

When there is no role specified, you should use the source arn conceptually if cross-account is allowed.
This can be seen in a case where `account_id` was added [added](https://github.com/localstack/localstack/blob/ae31f63bb6d8254edc0c85a66e3c36cd0c7dc7b0/localstack/utils/aws/message_forwarding.py#L42) to [send events to the target](https://github.com/localstack/localstack/blob/ae31f63bb6d8254edc0c85a66e3c36cd0c7dc7b0/localstack/utils/aws/message_forwarding.py#L31) service like SQS, SNS, Lambda, etc.

Always refer to the official AWS documentation and investigate how the the services communicate with each other.
For example, here are the [AWS Firehose docs](https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html#cross-account-delivery-s3) explaining Firehose and S3 integration.


## Test changes in CI with random credentials

We regularly run the test suite on GitHub Actions to verify compatibility with multi-account and multi-region features. A [scheduled GitHub Actions workflow](https://github.com/localstack/localstack/actions/workflows/aws-tests-mamr.yml) runs on working days at 01:00 UTC, executing the tests with randomized account IDs and regions.

If you have the necessary permissions, you can also manually trigger the [workflow](https://github.com/localstack/localstack/actions/workflows/aws-tests-mamr.yml) directly from GitHub.

## Test changes locally with random credentials

To test changes locally for multi-account and multi-region compatibility, set the environment config values as follows:

- `TEST_AWS_ACCOUNT_ID` (Any value except `000000000000`)
- `TEST_AWS_ACCESS_KEY_ID` (Any value except `000000000000`)
- `TEST_AWS_REGION` (Any value except `us-east-1`)

You may also opt to create a commit (for example: [`da3f8d5`](https://github.com/localstack/localstack/pull/9751/commits/da3f8d5f2328adb7c5c025722994fea4433c08ba)) to test the pipeline for non-default credentials against your changes.
Note that within all tests you must use `account_id`, `secondary_account_id`, `region_name`, `secondary_region_name` fixtures.
Importing and using `localstack.constants.TEST_` values is not advised.
