import json
import os
import os.path

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@markers.aws.validated
def test_sam_policies(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.iam_api())
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sam_function-policies.yaml"
        )
    )
    role_name = stack.outputs["HelloWorldFunctionIamRoleName"]

    roles = aws_client.iam.list_attached_role_policies(RoleName=role_name)
    assert "AmazonSNSFullAccess" in [p["PolicyName"] for p in roles["AttachedPolicies"]]
    snapshot.match("list_attached_role_policies", roles)


@markers.aws.unknown
def test_sam_template(deploy_cfn_template, aws_client):
    # deploy template
    func_name = f"test-{short_uid()}"
    deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/template4.yaml"),
        parameters={"FunctionName": func_name},
    )

    # run Lambda test invocation
    result = aws_client.lambda_.invoke(FunctionName=func_name)
    result = json.load(result["Payload"])
    assert result == {"hello": "world"}


@markers.aws.validated
def test_sam_sqs_event(deploy_cfn_template, aws_client):
    result_key = f"event-{short_uid()}"
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sam_sqs_template.yml"
        ),
        parameters={"ResultKey": result_key},
    )

    queue_url = stack.outputs["QueueUrl"]
    bucket_name = stack.outputs["BucketName"]

    message_body = "test"
    aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)

    def get_object():
        return json.loads(
            aws_client.s3.get_object(Bucket=bucket_name, Key=result_key)["Body"].read().decode()
        )["Records"][0]["body"]

    body = retry(get_object, retries=10, sleep=5.0)

    assert body == message_body

    @pytest.mark.parametrize(
        "create_bucket_first,bucket_region", [(True, "eu-west-1"), (False, "us-east-1")]
    )
    @markers.aws.unknown
    def test_cfn_handle_serverless_api_resource(
        self, deploy_cfn_template, aws_client, account_id, region_name
    ):
        stack = deploy_cfn_template(template=TEST_TEMPLATE_22)

        res = aws_client.cloudformation.list_stack_resources(StackName=stack.stack_name)[
            "StackResourceSummaries"
        ]
        rest_api_ids = [
            r["PhysicalResourceId"] for r in res if r["ResourceType"] == "AWS::ApiGateway::RestApi"
        ]
        lambda_func_names = [
            r["PhysicalResourceId"] for r in res if r["ResourceType"] == "AWS::Lambda::Function"
        ]

        assert len(rest_api_ids) == 1
        assert len(lambda_func_names) == 1

        rs = aws_client.apigateway.get_resources(restApiId=rest_api_ids[0])
        assert len(rs["items"]) == 1
        resource = rs["items"][0]

        uri = resource["resourceMethods"]["GET"]["methodIntegration"]["uri"]
        lambda_arn = arns.lambda_function_arn(
            lambda_func_names[0], account_id=account_id, region_name=region_name
        )
        assert lambda_arn in uri
