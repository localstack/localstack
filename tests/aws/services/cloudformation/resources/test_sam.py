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


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..Tags", "$..tags", "$..Configuration.CodeSha256"])
def test_cfn_handle_serverless_api_resource(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/sam_api.yml"),
    )

    response = aws_client.apigateway.get_rest_api(restApiId=stack.outputs["ApiId"])
    snapshot.match("get_rest_api", response)

    response = aws_client.lambda_.get_function(FunctionName=stack.outputs["LambdaFunction"])
    snapshot.match("get_function", response)

    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_id, "<stack-id>"))
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "<stack-name>"))
