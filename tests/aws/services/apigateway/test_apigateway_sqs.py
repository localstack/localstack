import base64
import json

import requests

from localstack.services.apigateway.helpers import connect_api_gateway_to_sqs, path_based_url
from localstack.testing.pytest import markers
from localstack.utils.aws import queries
from localstack.utils.aws import resources as resource_util
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY
from tests.aws.services.apigateway.test_apigateway_basic import TEST_STAGE_NAME


@markers.aws.unknown
def test_api_gateway_sqs_integration(aws_client):
    # create target SQS stream
    queue_name = f"queue-{short_uid()}"
    resource_util.create_sqs_queue(queue_name)

    # create API Gateway and connect it to the target queue
    result = connect_api_gateway_to_sqs(
        "test_gateway4",
        stage_name=TEST_STAGE_NAME,
        queue_arn=queue_name,
        path="/data",
    )

    # generate test data
    test_data = {"spam": "eggs"}

    url = path_based_url(
        api_id=result["id"],
        stage_name=TEST_STAGE_NAME,
        path="/data",
    )
    result = requests.post(url, data=json.dumps(test_data))
    assert 200 == result.status_code

    messages = queries.sqs_receive_message(queue_name)["Messages"]
    assert 1 == len(messages)
    assert test_data == json.loads(base64.b64decode(messages[0]["Body"]))


@markers.aws.validated
def test_sqs_aws_integration(
    create_rest_apigw,
    sqs_create_queue,
    aws_client,
    create_role_with_policy,
    region,
    account_id,
    snapshot,
):
    # create target SQS stream
    queue_name = f"queue-{short_uid()}"
    sqs_create_queue(QueueName=queue_name)

    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "sqs:SendMessage", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    api_id, _, root = create_rest_apigw(
        name=f"test-api-${short_uid()}",
        description="Test Integration with SQS",
    )

    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id,
        parentId=root,
        pathPart="sqs",
    )["id"]

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="AWS",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{region}:sqs:path/{account_id}/{queue_name}",
        credentials=role_arn,
        requestParameters={
            "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"
        },
        requestTemplates={"application/json": "Action=SendMessage&MessageBody=$input.body"},
        passthroughBehavior="NEVER",
    )

    aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        responseModels={"application/json": "Empty"},
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "great success!"}'},
    )

    response = aws_client.apigateway.create_deployment(restApiId=api_id)
    deployment_id = response["id"]

    aws_client.apigateway.create_stage(
        restApiId=api_id,
        stageName=TEST_STAGE_NAME,
        deploymentId=deployment_id,
    )

    invocation_url = api_invoke_url(api_id=api_id, stage=TEST_STAGE_NAME, path="/sqs")

    def invoke_api(url):
        _response = requests.post(url, verify=False)
        assert _response.ok
        content = _response.json()
        assert content == {"message": "great success!"}
        return content

    response_data = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("sqs-aws-integration", response_data)
