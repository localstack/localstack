import json
import re

import pytest
import requests

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import retry
from localstack.utils.xml import is_valid_xml
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY
from tests.aws.services.apigateway.test_apigateway_basic import TEST_STAGE_NAME


@markers.aws.validated
def test_sqs_aws_integration(
    create_rest_apigw,
    sqs_create_queue,
    aws_client,
    create_role_with_policy,
    region_name,
    account_id,
    snapshot,
):
    # create target SQS stream
    queue_name = f"queue-{short_uid()}"
    queue_url = sqs_create_queue(QueueName=queue_name)

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
        uri=f"arn:aws:apigateway:{region_name}:sqs:path/{account_id}/{queue_name}",
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
        _response = requests.post(url, json={"foo": "bar"})
        assert _response.ok
        content = _response.json()
        assert content == {"message": "great success!"}
        return content

    response_data = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("sqs-aws-integration", response_data)

    def get_sqs_message():
        messages = aws_client.sqs.receive_message(QueueUrl=queue_url).get("Messages", [])
        assert 1 == len(messages)
        return messages[0]

    message = retry(get_sqs_message, sleep=2, retries=10)
    snapshot.match("sqs-message", json.loads(message["Body"]))


@markers.aws.validated
def test_sqs_request_and_response_xml_templates_integration(
    create_rest_apigw,
    sqs_create_queue,
    aws_client,
    create_role_with_policy,
    region_name,
    account_id,
    snapshot,
):
    queue_name = f"queue-{short_uid()}"
    sqs_create_queue(QueueName=queue_name)

    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "sqs:SendMessage", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    api_id, _, root = create_rest_apigw(
        name=f"test-api-${short_uid()}",
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
        uri=f"arn:aws:apigateway:{region_name}:sqs:path/{account_id}/{queue_name}",
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
        responseTemplates={
            "application/json": """
            #set($responseBody = $input.path('$.SendMessageResponse'))
            #set($requestId = $input.path('$.SendMessageResponse.ResponseMetadata.RequestId'))
            #set($messageId = $responseBody.SendMessageResult.MessageId)
            {
            "requestId": "$requestId",
            "messageId": "$messageId"
            }
            """
        },
    )

    response = aws_client.apigateway.create_deployment(
        restApiId=api_id,
    )
    deployment_id = response["id"]

    aws_client.apigateway.create_stage(
        restApiId=api_id, stageName=TEST_STAGE_NAME, deploymentId=deployment_id
    )

    invocation_url = api_invoke_url(api_id=api_id, stage=TEST_STAGE_NAME, path="/sqs")

    def invoke_api(url, validate_xml=None):
        _response = requests.post(url, data="<xml>Hello World</xml>", verify=False)
        if validate_xml:
            assert is_valid_xml(_response.content.decode("utf-8"))
            return _response

        assert _response.ok
        return _response

    response_data = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("sqs-json-response", response_data.json())

    # patch integration request parameters to use Accept header with "application/xml"
    # and remove response templates
    aws_client.apigateway.update_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        patchOperations=[
            {
                "op": "add",
                "path": "/requestParameters/integration.request.header.Accept",
                "value": "'application/xml'",
            }
        ],
    )

    aws_client.apigateway.update_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        patchOperations=[
            {
                "op": "remove",
                "path": "/responseTemplates/application~1json",
                "value": "application/json",
            }
        ],
    )

    # create deployment and update stage for re-deployment
    deployment = aws_client.apigateway.create_deployment(
        restApiId=api_id,
    )

    aws_client.apigateway.update_stage(
        restApiId=api_id,
        stageName=TEST_STAGE_NAME,
        patchOperations=[{"op": "replace", "path": "/deploymentId", "value": deployment["id"]}],
    )

    response = retry(invoke_api, sleep=2, retries=10, url=invocation_url, validate_xml=True)

    xml_body = to_str(response.content)
    # snapshotting would be great, but the response differs from AWS on the XML on the element order
    assert re.search("<MessageId>.*</MessageId>", xml_body)
    assert re.search("<MD5OfMessageBody>.*</MD5OfMessageBody>", xml_body)
    assert re.search("<RequestId>.*</RequestId>", xml_body)


@pytest.mark.parametrize("message_attribute", ["MessageAttribute", "MessageAttributes"])
@markers.aws.validated
def test_sqs_aws_integration_with_message_attribute(
    create_rest_apigw,
    sqs_create_queue,
    aws_client,
    create_role_with_policy,
    region_name,
    account_id,
    snapshot,
    message_attribute,
):
    # create target SQS stream
    queue_name = f"queue-{short_uid()}"
    queue_url = sqs_create_queue(QueueName=queue_name)

    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "sqs:SendMessage", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    api_id, _, root = create_rest_apigw(
        name=f"test-api-${short_uid()}",
        description="Test Integration with SQS",
    )

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=root,
        httpMethod="POST",
        authorizationType="NONE",
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=root,
        httpMethod="POST",
        type="AWS",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{region_name}:sqs:path/{account_id}/{queue_name}",
        credentials=role_arn,
        requestParameters={
            "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"
        },
        requestTemplates={
            "application/json": (
                "Action=SendMessage&MessageBody=$input.body&"
                f"{message_attribute}.1.Name=user-agent&"
                f"{message_attribute}.1.Value.DataType=String&"
                f"{message_attribute}.1.Value.StringValue=$input.params('HeaderFoo')"
            )
        },
        passthroughBehavior="NEVER",
    )

    aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=root,
        httpMethod="POST",
        statusCode="200",
        responseModels={"application/json": "Empty"},
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=root,
        httpMethod="POST",
        statusCode="200",
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=TEST_STAGE_NAME)
    invocation_url = api_invoke_url(api_id=api_id, stage=TEST_STAGE_NAME, path="/")

    def invoke_api(url):
        _response = requests.post(url, json={"foo": "bar"}, headers={"HeaderFoo": "BAR-Header"})
        assert _response.ok

    retry(invoke_api, sleep=2, retries=10, url=invocation_url)

    def get_sqs_message():
        messages = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        ).get("Messages", [])
        assert 1 == len(messages)
        return messages[0]

    message = retry(get_sqs_message, sleep=2, retries=10)
    snapshot.match("sqs-message-body", message["Body"])
    snapshot.match("sqs-message-attributes", message["MessageAttributes"])
