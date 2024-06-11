import json

import requests
import xmltodict

from localstack.testing.pytest import markers
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY


@markers.aws.validated
def test_apigateway_s3(
    aws_client, create_rest_apigw, s3_create_bucket, region_name, create_role_with_policy, snapshot
):
    api_id, api_name, root_id = create_rest_apigw()
    bucket = s3_create_bucket()
    stage_name = "test"
    object_name = "test.json"

    _, role_arn = create_role_with_policy(
        "Allow", "s3:*", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="{object_path+}"
    )["id"]

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        authorizationType="NONE",
        requestParameters={"method.request.path.object_path": True},
    )
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="ANY", statusCode="200"
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        integrationHttpMethod="ANY",
        type="AWS",
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{bucket}/{{object_path}}",
        requestParameters={
            "integration.request.path.object_path": "method.request.path.object_path"
        },
        credentials=role_arn,
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="ANY", statusCode="200"
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

    invoke_url = api_invoke_url(api_id, stage_name, path="/" + object_name)

    def _invoke(url, method="GET", body=None, assert_text_body: bool = False):
        response = requests.request(url=url, method=method, data=body)
        assert response.status_code == 200
        if assert_text_body:
            assert response.text.startswith("put_id")
        return response

    # Try to get an object that doesn't exists
    response = retry(lambda: _invoke(invoke_url), retries=10, sleep=2)
    snapshot.match("get-object-empty", xmltodict.parse(response.content))

    # Put a new object
    retry(lambda: _invoke(invoke_url, "PUT", {"put_id": 1}), retries=10, sleep=2)
    response = retry(lambda: _invoke(invoke_url, assert_text_body=True), retries=10, sleep=2)
    snapshot.match("get-object-1", response.text)

    # updated an object
    retry(lambda: _invoke(invoke_url, "PUT", {"put_id": 2}), retries=10, sleep=2)
    response = retry(lambda: _invoke(invoke_url, assert_text_body=True), retries=10, sleep=2)
    snapshot.match("get-object-2", response.text)

    # Delete an object
    retry(lambda: _invoke(invoke_url, "DELETE"), retries=10, sleep=2)
    response = retry(lambda: _invoke(invoke_url), retries=10, sleep=2)
    snapshot.match("get-object-deleted", xmltodict.parse(response.content))
