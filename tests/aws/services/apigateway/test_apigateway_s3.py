import json

import pytest
import requests
import xmltodict

from localstack.testing.pytest import markers
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY


@markers.aws.validated
def test_apigateway_s3_any(
    aws_client, create_rest_apigw, s3_bucket, region_name, create_role_with_policy, snapshot
):
    api_id, api_name, root_id = create_rest_apigw()
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
        requestParameters={
            "method.request.path.object_path": True,
            "method.request.header.Content-Type": False,
        },
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
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{{object_path}}",
        requestParameters={
            "integration.request.path.object_path": "method.request.path.object_path",
            "integration.request.header.Content-Type": "method.request.header.Content-Type",
        },
        credentials=role_arn,
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="ANY", statusCode="200"
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

    invoke_url = api_invoke_url(api_id, stage_name, path="/" + object_name)

    def _get_object(assert_json: bool = False):
        response = requests.get(url=invoke_url)
        assert response.status_code == 200
        if assert_json:
            response.json()
        return response

    def _put_object(data: dict):
        response = requests.put(
            url=invoke_url, json=data, headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 200

    # # Try to get an object that doesn't exists
    # TODO AWS sends a 200 with the xml empty bucket response from s3 when no objects are present.
    # response = retry(lambda: _get_object, retries=10, sleep=2)
    # snapshot.match("get-object-empty", xmltodict.parse(response.content))

    # Put a new object
    retry(lambda: _put_object({"put_id": 1}), retries=10, sleep=2)
    response = retry(lambda: _get_object(assert_json=True), retries=10, sleep=2)
    snapshot.match("get-object-1", response.text)

    # updated an object
    retry(lambda: _put_object({"put_id": 2}), retries=10, sleep=2)
    response = retry(lambda: _get_object(assert_json=True), retries=10, sleep=2)
    snapshot.match("get-object-2", response.text)

    # Delete an object
    requests.delete(invoke_url)
    # TODO AWS sends a 200 with the xml empty bucket response from s3 when no objects are present.
    # response = retry(lambda: _get_object, retries=10, sleep=2)
    # snapshot.match("get-object-deleted", xmltodict.parse(response.content))

    # TODO We can remove this part when we get the empty bucket response on parity
    with pytest.raises(Exception) as exc_info:
        aws_client.s3.get_object(Bucket=s3_bucket, Key=object_name)
    snapshot.match("get-object-s3", exc_info.value.response)

    # Make a POST request
    #  TODO AWS return a 200 with a message from s3 in xml format stating that POST is invalid
    # response = requests.post(invoke_url, headers={"Content-Type": "application/json"}, json={"put_id": 3})
    # snapshot.match("post-object", xmltodict.parse(response.content))


@pytest.mark.skip(reason="Need to implement a solution for method mapping")
@markers.aws.validated
def test_apigateway_s3_method_mapping(
    aws_client, create_rest_apigw, s3_bucket, region_name, create_role_with_policy, snapshot
):
    snapshot.add_transformers_list(
        [snapshot.transform.key_value("HostId"), snapshot.transform.key_value("RequestId")]
    )

    api_id, api_name, root_id = create_rest_apigw()
    stage_name = "test"
    object_name = "test.json"

    _, role_arn = create_role_with_policy(
        "Allow", "s3:*", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    get_resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="get"
    )["id"]
    put_resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="put"
    )["id"]
    delete_resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="delete"
    )["id"]

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=get_resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=put_resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=delete_resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )

    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=delete_resource_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=put_resource_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=get_resource_id, httpMethod="GET", statusCode="200"
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=get_resource_id,
        httpMethod="GET",
        integrationHttpMethod="GET",
        type="AWS",
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{object_name}",
        credentials=role_arn,
    )
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=put_resource_id,
        httpMethod="GET",
        integrationHttpMethod="PUT",
        type="AWS",
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{object_name}",
        requestParameters={
            "integration.request.header.Content-Type": "'application/json'",
        },
        requestTemplates={"application/json": '{"message": "great success!"}'},
        credentials=role_arn,
    )
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=delete_resource_id,
        httpMethod="GET",
        integrationHttpMethod="DELETE",
        type="AWS",
        uri=f"arn:aws:apigateway:{region_name}:s3:path/{s3_bucket}/{object_name}",
        credentials=role_arn,
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=get_resource_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=put_resource_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=delete_resource_id, httpMethod="GET", statusCode="200"
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

    get_invoke_url = api_invoke_url(api_id, stage_name, path="/get")
    put_invoke_url = api_invoke_url(api_id, stage_name, path="/put")
    delete_invoke_url = api_invoke_url(api_id, stage_name, path="/delete")

    def _invoke(url, get_json: bool = False, get_xml: bool = False):
        response = requests.get(url=url)
        assert response.status_code == 200
        if get_json:
            response = response.json()
        elif get_xml:
            response = xmltodict.parse(response.text)
        return response

    retry(lambda: _invoke(put_invoke_url), retries=10, sleep=2)
    get_object = retry(lambda: _invoke(get_invoke_url, get_json=True), retries=10, sleep=3)
    snapshot.match("get-object", get_object)
    _invoke(delete_invoke_url)

    get_object = retry(lambda: _invoke(get_invoke_url, get_xml=True), retries=10, sleep=2)
    snapshot.match("get-deleted-object", get_object)
