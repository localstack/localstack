from localstack.testing.pytest import markers
from tests.aws.services.apigateway.apigateway_fixtures import (
    create_rest_resource,
    create_rest_resource_method,
    create_rest_api_integration,
    api_invoke_url,
)
from localstack.utils.http import safe_requests as requests


@markers.aws.validated
def test_lambda_aws_proxy_integration(create_parameter, aws_client, create_rest_apigw):
    param_name = "param-test-123"
    create_parameter(
        Name=param_name,
        Description="test",
        Value="123",
        Type="String",
    )
    api_id, _, root = create_rest_apigw(name="aws ssm parameter api")
    resource_id, _ = create_rest_resource(
        aws_client.apigateway, restApiId=api_id, parentId=root, pathPart="test"
    )

    # create method and integration
    create_rest_resource_method(
        aws_client.apigateway,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    uri = f"arn:aws:apigateway:{aws_client.apigateway.meta.region_name}:ssm:action/GetParameter"
    create_rest_api_integration(
        aws_client.apigateway,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        integrationHttpMethod="GET",
        type="AWS",
        uri=uri,
    )

    url = api_invoke_url(api_id=api_id, stage="local", path="/test")
    response = requests.get(url)
    body = response.json()

    assert response.status_code == 400
    assert f'"{uri}" not yet implemented' in body["message"]