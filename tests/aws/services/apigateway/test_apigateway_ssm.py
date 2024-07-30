import json

import pytest
import xmltodict
from botocore.auth import SigV4Auth

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.http import safe_requests as requests
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY, is_next_gen_api


@markers.aws.validated
@pytest.mark.skipif(condition=not is_next_gen_api(), reason="Not implemented in default APIGW")
@markers.snapshot.skip_snapshot_verify(
    # seems like LocalStack is not returning the field
    path=["$..Tier"],
)
def test_ssm_aws_integration(
    aws_client,
    create_parameter,
    create_rest_apigw,
    create_role_with_policy,
    region_name,
    snapshot,
):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value(
                "LastModifiedDate", reference_replacement=False, value_replacement="<timestamp>"
            )
        ]
    )
    param_name = "param-test-123"
    put_param = create_parameter(
        Name=param_name,
        Description="test",
        Value="123",
        Type="String",
    )
    snapshot.match("put-param", put_param)
    api_id, _, root = create_rest_apigw(name="aws ssm parameter api")

    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "ssm:GetParameter", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id,
        parentId=root,
        pathPart="ssm",
    )["id"]

    # create method and integration
    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )

    uri = f"arn:aws:apigateway:{region_name}:ssm:action/GetParameter"
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        integrationHttpMethod="POST",
        type="AWS",
        credentials=role_arn,
        uri=uri,
        passthroughBehavior="WHEN_NO_TEMPLATES",
        requestParameters={"integration.request.querystring.Name": f"'{param_name}'"},
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
    )

    aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseModels={"application/json": "Empty"},
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName="test")

    url = api_invoke_url(api_id=api_id, stage="test", path="/ssm")

    def invoke_api() -> requests.Response:
        _response = requests.get(url)
        assert _response.ok
        return _response

    response = retry(invoke_api, sleep=2, retries=10)
    body = response.json()["GetParameterResponse"]
    body["ResponseMetadata"]["HTTPHeaders"] = response.headers
    snapshot.match("ssm-aws-integration", body)


@markers.aws.validated
@pytest.mark.skipif(
    condition=not is_aws_cloud(),
    reason="Legacy protocol, just to confirm AWS behavior",
)
def test_get_parameter_query_protocol(
    create_parameter, aws_client, aws_http_client_factory, region_name, snapshot
):
    """
    This test is written to confirm the behavior from AWS. It seems that by default, AWS will target the legacy
    Query protocol version of SSM.
    """
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("Name"),
            snapshot.transform.key_value(
                "LastModifiedDate", reference_replacement=False, value_replacement="<timestamp>"
            ),
        ]
    )
    param_name = f"param-{short_uid()}"
    create_parameter(
        Name=param_name,
        Description="test",
        Value="123",
        Type="String",
    )

    ssm_http_client = aws_http_client_factory("ssm", signer_factory=SigV4Auth)

    endpoint_url = f"https://ssm.{region_name}.amazonaws.com"
    parameters = {
        "Action": "GetParameter",
        "Name": param_name,
    }

    resp = ssm_http_client.post(
        url=endpoint_url,
        params=parameters,
    )
    response_json = xmltodict.parse(resp.content)["GetParameterResponse"]
    response_json["ResponseMetadata"]["HTTPHeaders"] = resp.headers
    snapshot.match("get-parameter-query-default", response_json)

    resp = ssm_http_client.post(
        url=endpoint_url, params=parameters, headers={"Accept": "application/json"}
    )
    response_json = resp.json()["GetParameterResponse"]
    response_json["ResponseMetadata"]["HTTPHeaders"] = resp.headers
    snapshot.match("get-parameter-query-json", response_json)
