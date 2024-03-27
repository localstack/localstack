import json

import pytest
import requests

from localstack.testing.pytest import markers
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url


@pytest.fixture
def add_http_integration_transformers(snapshot):
    key_value_transform = [
        "accept-encoding",  # TODO: We add an extra space when adding this header
        "content-length",
        "date",
        "domain",
        "host",
        "user-agent",
        "x-amzn-apigateway-api-id",
        "x-amzn-tls-cipher-suite",
        "x-amzn-tls-version",
        "x-amzn-trace-id",
        "x-forwarded-port",
        "x-forwarded-proto",
    ]
    for key in key_value_transform:
        snapshot.add_transformer(snapshot.transform.key_value(key, reference_replacement=False))


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # TODO: x-forwarded-for header is actually set when the request is sent to `requests.request`.
        # Custom servers receive the header, but lambda execution code receives an empty string.
        "$..content.headers.x-forwarded-for",
        "$..content.headers.x-localstack-edge",
        "$..headers.x-amz-apigw-id",  # TODO: we should add that header when forwardign the response
        "$..headers.server",
        "$..headers.x-amzn-requestid",
        "$..headers.x-amzn-trace-id",
        "$..origin",
    ]
)
def test_http_integration_with_lambda(
    create_echo_http_server,
    create_rest_api_with_integration,
    snapshot,
    add_http_integration_transformers,
):
    echo_server_url = create_echo_http_server()
    # create api gateway
    stage_name = "test"
    api_id = create_rest_api_with_integration(
        integration_uri=echo_server_url, integration_type="HTTP", stage=stage_name
    )
    invocation_url = api_invoke_url(
        api_id=api_id,
        stage=stage_name,
        path="/test",
    )

    def invoke_api(url):
        # use test header with different casing to check if it is preserved in the proxy payload
        # authorization is a weird case, it will get Pascal cased by default
        response = requests.post(
            url,
            data=json.dumps({"message": "hello world"}),
            headers={
                "Content-Type": "application/json",
                "user-agent": "localstack/test",
                "accept": "application/json",
            },
            verify=False,
        )
        assert 200 == response.status_code
        return {
            "content": response.json(),
            "headers": {k.lower(): v for k, v in dict(response.headers).items()},
            "status_code": response.status_code,
        }

    # retry is necessary against AWS, probably IAM permission delay
    invoke_response = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("http-invocation-lambda-url", invoke_response)
