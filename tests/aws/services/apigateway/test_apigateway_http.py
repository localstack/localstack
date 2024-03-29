import json

import pytest
import requests

from localstack.testing.pytest import markers
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url


@pytest.fixture
def add_http_integration_transformers(snapshot):
    key_value_transform = [
        "date",
        "domain",
        "host",
        "origin",
        "rest_api_id",
        "x-amz-apigw-id",
        "x-amzn-tls-cipher-suite",
        "x-amzn-tls-version",
        "x-amzn-requestid",
        "x-amzn-trace-id",
        "x-forwarded-for",
        "x-forwarded-port",
        "x-forwarded-proto",
    ]
    for key in key_value_transform:
        snapshot.add_transformer(snapshot.transform.key_value(key))

    snapshot.add_transformer(
        snapshot.transform.jsonpath(
            "$.*.headers.content-length",
            reference_replacement=True,
            value_replacement="content_length",
        ),
        priority=1,
    )


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..content.headers.accept-encoding",  # TODO: We add an extra space when adding this header
        "$..content.headers.user-agent",  # TODO: We have to properly set that header on non proxied requests.
        # TODO: x-forwarded-for header is actually set when the request is sent to `requests.request`.
        # Custom servers receive the header, but lambda execution code receives an empty string.
        "$..content.headers.x-forwarded-for",
        "$..content.headers.x-localstack-edge",
        "$..headers.server",
        "$..headers.x-amz-apigw-id",  # TODO: we should add that header when forwarding the response
        #  TODO the remapped headers are currently not added to apigateway response
        "$..headers.x-amzn-remapped-connection",
        "$..headers.x-amzn-remapped-content-length",
        "$..headers.x-amzn-remapped-date",
        "$..headers.x-amzn-remapped-x-amzn-requestid",
        "$..headers.x-amzn-requestid",
        "$..headers.x-amzn-trace-id",
        "$..origin",
    ]
)
@pytest.mark.parametrize("integration_type", ["HTTP", "HTTP_PROXY"])
def test_http_integration_with_lambda(
    integration_type,
    create_echo_http_server,
    create_rest_api_with_integration,
    snapshot,
    add_http_integration_transformers,
):
    echo_server_url = create_echo_http_server(trim_x_headers=False)
    # create api gateway
    stage_name = "test"
    api_id = create_rest_api_with_integration(
        integration_uri=echo_server_url, integration_type=integration_type, stage=stage_name
    )
    snapshot.match("api_id", {"rest_api_id": api_id})
    invocation_url = api_invoke_url(
        api_id=api_id,
        stage=stage_name,
        path="/test",
    )

    def invoke_api(url):
        response = requests.post(
            url,
            data=json.dumps({"message": "hello world"}),
            headers={
                "Content-Type": "application/json",
                "accept": "application/json",
                "user-Agent": "test/integration",
            },
            verify=False,
        )
        assert response.status_code == 200
        return {
            "content": response.json(),
            "headers": {k.lower(): v for k, v in dict(response.headers).items()},
            "status_code": response.status_code,
        }

    # retry is necessary against AWS, probably IAM permission delay
    invoke_response = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("http-invocation-lambda-url", invoke_response)
