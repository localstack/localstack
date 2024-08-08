import json
from http import HTTPMethod

import pytest
import requests

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import is_next_gen_api


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
        priority=2,
    )
    # remove the reference replacement, as sometimes we can have a difference with `date`
    snapshot.add_transformer(
        snapshot.transform.key_value(
            "x-amzn-remapped-date",
            value_replacement="<date>",
            reference_replacement=False,
        ),
        priority=-1,
    )


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # TODO: shared between HTTP & HTTP_PROXY
        "$..content.headers.x-forwarded-for",
        "$..content.origin",
        "$..headers.server",
        # TODO: for HTTP integration only: requests (urllib3) automatically adds `Accept-Encoding` when sending the
        #  request, seems like we cannot remove it
        "$..headers.accept-encoding",
        # TODO: for HTTP integration, Lambda URL do not add the Self=<trace-id> to its incoming headers
        "$..headers.x-amzn-trace-id",
        # TODO: only missing for HTTP_PROXY, Must be coming from the lambda url
        "$..headers.x-amzn-remapped-x-amzn-requestid",
        #  TODO AWS doesn't seems to add Server to lambda invocation for lambda url
        "$..headers.x-amzn-remapped-server",
    ]
)
@markers.snapshot.skip_snapshot_verify(
    condition=lambda: not is_next_gen_api(),
    paths=[
        "$..content.headers.x-amzn-trace-id",
        "$..headers.x-amz-apigw-id",
        "$..headers.x-amzn-requestid",
        "$..content.headers.user-agent",  # TODO: We have to properly set that header on non proxied requests.
        "$..content.headers.accept",  # legacy does not properly manage accept header
        # TODO: x-forwarded-for header is actually set when the request is sent to `requests.request`.
        # Custom servers receive the header, but lambda execution code receives an empty string.
        "$..content.headers.x-localstack-edge",
        #  TODO the remapped headers are currently not added to apigateway response
        "$..headers.x-amzn-remapped-connection",
        "$..headers.x-amzn-remapped-content-length",
        "$..headers.x-amzn-remapped-date",
        "$..headers.x-amzn-remapped-x-amzn-requestid",
    ],
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
                "accept": "application/xml",
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


@markers.aws.validated
@pytest.mark.parametrize("integration_type", ["HTTP", "HTTP_PROXY"])
def test_http_integration_invoke_status_code_passthrough(
    aws_client,
    create_status_code_echo_server,
    create_rest_api_with_integration,
    snapshot,
    integration_type,
):
    # Create echo serve
    echo_server_url = create_status_code_echo_server()
    # Create apigw
    stage_name = "test"
    apigw_id = create_rest_api_with_integration(
        integration_uri=f"{echo_server_url}{{map}}",
        integration_type=integration_type,
        path_part="{map+}",
        req_parameters={
            "integration.request.path.map": "method.request.path.map",
        },
        stage=stage_name,
    )

    def invoke_api(url: str, method: HTTPMethod = HTTPMethod.POST):
        response = requests.request(url=url, method=method)
        status_code = response.status_code
        assert status_code != 403
        return {"body": response.json(), "status_code": status_code}

    invocation_url = api_invoke_url(
        api_id=apigw_id,
        stage=stage_name,
        path="/status",
    )

    # Invoke with matching response code
    invoke_response = retry(invoke_api, sleep=2, retries=10, url=f"{invocation_url}/200")
    snapshot.match("matching-response", invoke_response)

    # invoke non matching response code
    invoke_response = retry(invoke_api, sleep=2, retries=10, url=f"{invocation_url}/400")
    snapshot.match("non-matching-response", invoke_response)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # TODO: shared between HTTP & HTTP_PROXY
        "$..origin",
        # TODO: for HTTP integration only: requests (urllib3) automatically adds `Accept-Encoding` when sending the
        #  request, seems like we cannot remove it
        "$..accept-encoding",
    ]
)
@markers.snapshot.skip_snapshot_verify(
    condition=lambda: not is_next_gen_api(),
    paths=[
        "$..headers.user-agent",  # TODO: We have to properly set that header on non proxied requests.
        "$..headers.x-localstack-edge",
    ],
)
@pytest.mark.parametrize("integration_type", ["HTTP", "HTTP_PROXY"])
def test_http_integration_method(
    integration_type,
    create_echo_http_server,
    create_rest_api_with_integration,
    snapshot,
    add_http_integration_transformers,
):
    echo_server_url = create_echo_http_server(trim_x_headers=True)
    # create api gateway
    stage_name = "test"
    api_id = create_rest_api_with_integration(
        integration_uri=echo_server_url,
        integration_type=integration_type,
        stage=stage_name,
        resource_method="ANY",
        integration_method="POST",
    )
    snapshot.match("api_id", {"rest_api_id": api_id})
    invocation_url = api_invoke_url(
        api_id=api_id,
        stage=stage_name,
        path="/test",
    )

    def invoke_api(url: str, method: str) -> dict:
        response = requests.request(
            method=method,
            url=url,
            data=json.dumps({"message": "hello world"}),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "user-Agent": "test/integration",
            },
            verify=False,
        )
        assert response.status_code == 200
        return response.json()

    # retry is necessary against AWS, probably IAM permission delay
    for http_method in ("POST", "PUT", "GET"):
        invoke_response = retry(invoke_api, sleep=2, retries=10, url=invocation_url, method="POST")
        snapshot.match(f"http-invocation-lambda-url-{http_method.lower()}", invoke_response)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..content.origin",
        "$..headers.server",
        "$..headers.x-amzn-remapped-x-amzn-requestid",
        #  TODO AWS doesn't seems to add Server to lambda invocation for lambda url
        "$..headers.x-amzn-remapped-server",
    ]
)
@pytest.mark.skipif(
    condition=not is_next_gen_api() and not is_aws_cloud(),
    reason="Wrong behavior in legacy implementation",
)
def test_http_proxy_integration_request_data_mappings(
    create_echo_http_server,
    create_rest_api_with_integration,
    snapshot,
    add_http_integration_transformers,
):
    echo_server_url = create_echo_http_server(trim_x_headers=True)
    # create api gateway
    stage_name = "test"
    req_parameters = {
        "integration.request.header.headerVar": "method.request.header.foobar",
        "integration.request.path.qsVar": "method.request.querystring.testVar",
        "integration.request.path.pathVar": "method.request.path.pathVariable",
        "integration.request.querystring.queryString": "method.request.querystring.testQueryString",
        "integration.request.querystring.testQs": "method.request.querystring.testQueryString",
        "integration.request.querystring.testEmptyQs": "method.request.header.emptyheader",
    }

    # Note: you cannot use path parameters directly, if you set `testValue={pathVariable}` it will fail
    integration_uri = f"{echo_server_url}?testVar={{pathVar}}&testQs={{qsVar}}"

    api_id = create_rest_api_with_integration(
        integration_uri=integration_uri,
        integration_type="HTTP_PROXY",
        stage=stage_name,
        path_part="{pathVariable}",
        req_parameters=req_parameters,
    )

    snapshot.match("api_id", {"rest_api_id": api_id})
    invocation_url = api_invoke_url(
        api_id=api_id,
        stage=stage_name,
        path="/foobar",
    )

    def invoke_api(url):
        response = requests.post(
            url,
            data=json.dumps({"message": "hello world"}),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "foobar": "mapped-value",
                "user-Agent": "test/integration",
                "headerVar": "request-value",
            },
            params={
                "testQueryString": "foo",
                "testVar": "bar",
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
    snapshot.match("http-proxy-invocation", invoke_response)
