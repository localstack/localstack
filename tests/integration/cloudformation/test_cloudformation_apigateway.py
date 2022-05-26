import os.path

import pytest

from localstack import constants
from localstack.utils.common import short_uid


def test_cfn_apigateway_aws_integration(
    apigateway_client, s3_client, iam_client, deploy_cfn_template
):
    api_name = f"rest-api-{short_uid()}"
    custom_id = short_uid()

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/apigw-awsintegration-request-parameters.yaml"
        ),
        parameters={
            "ApiName": api_name,
            "CustomTagKey": "_custom_id_",
            "CustomTagValue": custom_id,
        },
    )

    # check resources creation
    apis = [api for api in apigateway_client.get_rest_apis()["items"] if api["name"] == api_name]
    assert len(apis) == 1
    api_id = apis[0]["id"]

    # check resources creation
    resources = apigateway_client.get_resources(restApiId=api_id)["items"]
    assert (
        resources[0]["resourceMethods"]["GET"]["requestParameters"]["method.request.path.id"]
        is False
    )
    assert (
        resources[0]["resourceMethods"]["GET"]["methodIntegration"]["requestParameters"][
            "integration.request.path.object"
        ]
        == "method.request.path.id"
    )

    # check domains creation
    domain_names = [
        domain["domainName"] for domain in apigateway_client.get_domain_names()["items"]
    ]
    expected_domain = "cfn5632.localstack.cloud"  # hardcoded value from template yaml file
    assert expected_domain in domain_names

    # check basepath mappings creation
    mappings = [
        mapping["basePath"]
        for mapping in apigateway_client.get_base_path_mappings(domainName=expected_domain)["items"]
    ]
    assert len(mappings) == 1
    assert mappings[0] == "(none)"


@pytest.mark.only_localstack
def test_url_output(apigateway_client, tmp_http_server, deploy_cfn_template):
    test_port, invocations, proxy = tmp_http_server
    integration_uri = f"http://localhost:{test_port}/{{proxy}}"
    api_name = f"rest-api-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/apigateway-url-output.yaml"
        ),
        template_mapping={
            "api_name": api_name,
            "integration_uri": integration_uri,
        },
    )

    assert len(stack.outputs) == 2
    api_id = stack.outputs["ApiV1IdOutput"]
    api_url = stack.outputs["ApiV1UrlOutput"]
    assert api_id
    assert api_url
    assert api_id in api_url

    assert f"https://{api_id}.execute-api.{constants.LOCALHOST_HOSTNAME}:4566" in api_url
