import json
import os.path

import pytest
import requests

from localstack import constants
from localstack.utils.common import short_uid
from localstack.utils.files import load_file
from localstack.utils.run import to_str
from localstack.utils.testutil import create_zip_file
from tests.integration.apigateway_fixtures import api_invoke_url

TEST_TEMPLATE_1 = """
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Parameters:
  ApiName:
    Type: String
  IntegrationUri:
    Type: String
Resources:
  Api:
    Type: AWS::Serverless::Api
    Properties:
      StageName: dev
      Name: !Ref ApiName
      DefinitionBody:
        swagger: 2.0
        info:
          version: "1.0"
          title: "Public API"
        basePath: /base
        schemes:
        - "https"
        x-amazon-apigateway-binary-media-types:
        - "*/*"
        paths:
          /test:
            post:
              responses: {}
              x-amazon-apigateway-integration:
                uri: !Ref IntegrationUri
                httpMethod: "POST"
                type: "http_proxy"
"""


def test_cfn_apigateway_aws_integration(
    apigateway_client, s3_client, iam_client, deploy_cfn_template
):
    api_name = f"rest-api-{short_uid()}"
    custom_id = short_uid()

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../templates/apigw-awsintegration-request-parameters.yaml",
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


@pytest.mark.skip_offline
@pytest.mark.aws_validated
def test_cfn_apigateway_swagger_import(deploy_cfn_template, apigateway_client):
    api_name = f"rest-api-{short_uid()}"
    int_uri = "http://httpbin.org/post"
    deploy_cfn_template(
        template=TEST_TEMPLATE_1,
        parameters={"ApiName": api_name, "IntegrationUri": int_uri},
    )

    # get API details
    apis = [api for api in apigateway_client.get_rest_apis()["items"] if api["name"] == api_name]
    assert len(apis) == 1
    api_id = apis[0]["id"]

    # construct API endpoint URL
    url = api_invoke_url(api_id, stage="dev", path="/test")

    # invoke API endpoint, assert results
    result = requests.post(url, data="test 123")
    assert result.ok
    content = json.loads(to_str(result.content))
    assert content["data"] == "test 123"
    assert content["url"].endswith("/post")


@pytest.mark.only_localstack
def test_url_output(apigateway_client, tmp_http_server, deploy_cfn_template):
    test_port, invocations, proxy = tmp_http_server
    integration_uri = f"http://localhost:{test_port}/{{proxy}}"
    api_name = f"rest-api-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/apigateway-url-output.yaml"
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


def test_cfn_with_apigateway_resources(deploy_cfn_template, apigateway_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/template35.yaml")
    )
    apis = [
        api
        for api in apigateway_client.get_rest_apis()["items"]
        if api["name"] == "celeste-Gateway-local"
    ]
    assert len(apis) == 1
    api_id = apis[0]["id"]

    resources = [
        res
        for res in apigateway_client.get_resources(restApiId=api_id)["items"]
        if res.get("pathPart") == "account"
    ]

    assert len(resources) == 1

    # assert request parameter is present in resource method
    assert resources[0]["resourceMethods"]["POST"]["requestParameters"] == {
        "method.request.path.account": True
    }
    models = [
        model
        for model in apigateway_client.get_models(restApiId=api_id)["items"]
        if stack.stack_name in model["name"]
    ]

    assert len(models) == 2

    stack.destroy()

    apis = [
        api
        for api in apigateway_client.get_rest_apis()["items"]
        if api["name"] == "celeste-Gateway-local"
    ]
    assert not apis


@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..binaryMediaTypes",
        "$..version",
        "$..methodIntegration.cacheNamespace",
        "$..methodIntegration.connectionType",
        "$..methodIntegration.passthroughBehavior",
        "$..methodIntegration.requestTemplates",
        "$..methodIntegration.timeoutInMillis",
        "$..methodResponses",
        "$..requestModels",
        "$..requestParameters",
    ]
)
def test_cfn_deploy_apigateway_integration(
    deploy_cfn_template, s3_client, s3_create_bucket, cfn_client, apigateway_client, snapshot
):
    bucket_name = f"hofund-local-deployment-{short_uid()}"
    key_name = "serverless/hofund/local/1599143878432/authorizer.zip"
    package_path = os.path.join(
        os.path.dirname(__file__), "../../awslambda/functions/lambda_echo.js"
    )

    s3_create_bucket(Bucket=bucket_name, ACL="public-read")
    s3_client.put_object(
        Bucket=bucket_name,
        Key=key_name,
        Body=create_zip_file(package_path, get_content=True),
    )

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/apigateway_integration.yml"
        ),
        parameters={"CodeBucket": bucket_name, "CodeKey": key_name},
        max_wait=120,
    )

    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "stack-name"))

    rest_api_id = stack.outputs["RestApiId"]
    rest_api = apigateway_client.get_rest_api(restApiId=rest_api_id)
    snapshot.match("rest_api", rest_api)

    resource_id = stack.outputs["ResourceId"]
    method = apigateway_client.get_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
    )
    snapshot.match("method", method)


def test_cfn_apigateway_rest_api(deploy_cfn_template, apigateway_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/apigateway.json")
    )

    rs = apigateway_client.get_rest_apis()
    apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
    assert not apis

    stack.destroy()

    stack_2 = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/apigateway.json"),
        parameters={"Create": "True"},
    )
    rs = apigateway_client.get_rest_apis()
    apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
    assert len(apis) == 1

    rs = apigateway_client.get_models(restApiId=apis[0]["id"])
    assert len(rs["items"]) == 1

    stack_2.destroy()

    apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
    assert not apis


@pytest.mark.aws_validated
def test_account(deploy_cfn_template, apigateway_client, cfn_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/apigateway_account.yml"
        )
    )

    account_info = apigateway_client.get_account()
    assert account_info["cloudwatchRoleArn"] == stack.outputs["RoleArn"]

    # Assert that after deletion of stack, the apigw account is not updated
    stack.destroy()
    cfn_client.get_waiter("stack_delete_complete").wait(StackName=stack.stack_name)
    account_info = apigateway_client.get_account()
    assert account_info["cloudwatchRoleArn"] == stack.outputs["RoleArn"]


@pytest.mark.aws_validated
def test_update_usage_plan(deploy_cfn_template, cfn_client, apigateway_client):
    rest_api_name = f"api-{short_uid()}"
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/apigateway_usage_plan.yml"
        ),
        parameters={"QuotaLimit": "5000", "RestApiName": rest_api_name},
    )

    deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        template=load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/apigateway_usage_plan.yml")
        ),
        parameters={"QuotaLimit": "7000", "RestApiName": rest_api_name},
    )

    cfn_client.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)

    usage_plan = apigateway_client.get_usage_plan(usagePlanId=stack.outputs["UsagePlanId"])

    assert 7000 == usage_plan["quota"]["limit"]
