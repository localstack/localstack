import json
import os.path
from operator import itemgetter

import requests

from localstack import constants
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid
from localstack.utils.files import load_file
from localstack.utils.run import to_str
from localstack.utils.strings import to_bytes
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url

PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_LAMBDA_PYTHON_ECHO = os.path.join(PARENT_DIR, "lambda_/functions/lambda_echo.py")

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


# this is an `only_localstack` test because it makes use of _custom_id_ tag
@markers.aws.only_localstack
def test_cfn_apigateway_aws_integration(deploy_cfn_template, aws_client):
    api_name = f"rest-api-{short_uid()}"
    custom_id = short_uid()

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__),
            "../../../templates/apigw-awsintegration-request-parameters.yaml",
        ),
        parameters={
            "ApiName": api_name,
            "CustomTagKey": "_custom_id_",
            "CustomTagValue": custom_id,
        },
    )

    # check resources creation
    apis = [
        api for api in aws_client.apigateway.get_rest_apis()["items"] if api["name"] == api_name
    ]
    assert len(apis) == 1
    api_id = apis[0]["id"]

    # check resources creation
    resources = aws_client.apigateway.get_resources(restApiId=api_id)["items"]
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
        domain["domainName"] for domain in aws_client.apigateway.get_domain_names()["items"]
    ]
    expected_domain = "cfn5632.localstack.cloud"  # hardcoded value from template yaml file
    assert expected_domain in domain_names

    # check basepath mappings creation
    mappings = [
        mapping["basePath"]
        for mapping in aws_client.apigateway.get_base_path_mappings(domainName=expected_domain)[
            "items"
        ]
    ]
    assert len(mappings) == 1
    assert mappings[0] == "(none)"


@markers.aws.validated
def test_cfn_apigateway_swagger_import(deploy_cfn_template, echo_http_server_post, aws_client):
    api_name = f"rest-api-{short_uid()}"
    deploy_cfn_template(
        template=TEST_TEMPLATE_1,
        parameters={"ApiName": api_name, "IntegrationUri": echo_http_server_post},
    )

    # get API details
    apis = [
        api for api in aws_client.apigateway.get_rest_apis()["items"] if api["name"] == api_name
    ]
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


@markers.aws.only_localstack
def test_url_output(httpserver, deploy_cfn_template):
    httpserver.expect_request("").respond_with_data(b"", 200)
    api_name = f"rest-api-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/apigateway-url-output.yaml"
        ),
        template_mapping={
            "api_name": api_name,
            "integration_uri": httpserver.url_for("/{proxy}"),
        },
    )

    assert len(stack.outputs) == 2
    api_id = stack.outputs["ApiV1IdOutput"]
    api_url = stack.outputs["ApiV1UrlOutput"]
    assert api_id
    assert api_url
    assert api_id in api_url

    assert f"https://{api_id}.execute-api.{constants.LOCALHOST_HOSTNAME}:4566" in api_url


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$.get-method-post.methodIntegration.connectionType",  # TODO: maybe because this is a MOCK integration
    ]
)
def test_cfn_with_apigateway_resources(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.key_value("cacheNamespace"))

    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/template35.yaml")
    )
    apis = [
        api
        for api in aws_client.apigateway.get_rest_apis()["items"]
        if api["name"] == "celeste-Gateway-local"
    ]
    assert len(apis) == 1
    api_id = apis[0]["id"]

    resources = [
        res
        for res in aws_client.apigateway.get_resources(restApiId=api_id)["items"]
        if res.get("pathPart") == "account"
    ]

    assert len(resources) == 1

    resp = aws_client.apigateway.get_method(
        restApiId=api_id, resourceId=resources[0]["id"], httpMethod="POST"
    )
    snapshot.match("get-method-post", resp)

    models = aws_client.apigateway.get_models(restApiId=api_id)
    models["items"].sort(key=itemgetter("name"))
    snapshot.match("get-models", models)

    schemas = [model["schema"] for model in models["items"]]
    for schema in schemas:
        # assert that we can JSON load the schema, and that the schema is a valid JSON
        assert isinstance(json.loads(schema), dict)

    stack.destroy()

    apis = [
        api
        for api in aws_client.apigateway.get_rest_apis()["items"]
        if api["name"] == "celeste-Gateway-local"
    ]
    assert not apis


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$.get-resources.items..resourceMethods.ANY",  # TODO: empty in AWS
    ]
)
def test_cfn_deploy_apigateway_models(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/apigateway_models.json"
        )
    )

    api_id = stack.outputs["RestApiId"]

    resources = aws_client.apigateway.get_resources(restApiId=api_id)
    resources["items"].sort(key=itemgetter("path"))
    snapshot.match("get-resources", resources)

    models = aws_client.apigateway.get_models(restApiId=api_id)
    models["items"].sort(key=itemgetter("name"))
    snapshot.match("get-models", models)

    request_validators = aws_client.apigateway.get_request_validators(restApiId=api_id)
    snapshot.match("get-request-validators", request_validators)

    for resource in resources["items"]:
        if resource["path"] == "/validated":
            resp = aws_client.apigateway.get_method(
                restApiId=api_id, resourceId=resource["id"], httpMethod="ANY"
            )
            snapshot.match("get-method-any", resp)

    # construct API endpoint URL
    url = api_invoke_url(api_id, stage="local", path="/validated")

    # invoke API endpoint, assert results
    valid_data = {"string_field": "string", "integer_field": 123456789}

    result = requests.post(url, json=valid_data)
    assert result.ok

    # invoke API endpoint, assert results
    invalid_data = {"string_field": "string"}

    result = requests.post(url, json=invalid_data)
    assert result.status_code == 400

    result = requests.get(url)
    assert result.status_code == 400


@markers.aws.validated
def test_cfn_deploy_apigateway_integration(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.key_value("cacheNamespace"))

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/apigateway_integration_no_authorizer.yml"
        ),
        max_wait=120,
    )

    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "stack-name"))

    rest_api_id = stack.outputs["RestApiId"]
    rest_api = aws_client.apigateway.get_rest_api(restApiId=rest_api_id)
    snapshot.match("rest_api", rest_api)
    snapshot.add_transformer(snapshot.transform.key_value("rootResourceId"))

    resource_id = stack.outputs["ResourceId"]
    method = aws_client.apigateway.get_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
    )
    snapshot.match("method", method)
    # TODO: snapshot the authorizer too? it's not attached to the REST API


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$.resources.items..resourceMethods.GET"  # TODO: this is really weird, after importing, AWS returns them empty?
    ]
)
def test_cfn_deploy_apigateway_from_s3_swagger(
    deploy_cfn_template, snapshot, aws_client, s3_bucket
):
    # put the swagger file in S3
    swagger_template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../files/pets.json")
    )
    key_name = "swagger-template-pets.json"
    response = aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body=swagger_template)
    object_etag = response["ETag"]

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/apigateway_integration_from_s3.yml"
        ),
        parameters={
            "S3BodyBucket": s3_bucket,
            "S3BodyKey": key_name,
            "S3BodyETag": object_etag,
        },
        max_wait=120,
    )

    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "stack-name"))

    rest_api_id = stack.outputs["RestApiId"]
    rest_api = aws_client.apigateway.get_rest_api(restApiId=rest_api_id)
    snapshot.match("rest-api", rest_api)

    resources = aws_client.apigateway.get_resources(restApiId=rest_api_id)
    resources["items"] = sorted(resources["items"], key=itemgetter("path"))
    snapshot.match("resources", resources)


@markers.aws.validated
def test_cfn_apigateway_rest_api(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/apigateway.json")
    )

    rs = aws_client.apigateway.get_rest_apis()
    apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
    assert not apis

    stack.destroy()

    stack_2 = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/apigateway.json"),
        parameters={"Create": "True"},
    )
    rs = aws_client.apigateway.get_rest_apis()
    apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
    assert len(apis) == 1

    rs = aws_client.apigateway.get_models(restApiId=apis[0]["id"])
    assert len(rs["items"]) == 3

    stack_2.destroy()

    rs = aws_client.apigateway.get_rest_apis()
    apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
    assert not apis


@markers.aws.validated
def test_account(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/apigateway_account.yml"
        )
    )

    account_info = aws_client.apigateway.get_account()
    assert account_info["cloudwatchRoleArn"] == stack.outputs["RoleArn"]

    # Assert that after deletion of stack, the apigw account is not updated
    stack.destroy()
    aws_client.cloudformation.get_waiter("stack_delete_complete").wait(StackName=stack.stack_name)
    account_info = aws_client.apigateway.get_account()
    assert account_info["cloudwatchRoleArn"] == stack.outputs["RoleArn"]


@markers.aws.validated
def test_update_usage_plan(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("apiId"),
            snapshot.transform.key_value("stage"),
            snapshot.transform.key_value("id"),
            snapshot.transform.key_value("name"),
        ]
    )
    rest_api_name = f"api-{short_uid()}"
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/apigateway_usage_plan.yml"
        ),
        parameters={"QuotaLimit": "5000", "RestApiName": rest_api_name},
    )

    usage_plan = aws_client.apigateway.get_usage_plan(usagePlanId=stack.outputs["UsagePlanId"])
    snapshot.match("usage-plan", usage_plan)
    assert usage_plan["quota"]["limit"] == 5000

    deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        template=load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/apigateway_usage_plan.yml")
        ),
        parameters={"QuotaLimit": "7000", "RestApiName": rest_api_name},
    )

    usage_plan = aws_client.apigateway.get_usage_plan(usagePlanId=stack.outputs["UsagePlanId"])
    snapshot.match("updated-usage-plan", usage_plan)
    assert usage_plan["quota"]["limit"] == 7000


@markers.aws.validated
def test_api_gateway_with_policy_as_dict(deploy_cfn_template, snapshot, aws_client):
    template = """
    Parameters:
      RestApiName:
        Type: String
    Resources:
      MyApi:
        Type: AWS::ApiGateway::RestApi
        Properties:
          Name: !Ref RestApiName
          Policy:
            Version: "2012-10-17"
            Statement:
            - Sid: AllowInvokeAPI
              Action: "*"
              Effect: Allow
              Principal:
                AWS: "*"
              Resource: "*"
    Outputs:
      MyApiId:
        Value: !Ref MyApi
    """

    rest_api_name = f"api-{short_uid()}"
    stack = deploy_cfn_template(
        template=template,
        parameters={"RestApiName": rest_api_name},
    )

    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.regex(stack.stack_name, "stack-name"))

    rest_api = aws_client.apigateway.get_rest_api(restApiId=stack.outputs.get("MyApiId"))

    # note: API Gateway seems to perform double-escaping of the policy document for REST APIs, if specified as dict
    policy = to_bytes(rest_api["policy"]).decode("unicode_escape")
    rest_api["policy"] = json.loads(policy)

    snapshot.match("rest-api", rest_api)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$.put-ssm-param.Tier",
        "$.get-resources.items..resourceMethods.GET",
        "$.get-resources.items..resourceMethods.OPTIONS",
        "$..methodIntegration.cacheNamespace",
        "$.get-authorizers.items..authorizerResultTtlInSeconds",
    ]
)
def test_rest_api_serverless_ref_resolving(
    deploy_cfn_template, snapshot, aws_client, create_parameter, create_lambda_function
):
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformers_list(
        [
            snapshot.transform.resource_name(),
            snapshot.transform.key_value("cacheNamespace"),
            snapshot.transform.key_value("uri"),
            snapshot.transform.key_value("authorizerUri"),
        ]
    )
    create_parameter(Name="/test-stack/testssm/random-value", Value="x-test-header", Type="String")

    fn_name = f"test-{short_uid()}"
    lambda_authorizer = create_lambda_function(
        func_name=fn_name,
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        runtime=Runtime.python3_9,
    )

    create_parameter(
        Name="/test-stack/testssm/lambda-arn",
        Value=lambda_authorizer["CreateFunctionResponse"]["FunctionArn"],
        Type="String",
    )

    stack = deploy_cfn_template(
        template=load_file(
            os.path.join(
                os.path.dirname(__file__),
                "../../../templates/apigateway_serverless_api_resolving.yml",
            )
        ),
        parameters={"AllowedOrigin": "http://localhost:8000"},
    )
    rest_api_id = stack.outputs.get("ApiGatewayApiId")

    resources = aws_client.apigateway.get_resources(restApiId=rest_api_id)
    snapshot.match("get-resources", resources)

    authorizers = aws_client.apigateway.get_authorizers(restApiId=rest_api_id)
    snapshot.match("get-authorizers", authorizers)

    root_resource = resources["items"][0]

    for http_method in root_resource["resourceMethods"]:
        method = aws_client.apigateway.get_method(
            restApiId=rest_api_id, resourceId=root_resource["id"], httpMethod=http_method
        )
        snapshot.match(f"get-method-{http_method}", method)


class TestServerlessApigwLambda:
    @markers.aws.validated
    def test_serverless_like_deployment_with_update(
        self, deploy_cfn_template, aws_client, cleanups
    ):
        """
        Regression test for serverless. Since adding a delete handler for the "AWS::ApiGateway::Deployment" resource,
        the update was failing due to the delete raising an Exception because of a still connected Stage.

        This test recreates a simple recreated deployment procedure as done by "serverless" where
        `serverless deploy` actually both creates a stack and then immediately updates it.
        The second UpdateStack is then caused by another `serverless deploy`, e.g. when changing the lambda configuration
        """

        # 1. deploy create
        template_content = load_file(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/serverless-apigw-lambda.create.json"
            )
        )
        stack_name = f"slsstack-{short_uid()}"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        stack = aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template_content,
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(
            StackName=stack["StackId"]
        )

        # 2. update first
        # get deployed bucket name
        outputs = aws_client.cloudformation.describe_stacks(StackName=stack["StackId"])["Stacks"][
            0
        ]["Outputs"]
        outputs = {k["OutputKey"]: k["OutputValue"] for k in outputs}
        bucket_name = outputs["ServerlessDeploymentBucketName"]

        # upload zip file to s3 bucket
        # "serverless/test-service/local/1708076358388-2024-02-16T09:39:18.388Z/api.zip"
        handler1_filename = os.path.join(os.path.dirname(__file__), "handlers/handler1/api.zip")
        aws_client.s3.upload_file(
            Filename=handler1_filename,
            Bucket=bucket_name,
            Key="serverless/test-service/local/1708076358388-2024-02-16T09:39:18.388Z/api.zip",
        )

        template_content = load_file(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/serverless-apigw-lambda.update.json"
            )
        )
        stack = aws_client.cloudformation.update_stack(
            StackName=stack_name,
            TemplateBody=template_content,
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )
        aws_client.cloudformation.get_waiter("stack_update_complete").wait(
            StackName=stack["StackId"]
        )

        get_fn_1 = aws_client.lambda_.get_function(FunctionName="test-service-local-api")
        assert get_fn_1["Configuration"]["Handler"] == "index.handler"

        # # 3. update second
        # # upload zip file to s3 bucket
        handler2_filename = os.path.join(os.path.dirname(__file__), "handlers/handler2/api.zip")
        aws_client.s3.upload_file(
            Filename=handler2_filename,
            Bucket=bucket_name,
            Key="serverless/test-service/local/1708076568092-2024-02-16T09:42:48.092Z/api.zip",
        )

        template_content = load_file(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/serverless-apigw-lambda.update2.json"
            )
        )
        stack = aws_client.cloudformation.update_stack(
            StackName=stack_name,
            TemplateBody=template_content,
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )
        aws_client.cloudformation.get_waiter("stack_update_complete").wait(
            StackName=stack["StackId"]
        )
        get_fn_2 = aws_client.lambda_.get_function(FunctionName="test-service-local-api")
        assert get_fn_2["Configuration"]["Handler"] == "index.handler2"
