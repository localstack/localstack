import contextlib
import json
import textwrap
from urllib.parse import urlparse

import pytest
import requests
from botocore.exceptions import ClientError
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from localstack import config
from localstack.constants import APPLICATION_JSON
from localstack.services.lambda_.networking import get_main_endpoint_from_container
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.fixtures import PUBLIC_HTTP_ECHO_SERVER_URL
from localstack.utils.strings import short_uid, to_bytes
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import (
    api_invoke_url,
    create_rest_api_deployment,
)
from tests.aws.services.apigateway.conftest import DEFAULT_STAGE_NAME
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_LIBS


@pytest.fixture
def status_code_http_server(httpserver: HTTPServer):
    """Spins up a local HTTP echo server and returns the endpoint URL"""
    if is_aws_cloud():
        return f"{PUBLIC_HTTP_ECHO_SERVER_URL}/"

    def _echo(request: Request) -> Response:
        result = {
            "data": request.data or "{}",
            "headers": dict(request.headers),
            "url": request.url,
            "method": request.method,
        }
        status_code = request.url.rpartition("/")[2]
        response_body = json.dumps(result)
        return Response(response_body, status=int(status_code))

    httpserver.expect_request("").respond_with_handler(_echo)
    http_endpoint = httpserver.url_for("/")
    return http_endpoint


@markers.aws.validated
def test_http_integration_status_code_selection(
    create_rest_apigw, aws_client, status_code_http_server
):
    api_id, _, root_id = create_rest_apigw(name="my_api", description="this is my api")

    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="{status}"
    )["id"]

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="none",
        requestParameters={"method.request.path.status": True},
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="HTTP",
        uri=f"{status_code_http_server}status/{{status}}",
        requestParameters={"integration.request.path.status": "method.request.path.status"},
        integrationHttpMethod="GET",
    )

    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=resource_id, statusCode="200", httpMethod="GET"
    )
    aws_client.apigateway.put_integration_response(
        restApiId=api_id, resourceId=resource_id, statusCode="200", httpMethod="GET"
    )
    # forward 4xx errors to 400, so the assertions of the test fixtures hold
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=resource_id, statusCode="400", httpMethod="GET"
    )
    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        statusCode="400",
        httpMethod="GET",
        selectionPattern=r"4\d{2}",
    )

    stage_name = "test"
    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

    invocation_url = api_invoke_url(
        api_id=api_id,
        stage=stage_name,
        path="/",
    )

    def invoke_api(url, requested_response_code: int, expected_response_code: int):
        apigw_response = requests.get(
            f"{url}{requested_response_code}",
            headers={"User-Agent": "python-requests/testing"},
            verify=False,
        )
        assert expected_response_code == apigw_response.status_code
        return apigw_response

    # retry is necessary against AWS
    retry(
        invoke_api,
        sleep=2,
        retries=10,
        url=invocation_url,
        expected_response_code=400,
        requested_response_code=404,
    )
    retry(
        invoke_api,
        sleep=2,
        retries=10,
        url=invocation_url,
        expected_response_code=200,
        requested_response_code=201,
    )


@markers.aws.validated
def test_put_integration_responses(create_rest_apigw, aws_client, echo_http_server_post, snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("cacheNamespace"),
            snapshot.transform.key_value("uri"),
            snapshot.transform.key_value("id"),
        ]
    )
    api_id, _, root_id = create_rest_apigw(name="my_api", description="this is my api")

    response = aws_client.apigateway.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    snapshot.match("put-method-get", response)

    response = aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    snapshot.match("put-method-response-get", response)

    response = aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP",
        uri=echo_http_server_post,
        integrationHttpMethod="POST",
    )
    snapshot.match("put-integration-get", response)

    response = aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="2\\d{2}",
        responseTemplates={},
    )
    snapshot.match("put-integration-response-get", response)

    response = aws_client.apigateway.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    snapshot.match("get-integration-response-get", response)

    response = aws_client.apigateway.get_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET"
    )
    snapshot.match("get-method-get", response)

    stage_name = "local"
    response = aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)
    snapshot.match("deploy", response)

    url = api_invoke_url(api_id, stage=stage_name, path="/")
    response = requests.get(url)
    assert response.ok

    response = aws_client.apigateway.delete_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    snapshot.match("delete-integration-response-get", response)

    response = aws_client.apigateway.get_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET"
    )
    snapshot.match("get-method-get-after-int-resp-delete", response)

    # adding a new method and performing put integration with contentHandling as CONVERT_TO_BINARY
    response = aws_client.apigateway.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="PUT", authorizationType="none"
    )
    snapshot.match("put-method-put", response)

    response = aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="PUT", statusCode="200"
    )
    snapshot.match("put-method-response-put", response)

    response = aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="PUT",
        type="HTTP",
        uri=echo_http_server_post,
        integrationHttpMethod="POST",
    )
    snapshot.match("put-integration-put", response)

    response = aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="PUT",
        statusCode="200",
        selectionPattern="2\\d{2}",
        contentHandling="CONVERT_TO_BINARY",
    )
    snapshot.match("put-integration-response-put", response)

    response = aws_client.apigateway.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="PUT", statusCode="200"
    )
    snapshot.match("get-integration-response-put", response)


@markers.aws.validated
def test_put_integration_response_with_response_template(
    aws_client, create_rest_apigw, create_echo_http_server, snapshot
):
    echo_server_url = create_echo_http_server(trim_x_headers=True)
    api_id, _, root_id = create_rest_apigw(name="test-apigw")

    aws_client.apigateway.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP",
        uri=echo_server_url,
        integrationHttpMethod="POST",
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="foobar",
        responseTemplates={"application/json": json.dumps({"data": "test"})},
    )

    response = aws_client.apigateway.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    snapshot.match("get-integration-response", response)


# TODO: Aws does not return the uri when creating a MOCK integration
@markers.snapshot.skip_snapshot_verify(paths=["$..not-required-integration-method-MOCK.uri"])
@markers.aws.validated
def test_put_integration_validation(
    aws_client, account_id, region_name, create_rest_apigw, snapshot, partition
):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("cacheNamespace"),
        ]
    )

    api_id, _, root_id = create_rest_apigw(name="test-apigw")

    aws_client.apigateway.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    aws_client.apigateway.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    http_types = ["HTTP", "HTTP_PROXY"]
    aws_types = ["AWS", "AWS_PROXY"]
    types_requiring_integration_method = http_types + ["AWS"]
    types_not_requiring_integration_method = ["MOCK"]

    for _type in types_requiring_integration_method:
        # Ensure that integrations of these types fail if no integrationHttpMethod is provided
        with pytest.raises(ClientError) as ex:
            aws_client.apigateway.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                type=_type,
                uri="http://example.com",
            )
        snapshot.match(f"required-integration-method-{_type}", ex.value.response)

    for _type in types_not_requiring_integration_method:
        # Ensure that integrations of these types do not need the integrationHttpMethod
        response = aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type=_type,
            uri="http://example.com",
        )
        snapshot.match(f"not-required-integration-method-{_type}", response)

    for _type in http_types:
        # Ensure that it works fine when providing the integrationHttpMethod-argument
        response = aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type=_type,
            uri="http://example.com",
            integrationHttpMethod="POST",
        )
        snapshot.match(f"http-method-{_type}", response)

    for _type in ["AWS"]:
        # Ensure that it works fine when providing the integrationHttpMethod + credentials
        response = aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            credentials=f"arn:{partition}:iam::{account_id}:role/service-role/testfunction-role-oe783psq",
            httpMethod="GET",
            type=_type,
            uri=f"arn:{partition}:apigateway:{region_name}:s3:path/b/k",
            integrationHttpMethod="POST",
        )
        snapshot.match(f"aws-integration-{_type}", response)

    for _type in aws_types:
        # Ensure that credentials are not required when URI points to a Lambda stream
        response = aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type=_type,
            uri=f"arn:{partition}:apigateway:{region_name}:lambda:path/2015-03-31/functions/arn:{partition}:lambda:{region_name}:{account_id}:function:MyLambda/invocations",
            integrationHttpMethod="POST",
        )
        snapshot.match(f"aws-integration-type-{_type}", response)

    for _type in ["AWS_PROXY"]:
        # Ensure that aws_proxy does not support S3
        with pytest.raises(ClientError) as ex:
            aws_client.apigateway.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                credentials=f"arn:{partition}:iam::{account_id}:role/service-role/testfunction-role-oe783psq",
                httpMethod="GET",
                type=_type,
                uri=f"arn:{partition}:apigateway:{region_name}:s3:path/b/k",
                integrationHttpMethod="POST",
            )
        snapshot.match(f"no-s3-support-{_type}", ex.value.response)

    for _type in http_types:
        # Ensure that the URI is valid HTTP
        with pytest.raises(ClientError) as ex:
            aws_client.apigateway.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                type=_type,
                uri="non-valid-http",
                integrationHttpMethod="POST",
            )
        snapshot.match(f"invalid-uri-{_type}", ex.value.response)

    # Ensure that the URI is an ARN
    with pytest.raises(ClientError) as ex:
        aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type="AWS",
            uri="non-valid-arn",
            integrationHttpMethod="POST",
        )
    snapshot.match("invalid-uri-not-an-arn", ex.value.response)

    # Ensure that the URI is a valid ARN
    with pytest.raises(ClientError) as ex:
        aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type="AWS",
            uri=f"arn:{partition}:iam::0000000000:role/service-role/asdf",
            integrationHttpMethod="POST",
        )
    snapshot.match("invalid-uri-invalid-arn", ex.value.response)


@pytest.fixture
def default_vpc(aws_client):
    vpcs = aws_client.ec2.describe_vpcs()
    for vpc in vpcs["Vpcs"]:
        if vpc.get("IsDefault"):
            return vpc
    raise Exception("Default VPC not found")


@pytest.fixture
def create_vpc_endpoint(default_vpc, aws_client):
    endpoints = []

    def _create(**kwargs):
        kwargs.setdefault("VpcId", default_vpc["VpcId"])
        result = aws_client.ec2.create_vpc_endpoint(**kwargs)
        endpoints.append(result["VpcEndpoint"]["VpcEndpointId"])
        return result["VpcEndpoint"]

    yield _create

    for endpoint in endpoints:
        with contextlib.suppress(Exception):
            aws_client.ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint])


@markers.snapshot.skip_snapshot_verify(
    paths=["$..endpointConfiguration.types", "$..policy.Statement..Resource"]
)
@markers.aws.validated
def test_create_execute_api_vpc_endpoint(
    create_rest_api_with_integration,
    dynamodb_create_table,
    create_vpc_endpoint,
    default_vpc,
    create_lambda_function,
    ec2_create_security_group,
    snapshot,
    aws_client,
):
    poll_sleep = 5 if is_aws_cloud() else 1
    # TODO: create a re-usable ec2_api() transformer
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("DnsName"),
            snapshot.transform.key_value("GroupId"),
            snapshot.transform.key_value("GroupName"),
            snapshot.transform.key_value("SubnetIds"),
            snapshot.transform.key_value("VpcId"),
            snapshot.transform.key_value("VpcEndpointId"),
            snapshot.transform.key_value("HostedZoneId"),
            *snapshot.transform.apigateway_api(),
        ]
    )

    # create table
    table = dynamodb_create_table()["TableDescription"]
    table_name = table["TableName"]

    # insert items
    item_ids = ("test", "test2", "test 3")
    for item_id in item_ids:
        aws_client.dynamodb.put_item(TableName=table_name, Item={"id": {"S": item_id}})

    # construct request mapping template
    request_templates = {APPLICATION_JSON: json.dumps({"TableName": table_name})}

    # deploy REST API with integration
    region_name = aws_client.apigateway.meta.region_name
    integration_uri = f"arn:aws:apigateway:{region_name}:dynamodb:action/Scan"
    api_id = create_rest_api_with_integration(
        integration_uri=integration_uri,
        req_templates=request_templates,
        integration_type="AWS",
    )

    # get service names
    service_name = f"com.amazonaws.{region_name}.execute-api"
    service_names = aws_client.ec2.describe_vpc_endpoint_services()["ServiceNames"]
    assert service_name in service_names

    # create security group
    vpc_id = default_vpc["VpcId"]
    security_group = ec2_create_security_group(
        VpcId=vpc_id, Description="Test SG for API GW", ports=[443]
    )
    security_group = security_group["GroupId"]
    subnets = aws_client.ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    subnets = [sub["SubnetId"] for sub in subnets["Subnets"]]

    # get or create execute-api VPC endpoint
    endpoints = aws_client.ec2.describe_vpc_endpoints(MaxResults=1000)["VpcEndpoints"]
    matching = [ep for ep in endpoints if ep["ServiceName"] == service_name]
    if matching:
        endpoint_id = matching[0]["VpcEndpointId"]
    else:
        result = create_vpc_endpoint(
            ServiceName=service_name,
            VpcEndpointType="Interface",
            SubnetIds=subnets,
            SecurityGroupIds=[security_group],
        )
        endpoint_id = result["VpcEndpointId"]

    # wait until VPC endpoint is in state "available"
    def _check_available():
        result = aws_client.ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
        endpoint_details = result["VpcEndpoints"][0]
        # may have multiple entries in AWS
        endpoint_details["DnsEntries"] = endpoint_details["DnsEntries"][:1]
        endpoint_details.pop("SubnetIds", None)
        endpoint_details.pop("NetworkInterfaceIds", None)
        assert endpoint_details["State"] == "available"
        snapshot.match("endpoint-details", endpoint_details)

    retry(_check_available, retries=30, sleep=poll_sleep)

    # update API with VPC endpoint
    patches = [
        {"op": "replace", "path": "/endpointConfiguration/types/EDGE", "value": "PRIVATE"},
        {"op": "add", "path": "/endpointConfiguration/vpcEndpointIds", "value": endpoint_id},
    ]
    aws_client.apigateway.update_rest_api(restApiId=api_id, patchOperations=patches)

    # create Lambda that invokes API via VPC endpoint (required as the endpoint is only accessible within the VPC)
    subdomain = f"{api_id}-{endpoint_id}"
    endpoint = api_invoke_url(subdomain, stage=DEFAULT_STAGE_NAME, path="/test")
    host_header = urlparse(endpoint).netloc

    # create Lambda function that invokes the API GW (private VPC endpoint not accessible from outside of AWS)
    if not is_aws_cloud():
        api_host = get_main_endpoint_from_container()
        endpoint = endpoint.replace(host_header, f"{api_host}:{config.GATEWAY_LISTEN[0].port}")
    lambda_code = textwrap.dedent(
        f"""
    def handler(event, context):
        import requests
        headers = {{"content-type": "application/json", "host": "{host_header}"}}
        result = requests.post("{endpoint}", headers=headers)
        return {{"content": result.content.decode("utf-8"), "code": result.status_code}}
    """
    )
    func_name = f"test-{short_uid()}"
    vpc_config = {
        "SubnetIds": subnets,
        "SecurityGroupIds": [security_group],
    }
    create_lambda_function(
        func_name=func_name,
        handler_file=lambda_code,
        libs=TEST_LAMBDA_LIBS,
        timeout=10,
        VpcConfig=vpc_config,
    )

    # create resource policy
    statement = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "execute-api:Invoke",
                "Resource": ["execute-api:/*"],
            }
        ],
    }
    patches = [{"op": "replace", "path": "/policy", "value": json.dumps(statement)}]
    result = aws_client.apigateway.update_rest_api(restApiId=api_id, patchOperations=patches)
    result["policy"] = json.loads(to_bytes(result["policy"]).decode("unicode_escape"))
    snapshot.match("api-details", result)

    # re-deploy API
    create_rest_api_deployment(
        aws_client.apigateway, restApiId=api_id, stageName=DEFAULT_STAGE_NAME
    )

    def _invoke_api():
        invoke_response = aws_client.lambda_.invoke(FunctionName=func_name, Payload="{}")
        payload = json.load(invoke_response["Payload"])
        items = json.loads(payload["content"])["Items"]
        assert len(items) == len(item_ids)

    # invoke Lambda and assert result
    retry(_invoke_api, retries=15, sleep=poll_sleep)


# TODO - remove the code below?
#
# def test_aws_integration_dynamodb(apigateway_client):
#     if settings.TEST_SERVER_MODE:
#         raise SkipTest("Cannot test mock of execute-api.apigateway in ServerMode")
#
#     client = boto3.client("apigateway", region_name="us-west-2")
#     dynamodb = boto3.client("dynamodb", region_name="us-west-2")
#     table_name = "test_1"
#     integration_action = "arn:aws:apigateway:us-west-2:dynamodb:action/PutItem"
#     stage_name = "staging"
#
#     create_table(dynamodb, table_name)
#     api_id, _ = create_integration_test_api(client, integration_action)
#
#     client.create_deployment(restApiId=api_id, stageName=stage_name)
#
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/{stage_name}",
#         json={"TableName": table_name, "Item": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(200)
#     res.content.should.equal(b"{}")
#
#
# def test_aws_integration_dynamodb_multiple_stages(apigateway_client):
#     if settings.TEST_SERVER_MODE:
#         raise SkipTest("Cannot test mock of execute-api.apigateway in ServerMode")
#
#     client = boto3.client("apigateway", region_name="us-west-2")
#     dynamodb = boto3.client("dynamodb", region_name="us-west-2")
#     table_name = "test_1"
#     integration_action = "arn:aws:apigateway:us-west-2:dynamodb:action/PutItem"
#
#     create_table(dynamodb, table_name)
#     api_id, _ = create_integration_test_api(client, integration_action)
#
#     client.create_deployment(restApiId=api_id, stageName="dev")
#     client.create_deployment(restApiId=api_id, stageName="staging")
#
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/dev",
#         json={"TableName": table_name, "Item": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(200)
#
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/staging",
#         json={"TableName": table_name, "Item": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(200)
#
#     # We haven't pushed to prod yet
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/prod",
#         json={"TableName": table_name, "Item": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(400)
#
#
# @mock_apigateway
# @mock_dynamodb
# def test_aws_integration_dynamodb_multiple_resources():
#     if settings.TEST_SERVER_MODE:
#         raise SkipTest("Cannot test mock of execute-api.apigateway in ServerMode")
#
#     client = boto3.client("apigateway", region_name="us-west-2")
#     dynamodb = boto3.client("dynamodb", region_name="us-west-2")
#     table_name = "test_1"
#     create_table(dynamodb, table_name)
#
#     # Create API integration to PutItem
#     integration_action = "arn:aws:apigateway:us-west-2:dynamodb:action/PutItem"
#     api_id, root_id = create_integration_test_api(client, integration_action)
#
#     # Create API integration to GetItem
#     res = client.create_resource(restApiId=api_id, parentId=root_id, pathPart="item")
#     parent_id = res["id"]
#     integration_action = "arn:aws:apigateway:us-west-2:dynamodb:action/GetItem"
#     api_id, root_id = create_integration_test_api(
#         client,
#         integration_action,
#         api_id=api_id,
#         parent_id=parent_id,
#         http_method="GET",
#     )
#
#     client.create_deployment(restApiId=api_id, stageName="dev")
#
#     # Put item at the root resource
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/dev",
#         json={
#             "TableName": table_name,
#             "Item": {"name": {"S": "the-key"}, "attr2": {"S": "sth"}},
#         },
#     )
#     res.status_code.should.equal(200)
#
#     # Get item from child resource
#     res = requests.get(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/dev/item",
#         json={"TableName": table_name, "Key": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(200)
#     json.loads(res.content).should.equal(
#         {"Item": {"name": {"S": "the-key"}, "attr2": {"S": "sth"}}}
#     )
#
#
# def create_table(dynamodb, table_name):
#     # Create DynamoDB table
#     dynamodb.create_table(
#         TableName=table_name,
#         KeySchema=[{"AttributeName": "name", "KeyType": "HASH"}],
#         AttributeDefinitions=[{"AttributeName": "name", "AttributeType": "S"}],
#         BillingMode="PAY_PER_REQUEST",
#     )
#
#
# def create_integration_test_api(
#     client, integration_action, api_id=None, parent_id=None, http_method="PUT"
# ):
#     if not api_id:
#         # We do not have a root yet - create the API first
#         response = client.create_rest_api(name="my_api", description="this is my api")
#         api_id = response["id"]
#     if not parent_id:
#         resources = client.get_resources(restApiId=api_id)
#         parent_id = [
#             resource for resource in resources["items"] if resource["path"] == "/"
#         ][0]["id"]
#
#     client.put_method(
#         restApiId=api_id,
#         resourceId=parent_id,
#         httpMethod=http_method,
#         authorizationType="NONE",
#     )
#     client.put_method_response(
#         restApiId=api_id, resourceId=parent_id, httpMethod=http_method, statusCode="200"
#     )
#     client.put_integration(
#         restApiId=api_id,
#         resourceId=parent_id,
#         httpMethod=http_method,
#         type="AWS",
#         uri=integration_action,
#         integrationHttpMethod=http_method,
#     )
#     client.put_integration_response(
#         restApiId=api_id,
#         resourceId=parent_id,
#         httpMethod=http_method,
#         statusCode="200",
#         selectionPattern="",
#         responseTemplates={"application/json": "{}"},
#     )
#     return api_id, parent_id
