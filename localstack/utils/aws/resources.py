from localstack.aws.connect import connect_to
from localstack.constants import AWS_REGION_US_EAST_1
from localstack.utils.aws.aws_models import KinesisStream
from localstack.utils.aws.aws_stack import LOG, connect_to_resource
from localstack.utils.functions import run_safe
from localstack.utils.sync import poll_condition


def create_sqs_queue(queue_name):
    return connect_to().sqs.create_queue(QueueName=queue_name)


def get_or_create_bucket(bucket_name: str, s3_client=None):
    s3_client = s3_client or connect_to().s3
    try:
        return s3_client.head_bucket(Bucket=bucket_name)
    except Exception:
        return create_s3_bucket(bucket_name, s3_client=s3_client)


def create_s3_bucket(bucket_name: str, s3_client=None):
    """Creates a bucket in the region that is associated with the current request
    context, or with the given boto3 S3 client, if specified."""
    s3_client = s3_client or connect_to().s3
    region = s3_client.meta.region_name
    kwargs = {}
    if region != AWS_REGION_US_EAST_1:
        kwargs = {"CreateBucketConfiguration": {"LocationConstraint": region}}
    return s3_client.create_bucket(Bucket=bucket_name, **kwargs)


def create_dynamodb_table(
    table_name: str,
    partition_key: str,
    stream_view_type: str = None,
    region_name: str = None,
    client=None,
    wait_for_active: bool = True,
):
    """Utility method to create a DynamoDB table"""

    dynamodb = client or connect_to(region_name=region_name).dynamodb
    stream_spec = {"StreamEnabled": False}
    key_schema = [{"AttributeName": partition_key, "KeyType": "HASH"}]
    attr_defs = [{"AttributeName": partition_key, "AttributeType": "S"}]
    if stream_view_type is not None:
        stream_spec = {"StreamEnabled": True, "StreamViewType": stream_view_type}
    table = None
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            AttributeDefinitions=attr_defs,
            BillingMode="PAY_PER_REQUEST",
            StreamSpecification=stream_spec,
        )
    except Exception as e:
        if "ResourceInUseException" in str(e):
            # Table already exists -> return table reference
            return connect_to_resource("dynamodb", region_name=region_name).Table(table_name)
        if "AccessDeniedException" in str(e):
            raise

    def _is_active():
        return dynamodb.describe_table(TableName=table_name)["Table"]["TableStatus"] == "ACTIVE"

    if wait_for_active:
        poll_condition(_is_active)

    return table


def create_api_gateway(
    name,
    description=None,
    resources=None,
    stage_name=None,
    enabled_api_keys=None,
    usage_plan_name=None,
    region_name=None,
    auth_creator_func=None,  # function that receives an api_id and returns an authorizer_id
    client=None,
):
    if enabled_api_keys is None:
        enabled_api_keys = []
    if not client:
        client = connect_to(region_name=region_name).apigateway
    resources = resources or []
    stage_name = stage_name or "testing"
    usage_plan_name = usage_plan_name or "Basic Usage"
    description = description or 'Test description for API "%s"' % name

    LOG.info('Creating API resources under API Gateway "%s".', name)
    api = client.create_rest_api(name=name, description=description)
    api_id = api["id"]

    auth_id = None
    if auth_creator_func:
        auth_id = auth_creator_func(api_id)

    resources_list = client.get_resources(restApiId=api_id)
    root_res_id = resources_list["items"][0]["id"]
    # add API resources and methods
    for path, methods in resources.items():
        # create resources recursively
        parent_id = root_res_id
        for path_part in path.split("/"):
            api_resource = client.create_resource(
                restApiId=api_id, parentId=parent_id, pathPart=path_part
            )
            parent_id = api_resource["id"]
        # add methods to the API resource
        for method in methods:
            kwargs = {"authorizerId": auth_id} if auth_id else {}
            client.put_method(
                restApiId=api_id,
                resourceId=api_resource["id"],
                httpMethod=method["httpMethod"],
                authorizationType=method.get("authorizationType") or "NONE",
                apiKeyRequired=method.get("apiKeyRequired") or False,
                requestParameters=method.get("requestParameters") or {},
                requestModels=method.get("requestModels") or {},
                **kwargs,
            )
            # create integrations for this API resource/method
            integrations = method["integrations"]
            create_api_gateway_integrations(
                api_id,
                api_resource["id"],
                method,
                integrations,
                region_name=region_name,
                client=client,
            )
    # deploy the API gateway
    client.create_deployment(restApiId=api_id, stageName=stage_name)
    return api


def create_api_gateway_integrations(
    api_id, resource_id, method, integrations=None, region_name=None, client=None
):
    if integrations is None:
        integrations = []
    if not client:
        client = connect_to(region_name=region_name).apigateway
    for integration in integrations:
        req_templates = integration.get("requestTemplates") or {}
        res_templates = integration.get("responseTemplates") or {}
        success_code = integration.get("successCode") or "200"
        client_error_code = integration.get("clientErrorCode") or "400"
        server_error_code = integration.get("serverErrorCode") or "500"
        request_parameters = integration.get("requestParameters") or {}
        # create integration
        client.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=method["httpMethod"],
            integrationHttpMethod=method.get("integrationHttpMethod") or method["httpMethod"],
            type=integration["type"],
            uri=integration["uri"],
            requestTemplates=req_templates,
            requestParameters=request_parameters,
        )
        response_configs = [
            {"pattern": "^2.*", "code": success_code, "res_templates": res_templates},
            {"pattern": "^4.*", "code": client_error_code, "res_templates": {}},
            {"pattern": "^5.*", "code": server_error_code, "res_templates": {}},
        ]
        # create response configs
        for response_config in response_configs:
            # create integration response
            client.put_integration_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=method["httpMethod"],
                statusCode=response_config["code"],
                responseTemplates=response_config["res_templates"],
                selectionPattern=response_config["pattern"],
            )
            # create method response
            client.put_method_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=method["httpMethod"],
                statusCode=response_config["code"],
            )


def create_kinesis_stream(stream_name, shards=1, delete=False):
    stream = KinesisStream(id=stream_name, num_shards=shards)
    conn = connect_to().kinesis
    stream.connect(conn)
    if delete:
        run_safe(lambda: stream.destroy(), print_error=False)
    stream.create()
    # Note: Returning the stream without awaiting its creation (via wait_for()) to avoid API call timeouts/retries.
    return stream
