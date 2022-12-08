from localstack.utils.aws.arns import extract_region_from_arn, get_sqs_queue_url
from localstack.utils.aws.aws_stack import connect_to_service
from localstack.utils.strings import to_str


def sqs_receive_message(queue_arn):
    region_name = extract_region_from_arn(queue_arn)
    client = connect_to_service("sqs", region_name=region_name)
    queue_url = get_sqs_queue_url(queue_arn)
    response = client.receive_message(QueueUrl=queue_url)
    return response


def get_apigateway_integration(api_id, method, path, env=None):
    apigateway = connect_to_service(service_name="apigateway", client=True, env=env)

    resources = apigateway.get_resources(restApiId=api_id, limit=100)
    resource_id = None
    for r in resources["items"]:
        if r["path"] == path:
            resource_id = r["id"]
    if not resource_id:
        raise Exception('Unable to find apigateway integration for path "%s"' % path)

    integration = apigateway.get_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=method
    )
    return integration


def get_apigateway_resource_for_path(api_id, path, parent=None, resources=None):
    if resources is None:
        apigateway = connect_to_service(service_name="apigateway")
        resources = apigateway.get_resources(restApiId=api_id, limit=100)
    if not isinstance(path, list):
        path = path.split("/")
    if not path:
        return parent
    for resource in resources:
        if resource["pathPart"] == path[0] and (not parent or parent["id"] == resource["parentId"]):
            return get_apigateway_resource_for_path(
                api_id, path[1:], parent=resource, resources=resources
            )
    return None


def get_apigateway_path_for_resource(
    api_id, resource_id, path_suffix="", resources=None, region_name=None
):
    if resources is None:
        apigateway = connect_to_service(service_name="apigateway", region_name=region_name)
        resources = apigateway.get_resources(restApiId=api_id, limit=100)["items"]
    target_resource = list(filter(lambda res: res["id"] == resource_id, resources))[0]
    path_part = target_resource.get("pathPart", "")
    if path_suffix:
        if path_part:
            path_suffix = "%s/%s" % (path_part, path_suffix)
    else:
        path_suffix = path_part
    parent_id = target_resource.get("parentId")
    if not parent_id:
        return "/%s" % path_suffix
    return get_apigateway_path_for_resource(
        api_id,
        parent_id,
        path_suffix=path_suffix,
        resources=resources,
        region_name=region_name,
    )


def kinesis_get_latest_records(stream_name, shard_id, count=10, env=None, client=None):
    kinesis = client or connect_to_service("kinesis", env=env)
    result = []
    response = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )
    shard_iterator = response["ShardIterator"]
    while shard_iterator:
        records_response = kinesis.get_records(ShardIterator=shard_iterator)
        records = records_response["Records"]
        for record in records:
            try:
                record["Data"] = to_str(record["Data"])
            except Exception:
                pass
        result.extend(records)
        shard_iterator = records_response["NextShardIterator"] if records else False
        while len(result) > count:
            result.pop(0)
    return result
