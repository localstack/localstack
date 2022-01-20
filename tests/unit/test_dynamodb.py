from localstack.services.dynamodb.dynamodb_listener import ProxyListenerDynamoDB
from localstack.utils.aws import aws_stack


def test_fix_region_in_headers():
    # the NoSQL Workbench sends "localhost" or "local" as the region name
    # TODO: this may need to be updated once we migrate DynamoDB to ASF

    for region_name in ["local", "localhost"]:
        headers = aws_stack.mock_aws_request_headers("dynamodb", region_name=region_name)
        assert aws_stack.get_region() not in headers.get("Authorization")
        ProxyListenerDynamoDB.prepare_request_headers(headers)
        assert aws_stack.get_region() in headers.get("Authorization")
