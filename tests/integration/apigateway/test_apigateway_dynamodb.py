import json

import pytest
from botocore.exceptions import ClientError

from localstack.constants import APPLICATION_JSON
from localstack.utils.http import safe_requests as requests
from localstack.utils.sync import retry
from tests.integration.apigateway.conftest import DEFAULT_STAGE_NAME
from tests.integration.apigateway_fixtures import api_invoke_url, create_rest_api_integration


@pytest.mark.aws_validated
@pytest.mark.parametrize("ddb_action", ["PutItem", "Query", "Scan"])
def test_rest_api_to_dynamodb_integration(
    apigateway_client,
    ddb_action,
    dynamodb_create_table,
    dynamodb_resource,
    create_rest_api_with_integration,
    snapshot,
):
    # create table
    table = dynamodb_create_table()["TableDescription"]
    table_name = table["TableName"]

    # insert items
    dynamodb_table = dynamodb_resource.Table(table_name)
    item_ids = ("test", "test2", "test 3")
    for item_id in item_ids:
        dynamodb_table.put_item(Item={"id": item_id})

    # construct request mapping template
    if ddb_action == "PutItem":
        template = json.dumps(
            {
                "TableName": table_name,
                "Item": {"id": {"S": "$input.params('id')"}},
            }
        )
    elif ddb_action == "Query":
        template = json.dumps(
            {
                "TableName": table_name,
                "KeyConditionExpression": "id = :id",
                "ExpressionAttributeValues": {":id": {"S": "$input.params('id')"}},
            }
        )
    elif ddb_action == "Scan":
        template = json.dumps({"TableName": table_name})
    request_templates = {APPLICATION_JSON: template}

    # deploy REST API with integration
    region_name = apigateway_client.meta.region_name
    integration_uri = f"arn:aws:apigateway:{region_name}:dynamodb:action/{ddb_action}"
    api_id = create_rest_api_with_integration(
        integration_uri=integration_uri,
        req_templates=request_templates,
        integration_type="AWS",
    )

    def _invoke_endpoint(id_param=None):
        url = api_invoke_url(api_id, stage=DEFAULT_STAGE_NAME, path=f"/test?id={id_param}")
        response = requests.post(url)
        assert response.status_code == 200
        return response.json()

    def _invoke_with_retries(id_param=None):
        return retry(lambda: _invoke_endpoint(id_param), retries=15, sleep=2)

    # run assertions

    if ddb_action == "PutItem":
        result = _invoke_with_retries("test-new")
        snapshot.match("result-put-item", result)
        result = dynamodb_table.scan()
        result["Items"] = sorted(result["Items"], key=lambda x: x["id"])
        snapshot.match("result-scan", result)

    elif ddb_action == "Query":
        # retrieve valid item IDs
        for item_id in item_ids:
            result = _invoke_with_retries(item_id)
            snapshot.match(f"result-{item_id}", result)
        # retrieve invalid item ID
        result = _invoke_with_retries("test-invalid")
        snapshot.match("result-invalid", result)

    elif ddb_action == "Scan":
        result = _invoke_with_retries()
        result["Items"] = sorted(result["Items"], key=lambda x: x["id"]["S"])
        snapshot.match("result-scan", result)


@pytest.mark.aws_validated
def test_error_aws_proxy_not_supported(
    apigateway_client,
    create_rest_api_with_integration,
    snapshot,
):
    region_name = apigateway_client.meta.region_name
    integration_uri = f"arn:aws:apigateway:{region_name}:dynamodb:action/Query"

    api_id = create_rest_api_with_integration(
        integration_uri=integration_uri,
        integration_type="AWS",
    )

    # assert error - AWS_PROXY not supported for DDB integrations (AWS parity)
    resources = apigateway_client.get_resources(restApiId=api_id)["items"]
    child_resource = [res for res in resources if res.get("parentId")][0]
    with pytest.raises(ClientError) as exc:
        create_rest_api_integration(
            apigateway_client,
            restApiId=api_id,
            resourceId=child_resource["id"],
            httpMethod="POST",
            integrationHttpMethod="POST",
            type="AWS_PROXY",
            uri=integration_uri,
        )
    snapshot.match("create-integration-error", exc.value.response)
