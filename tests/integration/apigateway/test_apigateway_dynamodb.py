import json

import pytest
from botocore.exceptions import ClientError

from localstack.constants import APPLICATION_JSON
from localstack.utils.http import safe_requests as requests
from localstack.utils.sync import retry
from tests.integration.apigateway.conftest import DEFAULT_STAGE_NAME
from tests.integration.apigateway_fixtures import api_invoke_url, create_rest_api_integration


def test_rest_api_to_dynamodb_integration(
    apigateway_client,
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

    region_name = apigateway_client.meta.region_name
    integration_uri = f"arn:aws:apigateway:{region_name}:dynamodb:action/Query"
    request_templates = {
        APPLICATION_JSON: json.dumps(
            {
                "TableName": table_name,
                "KeyConditionExpression": "id = :id",
                "ExpressionAttributeValues": {":id": {"S": "$input.params('id')"}},
            }
        )
    }
    api_id = create_rest_api_with_integration(
        integration_uri=integration_uri,
        req_templates=request_templates,
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

    def _invoke_endpoint(id_param):
        url = api_invoke_url(api_id, stage=DEFAULT_STAGE_NAME, path=f"/test?id={id_param}")
        response = requests.post(url)
        assert response.status_code == 200
        return response.json()

    # retrieve valid item IDs
    for item_id in item_ids:
        result = retry(lambda: _invoke_endpoint(item_id), retries=15, sleep=1)
        snapshot.match(f"result-{item_id}", result)

    # retrieve invalid item ID
    result = retry(lambda: _invoke_endpoint("test-invalid"), retries=15, sleep=1)
    snapshot.match("result-invalid", result)
