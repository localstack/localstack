import json

import pytest
import requests

from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.integration.apigateway.apigateway_fixtures import (
    api_invoke_url,
    create_rest_api_deployment,
    create_rest_api_integration,
    create_rest_api_integration_response,
    create_rest_api_method_response,
    create_rest_resource,
    create_rest_resource_method,
)
from tests.integration.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY


@pytest.mark.aws_validated
def test_apigateway_to_eventbridge(
    aws_client, create_rest_apigw, create_role_with_policy, region, account_id, snapshot
):
    api_id, _, root = create_rest_apigw(name=f"{short_uid()}-eventbridge")

    resource_id, _ = create_rest_resource(
        aws_client.apigateway, restApiId=api_id, parentId=root, pathPart="event"
    )

    create_rest_resource_method(
        aws_client.apigateway,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
        requestParameters={
            "method.request.header.X-Amz-Target": False,
            "method.request.header.Content-Type": False,
        },
    )

    _, role_arn = create_role_with_policy(
        "Allow", "events:PutEvents", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    create_rest_api_integration(
        aws_client.apigateway,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        integrationHttpMethod="POST",
        type="AWS",
        uri=f"arn:aws:apigateway:{region}:events:action/PutEvents",
        passthroughBehavior="WHEN_NO_TEMPLATES",
        credentials=role_arn,
        requestParameters={},
        requestTemplates={
            "application/json": """
              #set($context.requestOverride.header.X-Amz-Target = "AWSEvents.PutEvents")
              #set($context.requestOverride.header.Content-Type = "application/x-amz-json-1.1")
              #set($inputRoot = $input.path('$'))
              {
                "Entries": [
                  #foreach($elem in $inputRoot.items)
                  {
                    "Detail": "$util.escapeJavaScript($elem.Detail).replaceAll("\\'","'")",
                    "DetailType": "$elem.DetailType",
                    "Source":"$elem.Source"
                  }#if($foreach.hasNext),#end
                  #end
                ]
              }
            """
        },
    )

    create_rest_api_method_response(
        aws_client.apigateway,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        responseModels={"application/json": "Empty"},
        responseParameters={},
    )

    create_rest_api_integration_response(
        aws_client.apigateway,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        responseTemplates={"application/json": "#set($inputRoot = $input.json('$'))\n$inputRoot"},
    )

    create_rest_api_deployment(aws_client.apigateway, restApiId=api_id, stageName="dev")

    # invoke rest api
    invocation_url = api_invoke_url(
        api_id=api_id,
        stage="dev",
        path="/event",
    )

    def invoke_api(url):
        response = requests.post(
            url,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            data=json.dumps(
                {
                    "items": [
                        {
                            "Detail": '{"data":"Order is created"}',
                            "DetailType": "Test",
                            "Source": "order",
                        }
                    ]
                }
            ),
            verify=False,
        )
        assert 200 == response.status_code
        return response

    # retry is necessary against AWS, probably IAM permission delay
    response = retry(invoke_api, sleep=1, retries=10, url=invocation_url)
    assert response.ok
    snapshot.match("eventbridge-put-events-response", response.json())
