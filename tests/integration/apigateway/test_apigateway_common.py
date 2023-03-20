import json

import pytest
import requests

from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.utils.aws.arns import parse_arn
from localstack.utils.strings import short_uid
from tests.integration.apigateway.apigateway_fixtures import api_invoke_url
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_AWS_PROXY


class TestApiGatewayCommon:
    """
    In this class we won't test individual CRUD API calls but how those will affect the integrations and
    requests/responses from the API.
    """

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$.invalid-request-body.Type",
            "$..methodIntegration.integrationResponses",
            "$..methodIntegration.passthroughBehavior",
            "$..methodIntegration.requestParameters",
            "$..methodIntegration.timeoutInMillis",
        ]
    )
    def test_api_gateway_request_validator(
        self,
        apigateway_client,
        create_lambda_function,
        create_rest_apigw,
        apigw_redeploy_api,
        lambda_client,
        snapshot,
    ):
        # TODO: create fixture which will provide basic integrations where we can test behaviour
        # see once we have more cases how we can regroup functionality into one or several fixtures
        # example: create a basic echo lambda + integrations + deploy stage
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("requestValidatorId"),
                snapshot.transform.key_value("cacheNamespace"),
                snapshot.transform.key_value("id"),  # deployment id
                snapshot.transform.key_value("fn_name"),  # lambda name
                snapshot.transform.key_value("fn_arn"),  # lambda arn
            ]
        )

        fn_name = f"test-{short_uid()}"
        create_lambda_function(
            func_name=fn_name,
            handler_file=TEST_LAMBDA_AWS_PROXY,
            runtime=LAMBDA_RUNTIME_PYTHON39,
        )
        lambda_arn = lambda_client.get_function(FunctionName=fn_name)["Configuration"][
            "FunctionArn"
        ]
        # matching on lambda id for reference replacement in snapshots
        snapshot.match("register-lambda", {"fn_name": fn_name, "fn_arn": lambda_arn})

        parsed_arn = parse_arn(lambda_arn)
        region = parsed_arn["region"]
        account_id = parsed_arn["account"]

        api_id, _, root = create_rest_apigw(name="aws lambda api")

        resource_1 = apigateway_client.create_resource(
            restApiId=api_id, parentId=root, pathPart="test"
        )["id"]

        resource_id = apigateway_client.create_resource(
            restApiId=api_id, parentId=resource_1, pathPart="{test}"
        )["id"]

        validator_id = apigateway_client.create_request_validator(
            restApiId=api_id,
            name="test-validator",
            validateRequestParameters=True,
            validateRequestBody=True,
        )["id"]

        for http_method in ("GET", "POST"):
            apigateway_client.put_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                authorizationType="NONE",
                requestValidatorId=validator_id,
                requestParameters={"method.request.path.test": True},
            )

            apigateway_client.put_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                integrationHttpMethod="POST",
                type="AWS_PROXY",
                uri=f"arn:aws:apigateway:{region}:lambda:path//2015-03-31/functions/"
                f"{lambda_arn}/invocations",
            )
            apigateway_client.put_method_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                statusCode="200",
            )
            apigateway_client.put_integration_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                statusCode="200",
            )

        stage_name = "local"
        deploy_1 = apigateway_client.create_deployment(restApiId=api_id, stageName=stage_name)
        snapshot.match("deploy-1", deploy_1)

        source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/*/test/*"

        lambda_client.add_permission(
            FunctionName=lambda_arn,
            StatementId=str(short_uid()),
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )

        url = api_invoke_url(api_id, stage=stage_name, path="/test/value")
        response = requests.post(url, json={"test": "test"})
        assert response.ok
        assert json.loads(response.json()["body"]) == {"test": "test"}

        # GET request with an empty body
        response_get = requests.get(url)
        assert response_get.ok

        response = apigateway_client.update_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            patchOperations=[
                {
                    "op": "add",
                    "path": "/requestParameters/method.request.path.issuer",
                    "value": "true",
                },
                {
                    "op": "remove",
                    "path": "/requestParameters/method.request.path.test",
                    "value": "true",
                },
            ],
        )
        snapshot.match("change-request-path-names", response)

        apigw_redeploy_api(rest_api_id=api_id, stage_name=stage_name)

        response = requests.post(url, json={"test": "test"})
        # FIXME: for now, not implemented in LocalStack, we don't validate RequestParameters yet
        # assert response.status_code == 400
        if response.status_code == 400:
            snapshot.match("missing-required-request-params", response.json())

        # create Model schema to validate body
        apigateway_client.create_model(
            restApiId=api_id,
            name="testSchema",
            contentType="application/json",
            schema=json.dumps(
                {
                    "title": "testSchema",
                    "type": "object",
                    "properties": {
                        "a": {"type": "number"},
                        "b": {"type": "number"},
                    },
                    "required": ["a", "b"],
                }
            ),
        )
        # then attach the schema to the methods
        for http_method in ("GET", "POST"):
            response = apigateway_client.update_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                patchOperations=[
                    {
                        "op": "add",
                        "path": "/requestModels/application~1json",
                        "value": "testSchema",
                    },
                ],
            )
            snapshot.match(f"add-schema-{http_method}", response)

        # revert the path validation for POST method
        response = apigateway_client.update_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            patchOperations=[
                {
                    "op": "add",
                    "path": "/requestParameters/method.request.path.test",
                    "value": "true",
                },
                {
                    "op": "remove",
                    "path": "/requestParameters/method.request.path.issuer",
                    "value": "true",
                },
            ],
        )
        snapshot.match("revert-request-path-names", response)

        apigw_redeploy_api(rest_api_id=api_id, stage_name=stage_name)

        # the validator should then check against this schema and fail
        response = requests.post(url, json={"test": "test"})
        assert response.status_code == 400
        snapshot.match("invalid-request-body", response.json())

        # GET request with an empty body
        response_get = requests.get(url)
        assert response_get.status_code == 400

        # GET request with an empty body, content type JSON
        response_get = requests.get(url, headers={"Content-Type": "application/json"})
        assert response_get.status_code == 400

        # remove the validator from the methods
        for http_method in ("GET", "POST"):
            response = apigateway_client.update_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                patchOperations=[
                    {
                        "op": "replace",
                        "path": "/requestValidatorId",
                        "value": "",
                    },
                ],
            )
            snapshot.match(f"remove-validator-{http_method}", response)
            print(response)

        apigw_redeploy_api(rest_api_id=api_id, stage_name=stage_name)

        response = requests.post(url, json={"test": "test"})
        assert response.ok
        assert json.loads(response.json()["body"]) == {"test": "test"}

        # GET request with an empty body
        response_get = requests.get(url)
        assert response_get.ok
