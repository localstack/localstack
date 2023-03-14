import json

import pytest
import requests

from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.utils.aws.arns import parse_arn
from localstack.utils.strings import short_uid
from tests.integration.apigateway_fixtures import api_invoke_url
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_AWS_PROXY


class TestApiGatewayCommon:
    """
    In this class we won't test individual CRUD API calls but how those will affect the integrations and
    requests/responses from the API.
    """

    @pytest.mark.aws_validated
    def test_api_gateway_request_validator(
        self,
        apigateway_client,
        create_lambda_function,
        create_rest_apigw,
        lambda_client,
    ):
        # TODO: create fixture which will provide basic integrations where we can test behaviour
        # see once we have more cases how we can regroup functionality into one or several fixtures
        # example: create a basic echo lambda + integrations + deploy stage

        fn_name = f"test-{short_uid()}"
        create_lambda_function(
            func_name=fn_name,
            handler_file=TEST_LAMBDA_AWS_PROXY,
            runtime=LAMBDA_RUNTIME_PYTHON39,
        )
        lambda_arn = lambda_client.get_function(FunctionName=fn_name)["Configuration"][
            "FunctionArn"
        ]
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

        apigateway_client.put_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            authorizationType="NONE",
            requestValidatorId=validator_id,
            requestParameters={"method.request.path.test": True},
        )

        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            integrationHttpMethod="POST",
            type="AWS_PROXY",
            uri=f"arn:aws:apigateway:{region}:lambda:path//2015-03-31/functions/"
            f"{lambda_arn}/invocations",
        )
        apigateway_client.put_method_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            statusCode="200",
        )
        apigateway_client.put_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            statusCode="200",
        )

        deployment_id = apigateway_client.create_deployment(restApiId=api_id)["id"]

        stage = apigateway_client.create_stage(
            restApiId=api_id, stageName="local", deploymentId=deployment_id
        )["stageName"]

        source_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*/*/test/*"

        lambda_client.add_permission(
            FunctionName=lambda_arn,
            StatementId=str(short_uid()),
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )

        url = api_invoke_url(api_id, stage=stage, path="/test/value")
        response = requests.post(url, json={"test": "test"})
        assert response.ok
        assert json.loads(response.json()["body"]) == {"test": "test"}

        apigateway_client.update_method(
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

        response = requests.post(url, json={"test": "test"})
        assert response.ok
        assert json.loads(response.json()["body"]) == {"test": "test"}

        # create Model schema to validate body
        apigateway_client.create_model(
            restApiId=api_id,
            name="testSchema",
            contentType="application/json",
            schema=json.dumps({}),
        )
        # then attach the schema to the method
        apigateway_client.update_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            patchOperations=[
                {"op": "add", "path": "/requestModels/application~1json", "value": "testSchema"},
            ],
        )
        # the validator should then check against this schema

        apigateway_client.update_method(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            patchOperations=[
                {
                    "op": "replace",
                    "path": "/requestValidatorId",
                    "value": "",
                },
            ],
        )
        response = requests.post(url, json={"test": "test"})
        assert response.ok
        assert json.loads(response.json()["body"]) == {"test": "test"}
