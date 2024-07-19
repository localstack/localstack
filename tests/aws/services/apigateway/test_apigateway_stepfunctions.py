import json

import pytest
import requests

from localstack.aws.api.lambda_ import Runtime
from localstack.constants import (
    APPLICATION_JSON,
)
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import (
    api_invoke_url,
    create_rest_api_method_response,
)
from tests.aws.services.apigateway.conftest import (
    APIGATEWAY_ASSUME_ROLE_POLICY,
    APIGATEWAY_LAMBDA_POLICY,
    APIGATEWAY_STEPFUNCTIONS_POLICY,
    STEPFUNCTIONS_ASSUME_ROLE_POLICY,
)
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON_ECHO


class TestApigatewayStepfunctions:
    @markers.aws.validated
    @pytest.mark.parametrize("action", ["StartExecution", "DeleteStateMachine"])
    def test_apigateway_with_step_function_integration(
        self,
        action,
        create_lambda_function,
        create_rest_apigw,
        create_iam_role_with_policy,
        aws_client,
        account_id,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("executionArn", "executionArn"))
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                jsonpath="$..startDate",
                value_replacement="<startDate>",
                reference_replacement=False,
            )
        )

        region_name = aws_client.apigateway._client_config.region_name

        # create lambda
        fn_name = f"lambda-sfn-apigw-{short_uid()}"
        lambda_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=fn_name,
            runtime=Runtime.python3_9,
        )["CreateFunctionResponse"]["FunctionArn"]

        # create state machine and permissions for step function to invoke lambda
        role_arn = create_iam_role_with_policy(
            RoleName=f"sfn_role-{short_uid()}",
            PolicyName=f"sfn-role-policy-{short_uid()}",
            RoleDefinition=STEPFUNCTIONS_ASSUME_ROLE_POLICY,
            PolicyDefinition=APIGATEWAY_LAMBDA_POLICY,
        )

        state_machine_name = f"test-{short_uid()}"
        state_machine_def = {
            "Comment": "Hello World example",
            "StartAt": "step1",
            "States": {
                "step1": {"Type": "Task", "Resource": "__tbd__", "End": True},
            },
        }
        state_machine_def["States"]["step1"]["Resource"] = lambda_arn
        result = aws_client.stepfunctions.create_state_machine(
            name=state_machine_name,
            definition=json.dumps(state_machine_def),
            roleArn=role_arn,
            type="EXPRESS",
        )
        sm_arn = result["stateMachineArn"]

        # create REST API with integrations
        rest_api, _, root_id = create_rest_apigw(
            name=f"test-{short_uid()}", description="test-step-function-integration"
        )
        aws_client.apigateway.put_method(
            restApiId=rest_api,
            resourceId=root_id,
            httpMethod="POST",
            authorizationType="NONE",
        )
        create_rest_api_method_response(
            aws_client.apigateway,
            restApiId=rest_api,
            resourceId=root_id,
            httpMethod="POST",
            statusCode="200",
        )

        # give permission to api gateway to invoke step function
        uri = f"arn:aws:apigateway:{region_name}:states:action/{action}"
        assume_role_arn = create_iam_role_with_policy(
            RoleName=f"role-apigw-{short_uid()}",
            PolicyName=f"policy-apigw-{short_uid()}",
            RoleDefinition=APIGATEWAY_ASSUME_ROLE_POLICY,
            PolicyDefinition=APIGATEWAY_STEPFUNCTIONS_POLICY,
        )

        def _prepare_integration(request_template=None, response_template=None):
            aws_client.apigateway.put_integration(
                restApiId=rest_api,
                resourceId=root_id,
                httpMethod="POST",
                integrationHttpMethod="POST",
                type="AWS",
                uri=uri,
                credentials=assume_role_arn,
                requestTemplates=request_template,
            )

            aws_client.apigateway.put_integration_response(
                restApiId=rest_api,
                resourceId=root_id,
                selectionPattern="",
                responseTemplates=response_template,
                httpMethod="POST",
                statusCode="200",
            )

        test_data = {"test": "test-value"}
        url = api_invoke_url(api_id=rest_api, stage="dev", path="/")

        req_template = {
            "application/json": """
            {
            "input": "$util.escapeJavaScript($input.json('$'))",
            "stateMachineArn": "%s"
            }
            """
            % sm_arn
        }
        match action:
            case "StartExecution":
                _prepare_integration(req_template, response_template={})
                aws_client.apigateway.create_deployment(restApiId=rest_api, stageName="dev")

                # invoke stepfunction via API GW, assert results
                def _invoke_start_step_function():
                    resp = requests.post(url, data=json.dumps(test_data))
                    assert resp.ok
                    content = json.loads(resp.content)
                    assert "executionArn" in content
                    assert "startDate" in content
                    return content

                body = retry(_invoke_start_step_function, retries=15, sleep=0.8)
                snapshot.match("start_execution_response", body)

            case "StartSyncExecution":
                resp_template = {APPLICATION_JSON: "$input.path('$.output')"}
                _prepare_integration(req_template, resp_template)
                aws_client.apigateway.create_deployment(restApiId=rest_api, stageName="dev")
                input_data = {"input": json.dumps(test_data), "name": "MyExecution"}

                def _invoke_start_sync_step_function():
                    input_data["name"] += "1"
                    resp = requests.post(url, data=json.dumps(input_data))
                    assert resp.ok
                    body = json.loads(resp.content)
                    assert test_data == body
                    return body

                body = retry(_invoke_start_sync_step_function, retries=15, sleep=0.8)
                snapshot.match("start_sync_response", body)

            case "DeleteStateMachine":
                _prepare_integration({}, {})
                aws_client.apigateway.create_deployment(restApiId=rest_api, stageName="dev")

                def _invoke_step_function():
                    resp = requests.post(url, data=json.dumps({"stateMachineArn": sm_arn}))
                    # If the action is successful, the service sends back an HTTP 200 response with an empty HTTP body.
                    assert resp.ok
                    return json.loads(resp.content)

                body = retry(_invoke_step_function, retries=15, sleep=1)
                snapshot.match("delete_state_machine_response", body)
