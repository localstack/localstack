import json

import pytest
from localstack_snapshot.snapshots import JsonpathTransformer

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.constants import TEST_AWS_REGION_NAME
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns, aws_stack
from localstack.utils.strings import short_uid
from tests.aws.services.apigateway.apigateway_fixtures import create_rest_resource
from tests.aws.services.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
        # TODO: add support for response headers, review:
        #  localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_api_gateway.StateTaskServiceApiGateway._invoke_output_of
        "$..Headers.Content-Length",
    ]
)
class TestTaskApiGateway:
    @staticmethod
    def _add_api_gateway_transformers(snapshot) -> None:
        snapshot.add_transformers_list(
            [
                JsonpathTransformer(
                    jsonpath="$..ApiEndpoint",
                    replacement="<api-endpoint>",
                    replace_reference=False,
                ),
                JsonpathTransformer(
                    jsonpath="$..Headers.Date",
                    replacement="<headers-date>",
                    replace_reference=False,
                ),
                JsonpathTransformer(
                    jsonpath="$..Headers.Via",
                    replacement="<headers-Via>",
                    replace_reference=False,
                ),
                JsonpathTransformer(
                    jsonpath="$..Headers.x-amz-apigw-id",
                    replacement="<headers-x-amz-apigw-id>",
                    replace_reference=False,
                ),
                JsonpathTransformer(
                    jsonpath="$..Headers.X-Amz-Cf-Id",
                    replacement="<headers-X-Amz-Cf-Id>",
                    replace_reference=False,
                ),
                JsonpathTransformer(
                    jsonpath="$..Headers.X-Amz-Cf-Pop",
                    replacement="<headers-X-Amz-Cf-Pop>",
                    replace_reference=False,
                ),
                JsonpathTransformer(
                    jsonpath="$..Headers.x-amzn-RequestId",
                    replacement="<headers-x-amzn-RequestId>",
                    replace_reference=False,
                ),
                JsonpathTransformer(
                    jsonpath="$..Headers.X-Amzn-Trace-Id",
                    replacement="<headers-X-Amzn-Trace-Id>",
                    replace_reference=False,
                ),
            ]
        )

    @staticmethod
    def _create_lambda_api_response(
        apigw_client,
        create_rest_apigw,
        create_lambda_function,
        create_role_with_policy,
        lambda_function_filename,
        http_method,
        part_path,
        pipe_query_parameters=False,
    ):
        function_name = f"sfn-apigw-test-{short_uid()}"
        stage_name = "sfn-apigw-api"

        create_function_response = create_lambda_function(
            func_name=function_name,
            handler_file=lambda_function_filename,
            runtime=Runtime.python3_9,
        )

        _, role_arn = create_role_with_policy(
            "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
        )
        lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
        target_uri = arns.apigateway_invocations_arn(lambda_arn, TEST_AWS_REGION_NAME)

        api_id, _, root = create_rest_apigw(name=f"sfn-test-api-{short_uid()}")
        resource_id, _ = create_rest_resource(
            apigw_client, restApiId=api_id, parentId=root, pathPart=part_path
        )

        if pipe_query_parameters:
            apigw_client.put_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                authorizationType="NONE",
                requestParameters={
                    "method.request.path.param1": False,
                    "method.request.path.param2": False,
                },
            )
        else:
            apigw_client.put_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                authorizationType="NONE",
            )

        if pipe_query_parameters:
            apigw_client.put_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                type="AWS",
                integrationHttpMethod=http_method,
                uri=target_uri,
                credentials=role_arn,
                requestParameters={
                    "integration.request.querystring.param1": "method.request.querystring.param1",
                    "integration.request.querystring.param2": "method.request.querystring.param2",
                },
                requestTemplates={
                    "application/json": """
                            {
                                "body": $input.json('$'),
                                "queryStringParameters": "$input.params().querystring"
                            }
                        """
                },
            )
        else:
            apigw_client.put_integration(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=http_method,
                type="AWS",
                integrationHttpMethod=http_method,
                uri=target_uri,
                credentials=role_arn,
            )

        apigw_client.put_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=http_method,
            statusCode="200",
        )

        apigw_client.put_method_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=http_method,
            statusCode="200",
        )

        apigw_client.create_deployment(restApiId=api_id, stageName=stage_name)
        if is_aws_cloud():
            invocation_url = f"{api_id}.execute-api.{aws_stack.get_boto3_region()}.amazonaws.com"
        else:
            invocation_url = f"{config.internal_service_url()}/restapis/{api_id}"
        return invocation_url, stage_name

    @markers.aws.validated
    def test_invoke_base(
        self,
        aws_client,
        create_lambda_function,
        create_role_with_policy,
        create_iam_role_for_sfn,
        create_state_machine,
        create_rest_apigw,
        sfn_snapshot,
    ):
        self._add_api_gateway_transformers(sfn_snapshot)

        http_method = "POST"
        part_path = "get_constant"

        api_url, api_stage = self._create_lambda_api_response(
            apigw_client=aws_client.apigateway,
            create_lambda_function=create_lambda_function,
            create_role_with_policy=create_role_with_policy,
            lambda_function_filename=ST.LAMBDA_ID_FUNCTION,
            create_rest_apigw=create_rest_apigw,
            http_method=http_method,
            part_path=part_path,
        )

        template = ST.load_sfn_template(ST.API_GATEWAY_INVOKE_BASE)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"ApiEndpoint": api_url, "Method": http_method, "Path": part_path, "Stage": api_stage}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @pytest.mark.parametrize(
        "request_body",
        [
            None,
            "",
            "HelloWorld",
            {"message": "HelloWorld!"},
        ],
    )
    @markers.aws.validated
    def test_invoke_with_body_post(
        self,
        aws_client,
        create_lambda_function,
        create_role_with_policy,
        create_iam_role_for_sfn,
        create_state_machine,
        create_rest_apigw,
        sfn_snapshot,
        request_body,
    ):
        self._add_api_gateway_transformers(sfn_snapshot)

        http_method = "POST"
        part_path = "id_func"

        api_url, api_stage = self._create_lambda_api_response(
            apigw_client=aws_client.apigateway,
            create_lambda_function=create_lambda_function,
            create_role_with_policy=create_role_with_policy,
            lambda_function_filename=ST.LAMBDA_ID_FUNCTION,
            create_rest_apigw=create_rest_apigw,
            http_method=http_method,
            part_path=part_path,
        )

        template = ST.load_sfn_template(ST.API_GATEWAY_INVOKE_WITH_BODY)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "ApiEndpoint": api_url,
                "Method": http_method,
                "Path": part_path,
                "Stage": api_stage,
                "RequestBody": request_body,
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: ApiGateway return incorrect output type (string instead of json) either here or in other scenarios,
            #  the formatting of query parameters is also incorrect, using ": " assignment separators instead of  "=".
            "$..output.ResponseBody"
        ]
    )
    @markers.aws.validated
    def test_invoke_with_query_parameters(
        self,
        aws_client,
        create_lambda_function,
        create_role_with_policy,
        create_iam_role_for_sfn,
        create_state_machine,
        create_rest_apigw,
        sfn_snapshot,
    ):
        self._add_api_gateway_transformers(sfn_snapshot)

        http_method = "POST"
        part_path = "id_func"

        api_url, api_stage = self._create_lambda_api_response(
            apigw_client=aws_client.apigateway,
            create_lambda_function=create_lambda_function,
            create_role_with_policy=create_role_with_policy,
            lambda_function_filename=ST.LAMBDA_ID_FUNCTION,
            create_rest_apigw=create_rest_apigw,
            http_method=http_method,
            part_path=part_path,
            pipe_query_parameters=True,
        )

        template = ST.load_sfn_template(ST.API_GATEWAY_INVOKE_WITH_QUERY_PARAMETERS)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "ApiEndpoint": api_url,
                "Method": http_method,
                "Path": part_path,
                "Stage": api_stage,
                "RequestBody": {"message": ["Hello", "World!"]},
                "AllowNullValues": True,
                "QueryParameters": {"param1": ["Hello"], "param2": ["World"]},
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: apigw should return an authorisation error (403) but 404 is returned instead.
            "$..error",
            # TODO: add support for error decoration.
            "$..cause",
        ]
    )
    @markers.aws.validated
    def test_invoke_error(
        self,
        aws_client,
        create_lambda_function,
        create_role_with_policy,
        create_iam_role_for_sfn,
        create_state_machine,
        create_rest_apigw,
        sfn_snapshot,
    ):
        self._add_api_gateway_transformers(sfn_snapshot)

        http_method = "POST"
        part_path = "id_func"

        api_url, api_stage = self._create_lambda_api_response(
            apigw_client=aws_client.apigateway,
            create_lambda_function=create_lambda_function,
            create_role_with_policy=create_role_with_policy,
            lambda_function_filename=ST.LAMBDA_ID_FUNCTION,
            create_rest_apigw=create_rest_apigw,
            http_method=http_method,
            part_path=part_path,
        )

        template = ST.load_sfn_template(ST.API_GATEWAY_INVOKE_WITH_BODY)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "ApiEndpoint": api_url,
                "Method": http_method,
                "Path": part_path + "invalid",
                "Stage": api_stage,
                "RequestBody": "HelloWorld",
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
