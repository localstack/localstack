import aws_cdk as cdk
import aws_cdk.aws_apigateway as apigateway
import aws_cdk.aws_lambda as awslambda
import pytest

from localstack.testing.pytest import markers

FN_CODE = """
import json
def handler(event, context):
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Hello World!"
        })
    }
"""


@markers.acceptance_test
class TestApigatewayLambdaIntegration:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="APIGWtest")

        stack = cdk.Stack(infra.cdk_app, "ApiGatewayStack")
        api = apigateway.RestApi(stack, "rest-api")
        backend = awslambda.Function(
            stack,
            "backend",
            runtime=awslambda.Runtime.PYTHON_3_10,
            code=cdk.aws_lambda.Code.from_inline(FN_CODE),
            handler="index.handler",
        )
        resource = api.root.add_resource("v1")
        resource.add_method("GET", apigateway.LambdaIntegration(backend))
        api.add_gateway_response(
            "default-4xx-response",
            type=apigateway.ResponseType.DEFAULT_4_XX,
            response_headers={
                "Access-Control-Allow-Origin": "'*'",
            },
        )

        api.add_gateway_response(
            "default-5xx-response",
            type=apigateway.ResponseType.DEFAULT_5_XX,
            response_headers={
                "Access-Control-Allow-Origin": "'*'",
            },
        )

        cdk.CfnOutput(stack, "ApiId", value=api.rest_api_id)

        with infra.provisioner() as prov:
            yield prov

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..restapiEndpointC67DEFEA",
        ]
    )
    def test_scenario_validate_infra(self, aws_client, infrastructure, snapshot):
        snapshot.add_transformer(snapshot.transform.key_value("ApiId"))
        outputs = infrastructure.get_stack_outputs(stack_name="ApiGatewayStack")
        api_id = outputs["ApiId"]
        apis = aws_client.apigateway.get_rest_api(restApiId=api_id)
        assert apis["id"] == api_id

        resources = infrastructure.get_stack_outputs(stack_name="ApiGatewayStack")
        snapshot.match("resources", resources)

        # makes sure we have a physical resource
        resources = aws_client.cloudformation.describe_stack_resources(StackName="ApiGatewayStack")[
            "StackResources"
        ]
        for r in resources:
            if r["ResourceType"] == "AWS::ApiGateway::GatewayResponse":
                assert r["PhysicalResourceId"]
