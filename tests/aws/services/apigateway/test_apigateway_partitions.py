import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestApiGatewayApiPartitions:
    # We only have access to the AWS partition not to CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_put_integration_validation(self, account_id, aws_client_factory, region, partition):
        apigw = aws_client_factory(region_name=region).apigateway

        response = apigw.create_rest_api(name=f"api{short_uid()}", description="no")
        api_id = response["id"]
        resources = apigw.get_resources(restApiId=api_id)
        root_id = [resource for resource in resources["items"] if resource["path"] == "/"][0]["id"]

        apigw.put_method(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
        )
        apigw.put_method_response(
            restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
        )
        resp = apigw.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            credentials=f"arn:{partition}:iam::{account_id}:role/service-role/testfunction-role-oe783psq",
            httpMethod="GET",
            type="AWS",
            uri=f"arn:{partition}:apigateway:{region}:s3:path/b/k",
            integrationHttpMethod="POST",
        )
        # We just want to validate that the partitioned Credentials/URI was accepted
        assert resp["uri"] == f"arn:{partition}:apigateway:{region}:s3:path/b/k"

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_get_account(self, account_id, aws_client_factory, region, partition):
        apigw = aws_client_factory(region_name=region).apigateway

        response = apigw.get_account()
        assert response["cloudwatchRoleArn"].startswith(f"arn:{partition}:iam::{account_id}:role/")
