import requests

from localstack.constants import TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url


class TestS3Integration:
    @markers.aws.unknown
    def test_api_gateway_s3_get_integration(self, s3_bucket, create_rest_apigw, aws_client):
        apigateway_name = f"test-api-{short_uid()}"
        object_name = "test.json"
        object_content = '{ "success": "true" }'
        object_content_type = "application/json"

        api_id, _, _ = create_rest_apigw(name=apigateway_name)

        aws_client.s3.put_object(
            Bucket=s3_bucket,
            Key=object_name,
            Body=object_content,
            ContentType=object_content_type,
        )

        self.connect_api_gateway_to_s3(aws_client.apigateway, s3_bucket, object_name, api_id, "GET")

        aws_client.apigateway.create_deployment(restApiId=api_id, stageName="test")
        url = api_invoke_url(api_id, stage="test", path=f"/{object_name}")
        result = requests.get(url)
        assert 200 == result.status_code
        assert object_content == result.text
        assert object_content_type == result.headers["content-type"]

    def connect_api_gateway_to_s3(self, apigw_client, bucket_name, file_name, api_id, method):
        """Connects the root resource of an api gateway to the given object of an s3 bucket."""
        s3_uri = "arn:aws:apigateway:{}:s3:path/{}/{{proxy}}".format(
            TEST_AWS_REGION_NAME, bucket_name
        )

        test_role = "test-s3-role"
        role_arn = arns.role_arn(role_name=test_role)
        resources = apigw_client.get_resources(restApiId=api_id)
        # using the root resource '/' directly for this test
        root_resource_id = resources["items"][0]["id"]
        proxy_resource = apigw_client.create_resource(
            restApiId=api_id, parentId=root_resource_id, pathPart="{proxy+}"
        )
        apigw_client.put_method(
            restApiId=api_id,
            resourceId=proxy_resource["id"],
            httpMethod=method,
            authorizationType="NONE",
            apiKeyRequired=False,
            requestParameters={},
        )
        apigw_client.put_integration(
            restApiId=api_id,
            resourceId=proxy_resource["id"],
            httpMethod=method,
            type="AWS",
            integrationHttpMethod=method,
            uri=s3_uri,
            credentials=role_arn,
            requestParameters={"integration.request.path.proxy": "method.request.path.proxy"},
        )
