"""
This scenario setup is based on the official AWS Modern Application Workshop sample available at
https://github.com/aws-samples/aws-modern-application-workshop/tree/python-cdk

It's originally written via TypeScript CDK but has been adapted here into a Python-based CDK application.
"""

import base64
import json

import pytest
import requests

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner
from localstack.utils.strings import to_str
from localstack.utils.sync import retry
from tests.aws.scenario.mythical_mysfits.stacks.mysfits_core_stack import MythicalMysfitsCoreStack

STACK_NAME = "MythicalMisfitsStack"


@pytest.mark.skipif(condition=not is_aws_cloud(), reason="not working in too many places")
class TestMythicalMisfitsScenario:
    """
    Components:
    The Mysfits microservice - Uses an Amazon Fargate container behind an NLB storing data into a DynamoDB table.
    The Mysfits API - Provides an API with APIGateway which exposes the Mysfits microservice, as well as the Comments microservice. Uses Cognito authorizer.
    The Comments microservice - Provides an API to update/get comments with DynamoDB, Lambda and SNS, traced with X-Ray.
    The Users Clicks API - Pushes Click events to Kinesis Data Firehose through API Gateway to a Lambda storing enriched events in an S3 bucket via Kinesis.
    The Recommendation API - Provides an API to give recommendations from SageMaker.
    """

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="MythicalMisfits")
        MythicalMysfitsCoreStack(infra.cdk_app, STACK_NAME)
        with infra.provisioner(skip_teardown=False) as prov:
            yield prov

    def _clean_table(self, aws_client, table_name: str):
        items = aws_client.dynamodb.scan(TableName=table_name, ConsistentRead=True)["Items"]
        for item in items:
            aws_client.dynamodb.delete_item(
                TableName=table_name, Key={"MysfitId": {"S": item["MysfitId"]["S"]}}
            )

    @markers.aws.validated
    def test_deployed_infra_state(self, aws_client, infrastructure, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("DeliveryStreamName"),
                snapshot.transform.key_value("ClicksBucketDestinationName"),
                snapshot.transform.key_value("PopulateDbFunctionName"),
                snapshot.transform.key_value("StreamProcessorFunctionName"),
                snapshot.transform.key_value("UserClicksServiceAPIId"),
                snapshot.transform.key_value("StackId"),
                snapshot.transform.key_value("LogicalResourceId"),
                snapshot.transform.key_value("PhysicalResourceId"),
                snapshot.transform.key_value("RuntimeVersionArn"),
                snapshot.transform.key_value("Location"),
                snapshot.transform.key_value(
                    "CodeSize", value_replacement="<code-size>", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    jsonpath="$..Code.Location",
                    value_replacement="<location>",
                    reference_replacement=False,
                ),
            ]
        )
        outputs = infrastructure.get_stack_outputs(stack_name=STACK_NAME)
        # TODO: UserClicksServiceAPIEndpoint from output will be different in AWS and LocalStack
        snapshot.match("outputs", outputs)
        describe_stack = aws_client.cloudformation.describe_stacks(StackName=STACK_NAME)["Stacks"][
            0
        ]
        snapshot.match("describe_stack", describe_stack)
        describe_stack_resources = aws_client.cloudformation.describe_stack_resources(
            StackName=STACK_NAME
        )
        snapshot.match("describe_stack_resources", describe_stack_resources)

        # collect service level describe calls
        service_resources = {}
        resource_count = {}
        for stack_resource in describe_stack_resources["StackResources"]:
            resource_type = stack_resource["ResourceType"]
            r_count = resource_count.setdefault(resource_type, 0) + 1
            resource_count[resource_type] = r_count
            r_key = f"{resource_type}-{r_count}"

            match resource_type:
                case "AWS::Lambda::Function":
                    service_resources[r_key] = aws_client.lambda_.get_function(
                        FunctionName=stack_resource["PhysicalResourceId"]
                    )
                case "AWS::KinesisFirehose::DeliveryStream":
                    service_resources[r_key] = aws_client.firehose.describe_delivery_stream(
                        DeliveryStreamName=stack_resource["PhysicalResourceId"]
                    )
                case "AWS::DynamoDB::Table":
                    service_resources[r_key] = aws_client.dynamodb.describe_table(
                        TableName=stack_resource["PhysicalResourceId"]
                    )
                # TODO: RestApi/Resource/Method-x2 + sub resources from the Method?
        snapshot.match("resources", service_resources)

    @markers.aws.validated
    def test_populate_data(self, aws_client, infrastructure: "InfraProvisioner"):
        """populate dynamodb table with data"""
        outputs = infrastructure.get_stack_outputs(stack_name=STACK_NAME)
        mysfits_table_name = outputs["MysfitsTableName"]
        populate_data_fn = outputs["PopulateDbFunctionName"]

        self._clean_table(aws_client, mysfits_table_name)

        objs = aws_client.dynamodb.scan(TableName=mysfits_table_name)
        assert objs["Count"] == 0

        # populate the data now (sync)
        result = aws_client.lambda_.invoke(
            FunctionName=populate_data_fn, InvocationType="RequestResponse", LogType="Tail"
        )
        logs = to_str(base64.b64decode(result["LogResult"]))
        assert "'UnprocessedItems': {}" in logs

        objs = aws_client.dynamodb.scan(TableName=mysfits_table_name)
        assert objs["Count"] > 0

    @markers.aws.validated
    def test_user_clicks_are_stored(self, aws_client, infrastructure: "InfraProvisioner", snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("x-amz-apigw-id"),
                snapshot.transform.key_value("x-amzn-RequestId"),
                snapshot.transform.key_value("Date"),
                snapshot.transform.key_value("Key"),
                snapshot.transform.key_value("Name"),
            ]
        )
        outputs = infrastructure.get_stack_outputs(stack_name=STACK_NAME)
        bucket_name = outputs["ClicksBucketDestinationName"]
        # replace with UserClicksServiceAPIEndpoint
        mysfits_api_base_url = outputs["UserClicksServiceAPIEndpoint1DA4E100"]
        misfits_api_url = f"{mysfits_api_base_url}/clicks"

        # test the MOCK integration that returns CORS headers
        cors_req = requests.options(misfits_api_url, headers={"Origin": "test.domain.com"})
        assert cors_req.ok
        assert cors_req.content == b""
        snapshot.match("cors-req-headers", dict(cors_req.headers))

        # test the AWS firehose integration, taken from the web app part
        user_click = {
            "userId": "randomuser",
            "mysfitId": "b6d16e02-6aeb-413c-b457-321151bb403d",  # need to use a proper mysfitId
        }

        click_req = requests.put(misfits_api_url, json=user_click)
        assert click_req.ok
        assert click_req.content == b'{"status":"OK"}'
        # TODO: snapshot headers?

        # TODO: instead of polling S3, maybe we could set up S3 notifications to SQS and poll a Queue?
        def _poll_s3_for_firehose(expected_objects: int):
            resp = aws_client.s3.list_objects_v2(Bucket=bucket_name, Prefix="firehose/")
            assert resp["KeyCount"] == expected_objects
            return resp

        response = retry(_poll_s3_for_firehose, retries=60, sleep=10, expected_objects=1)
        snapshot.match("list-objects", response)

        s3_object_key = response["Contents"][0]["Key"]
        get_obj = aws_client.s3.get_object(Bucket=bucket_name, Key=s3_object_key)
        firehose_event = json.loads(get_obj["Body"].read())
        snapshot.match("get-first-click", firehose_event)
        assert firehose_event["mysfitId"] == user_click["mysfitId"]
        # assert that the event has been enriched by the Lambda
        assert firehose_event["species"] == "Troll"

        aws_client.s3.delete_object(Bucket=bucket_name, Key=s3_object_key)
