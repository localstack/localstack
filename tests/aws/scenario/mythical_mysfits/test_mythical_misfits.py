"""
This scenario setup is based on the official AWS serverlesspresso sample available at https://workshop.serverlesscoffee.com/
Source: https://github.com/aws-samples/serverless-coffee-workshop
It's originally written via SAM but has been adapted here into a Python-based CDK application.
"""

import base64

import aws_cdk as cdk
import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner

# cleanup_s3_bucket
from localstack.utils.strings import to_str

# from localstack.utils.sync import retry
from tests.aws.scenario.mythical_mysfits.stacks.mysfits_core_stack import MythicalMysfitsCoreStack

# import json
# import os
# import time


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
    def infrastructure(self, aws_client):
        # ================================================================================================
        # CDK App/stack
        # ================================================================================================
        app = cdk.App(auto_synth=False)
        stack = MythicalMysfitsCoreStack(app, STACK_NAME)

        # ================================================================================================
        # Provisioner setup
        # ================================================================================================

        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        with provisioner.provisioner(skip_teardown=True) as prov:
            yield prov

    def _clean_table(self, aws_client, table_name: str):
        items = aws_client.dynamodb.scan(TableName=table_name, ConsistentRead=True)["Items"]
        for item in items:
            aws_client.dynamodb.delete_item(TableName=table_name, Key={"PK": item["PK"]})

    def test_deployed_infra_state(self, aws_client, infrastructure, snapshot):
        outputs = infrastructure.get_stack_outputs(stack_name=STACK_NAME)
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
        for stack_resource in describe_stack_resources["StackResources"]:
            print(stack_resource["ResourceType"])
            match stack_resource["ResourceType"]:
                case "AWS::Lambda::Function":
                    service_resources[
                        stack_resource["LogicalResourceId"]
                    ] = aws_client.lambda_.get_function(
                        FunctionName=stack_resource["PhysicalResourceId"]
                    )
                # case "AWS::S3::Bucket":
                #     service_resources[
                #         stack_resource["LogicalResourceId"]
                #     ] = aws_client.s3.describe_state_machine(
                #         stateMachineArn=stack_resource["PhysicalResourceId"]
                #     )
                case "AWS::DynamoDB::Table":
                    service_resources[
                        stack_resource["LogicalResourceId"]
                    ] = aws_client.dynamodb.describe_table(
                        TableName=stack_resource["PhysicalResourceId"]
                    )
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
        print(logs)

        objs = aws_client.dynamodb.scan(TableName=mysfits_table_name)
        assert objs["Count"] > 0

    def test_user_clicks_are_stored(self):
        pass
