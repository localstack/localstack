"""
This scenario tests is based on the aws-sample aws-sdk-js-notes app (https://github.com/aws-samples/aws-sdk-js-notes-app),
which was adapted to work with LocalStack https://github.com/localstack-samples/sample-notes-app-dynamodb-lambda-apigateway.
"""

import copy
import json
import logging
import os
from dataclasses import dataclass
from operator import itemgetter

import aws_cdk as cdk
import aws_cdk.aws_apigateway as apigw
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_lambda as awslambda
import pytest
import requests
from constructs import Construct

from localstack.testing.pytest import markers
from localstack.testing.scenario.cdk_lambda_helper import load_nodejs_lambda_to_s3
from localstack.testing.scenario.provisioning import InfraProvisioner

LOG = logging.getLogger(__name__)


class NotesApi(Construct):
    handler: awslambda.Function

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        bucket_name: str,
        table: dynamodb.Table,
        grant_actions: list[str],
    ):
        super().__init__(scope, id)
        bucket = cdk.aws_s3.Bucket.from_bucket_name(self, "notes", bucket_name=bucket_name)
        self.handler = awslambda.Function(
            self,
            "handler",
            code=awslambda.S3Code(bucket=bucket, key=f"{id}.zip"),
            handler="index.handler",
            runtime=awslambda.Runtime.NODEJS_18_X,  # noqa
            environment={"NOTES_TABLE_NAME": table.table_name},
        )
        table.grant(self.handler, *grant_actions)


@dataclass
class Endpoint:
    http_method: str
    endpoint_id: str
    grant_actions: str


def _add_endpoints(
    resource: apigw.Resource,
    stack: cdk.Stack,
    bucket_name: str,
    table: dynamodb.Table,
    endpoints: list[Endpoint],
):
    for endpoint in endpoints:
        resource.add_method(
            http_method=endpoint.http_method,
            integration=apigw.LambdaIntegration(
                handler=NotesApi(
                    stack,
                    endpoint.endpoint_id,
                    bucket_name=bucket_name,
                    table=table,
                    grant_actions=[endpoint.grant_actions],
                ).handler
            ),
        )


class TestNoteTakingScenario:
    STACK_NAME = "NoteTakingStack"

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="NoteTaking")
        stack = cdk.Stack(infra.cdk_app, self.STACK_NAME)

        # manually upload lambda to s3
        def _create_lambdas():
            lambda_notes = ["createNote", "deleteNote", "getNote", "listNotes", "updateNote"]
            additional_resources = [os.path.join(os.path.dirname(__file__), "./functions/libs")]
            for note in lambda_notes:
                code_path = os.path.join(os.path.dirname(__file__), f"./functions/{note}.js")
                load_nodejs_lambda_to_s3(
                    aws_client.s3,
                    infra.get_asset_bucket(),
                    key_name=f"{note}.zip",
                    code_path=code_path,
                    additional_resources=additional_resources,
                )

        infra.add_custom_setup_provisioning_step(_create_lambdas)

        table = dynamodb.Table(
            stack,
            "notes",
            partition_key=dynamodb.Attribute(name="noteId", type=dynamodb.AttributeType.STRING),
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        api = apigw.RestApi(stack, "endpoint")
        notes_endpoint = api.root.add_resource("notes")
        _add_endpoints(
            resource=notes_endpoint,
            stack=stack,
            bucket_name=InfraProvisioner.get_asset_bucket_cdk(stack),
            table=table,
            endpoints=[
                Endpoint(http_method="GET", endpoint_id="listNotes", grant_actions="dynamodb:Scan"),
                Endpoint(
                    http_method="POST", endpoint_id="createNote", grant_actions="dynamodb:PutItem"
                ),
            ],
        )
        single_note_endpoint = notes_endpoint.add_resource(
            path_part="{id}",
            default_cors_preflight_options={
                "allow_origins": apigw.Cors.ALL_ORIGINS,
            },
        )
        _add_endpoints(
            resource=single_note_endpoint,
            stack=stack,
            bucket_name=InfraProvisioner.get_asset_bucket_cdk(stack),
            table=table,
            endpoints=[
                Endpoint(
                    http_method="GET", endpoint_id="getNote", grant_actions="dynamodb:GetItem"
                ),
                Endpoint(
                    http_method="PUT", endpoint_id="updateNote", grant_actions="dynamodb:UpdateItem"
                ),
                Endpoint(
                    http_method="DELETE",
                    endpoint_id="deleteNote",
                    grant_actions="dynamodb:DeleteItem",
                ),
            ],
        )

        # TODO could enhance app by using audio upload and transcribe feature, sign-up, etc

        cdk.CfnOutput(stack, "GatewayUrl", value=api.url)
        cdk.CfnOutput(stack, "Region", value=stack.region)

        with infra.provisioner() as prov:
            yield prov

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Tags",
            "$..get_resources.items",  # TODO apigateway.get-resources
            "$..rootResourceId",
            "$..Table.DeletionProtectionEnabled",
            "$..Table.ProvisionedThroughput.LastDecreaseDateTime",
            "$..Table.ProvisionedThroughput.LastIncreaseDateTime",
            "$..Table.Replicas",
        ]
    )
    def test_validate_infra_setup(self, aws_client, infrastructure, snapshot):
        describe_stack_resources = aws_client.cloudformation.describe_stack_resources(
            StackName=self.STACK_NAME
        )
        snapshot.add_transformer(snapshot.transform.cfn_stack_resource())
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.key_value("TableName"))
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "CodeSha256", value_replacement="code-sha-256", reference_replacement=False
            )
        )
        snapshot.add_transformer(snapshot.transform.key_value("FunctionName"), priority=-1)
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "Location", value_replacement="location", reference_replacement=False
            )
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("parentId", reference_replacement=False)
        )
        snapshot.add_transformer(snapshot.transform.key_value("id", reference_replacement=False))
        snapshot.add_transformer(
            snapshot.transform.key_value("rootResourceId", reference_replacement=False)
        )

        describe_stack_resources["StackResources"].sort(key=itemgetter("ResourceType"))
        snapshot.match("describe_stack_resources", describe_stack_resources)

        service_resources_fn = {}
        rest_api_id = None
        for stack_resource in describe_stack_resources["StackResources"]:
            match stack_resource["ResourceType"]:
                case "AWS::Lambda::Function":
                    service_resources_fn[stack_resource["LogicalResourceId"]] = (
                        aws_client.lambda_.get_function(
                            FunctionName=stack_resource["PhysicalResourceId"]
                        )
                    )
                case "AWS::DynamoDB::Table":
                    # we only have one table
                    snapshot.match(
                        "resource_table",
                        aws_client.dynamodb.describe_table(
                            TableName=stack_resource["PhysicalResourceId"]
                        ),
                    )

                case "AWS::ApiGateway::RestApi":
                    rest_api_id = stack_resource["PhysicalResourceId"]

        ctn = 0
        for k in sorted(service_resources_fn.keys()):
            v = service_resources_fn.get(k)
            # introduce a new label, as the resource-id would be replaced as key-identifier,
            # messing up the transformers
            snapshot.match(f"fn_{ctn}", v)
            ctn += 1

        snapshot.match("get_rest_api", aws_client.apigateway.get_rest_api(restApiId=rest_api_id))
        resources = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        resources["items"].sort(key=itemgetter("path"))
        snapshot.match("get_resources", resources)

    @markers.aws.validated
    def test_notes_rest_api(self, infrastructure):
        outputs = infrastructure.get_stack_outputs(self.STACK_NAME)
        gateway_url = outputs["GatewayUrl"]
        base_url = f"{gateway_url}notes"

        response = requests.get(base_url)
        assert response.status_code == 200
        assert json.loads(response.text) == []

        # add some notes
        response = requests.post(base_url, json={"content": "hello world, this is my note"})
        assert response.status_code == 200
        note_1 = json.loads(response.text)

        response = requests.post(base_url, json={"content": "testing is fun :)"})
        assert response.status_code == 200
        note_2 = json.loads(response.text)

        response = requests.post(
            base_url, json={"content": "we will modify and later on remove this note"}
        )
        assert response.status_code == 200
        note_3 = json.loads(response.text)

        # check the notes are returned by the endpoint
        expected = sorted([note_1, note_2, note_3], key=lambda e: e["createdAt"])

        response = requests.get(base_url)
        assert sorted(json.loads(response.text), key=lambda e: e["createdAt"]) == expected

        # retrieve a single note
        response = requests.get(f"{base_url}/{note_1['noteId']}")
        assert response.status_code == 200
        assert json.loads(response.text) == note_1

        # modify a note
        new_content = "this is now new and modified"
        response = requests.put(f"{base_url}/{note_3['noteId']}", json={"content": new_content})
        assert response.status_code == 200

        # retrieve notes
        expected_note_3 = copy.deepcopy(note_3)
        expected_note_3["content"] = new_content

        response = requests.get(base_url)
        assert sorted(json.loads(response.text), key=lambda e: e["createdAt"]) == sorted(
            [note_1, note_2, expected_note_3], key=lambda e: e["createdAt"]
        )

        # delete note
        response = requests.delete(f"{base_url}/{note_2['noteId']}")
        assert response.status_code == 200

        # verify note was deleted
        response = requests.get(base_url)
        assert sorted(json.loads(response.text), key=lambda e: e["createdAt"]) == sorted(
            [note_1, expected_note_3], key=lambda e: e["createdAt"]
        )

        # assert deleted note cannot be retrieved
        response = requests.get(f"{base_url}/{note_2['noteId']}")
        assert response.status_code == 404
        assert json.loads(response.text) == {"status": False, "error": "Item not found."}
