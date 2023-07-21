import copy
import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass

import aws_cdk as cdk
import aws_cdk.aws_apigateway as apigw
import aws_cdk.aws_cognito as cognito
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as awslambda
import aws_cdk.aws_s3 as s3
import pytest
import requests
from constructs import Construct

from localstack.testing.scenario.provisioning import InfraProvisioner


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
    @pytest.fixture(scope="class")
    def create_archive_for_lambda_resource(self):
        existing_zip_path = os.path.join(
            os.path.dirname(__file__), "./notes_resources/node_modules.zip"
        )
        libs_file = os.path.join(
            os.path.dirname(__file__), "./notes_resources/lambda_sources/libs/response.js"
        )
        tmp_dir_list = []
        tmp_zip_path_list = []

        def create_tmp_zip(**kwargs):
            lambda_file_base_name = kwargs["lambda_name"]

            # Create a temporary directory
            temp_dir = tempfile.mkdtemp()
            tmp_dir_list.append(temp_dir)
            # Extract the existing ZIP file contents to the temporary directory
            with zipfile.ZipFile(existing_zip_path, "r") as existing_zip:
                existing_zip.extractall(temp_dir)

            # Add the libs to the temporary directory
            new_resource_filename = os.path.basename(libs_file)
            os.mkdir(os.path.join(temp_dir, "libs"))
            new_resource_temp_path = os.path.join(temp_dir, "libs", new_resource_filename)
            shutil.copy2(libs_file, new_resource_temp_path)

            # Add the lambda to the temporary directory
            lambda_file = f"{lambda_file_base_name}.js"
            lambda_file_path = os.path.join(
                os.path.dirname(__file__), f"./notes_resources/lambda_sources/{lambda_file}"
            )
            new_resource_temp_path = os.path.join(temp_dir, "index.js")
            shutil.copy2(lambda_file_path, new_resource_temp_path)

            # Create a temporary ZIP file
            temp_zip_path = os.path.join(tempfile.gettempdir(), f"{lambda_file_base_name}.zip")
            tmp_zip_path_list.append(temp_zip_path)
            with zipfile.ZipFile(temp_zip_path, "w") as temp_zip:
                # Add the contents of the existing ZIP file
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        archive_name = os.path.relpath(file_path, temp_dir)
                        temp_zip.write(file_path, archive_name)
            return temp_zip_path

        yield create_tmp_zip

        # Clean up the temporary directory
        for tmp_dir in tmp_dir_list:
            shutil.rmtree(tmp_dir)

        # Clean up the temporary ZIP file if it exists
        for tmp_zip_path in tmp_zip_path_list:
            if os.path.exists(tmp_zip_path):
                os.remove(tmp_zip_path)

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(
        self, aws_client, s3_create_bucket_class_scope, create_archive_for_lambda_resource
    ):
        # stack definition
        # manually create s3 bucket + upload lambda
        bucket_name = s3_create_bucket_class_scope(Bucket="notes")
        lambda_notes = ["createNote", "deleteNote", "getNote", "listNotes", "updateNote"]
        for note in lambda_notes:
            archive = create_archive_for_lambda_resource(lambda_name=note)
            aws_client.s3.upload_file(
                Filename=archive,
                Bucket=bucket_name,
                Key=f"{note}.zip",
            )

        app = cdk.App()
        stack = cdk.Stack(app, "NoteTakingStack")
        table = dynamodb.Table(
            stack,
            "notes",
            partition_key=dynamodb.Attribute(name="noteId", type=dynamodb.AttributeType.STRING),
        )
        api = apigw.RestApi(stack, "endpoint")
        notes_endpoint = api.root.add_resource("notes")
        _add_endpoints(
            resource=notes_endpoint,
            stack=stack,
            bucket_name=bucket_name,
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
            bucket_name=bucket_name,
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

        # TODO this seems to belong to audio upload/transcription and is currently not part of the app
        files_bucket = s3.Bucket(stack, "files_bucket")
        files_bucket.add_cors_rule(
            allowed_origins=apigw.Cors.ALL_ORIGINS,
            allowed_methods=[
                s3.HttpMethods.PUT,
                s3.HttpMethods.GET,
                s3.HttpMethods.DELETE,
            ],
            allowed_headers=["*"],
        )
        identity_pool = cognito.CfnIdentityPool(
            stack, "identity-pool", allow_unauthenticated_identities=True
        )
        unauthenticated_role = iam.Role(
            stack,
            "unauthenticated-role",
            assumed_by=iam.FederatedPrincipal(
                "cognito-identity.amazonaws.com",
                conditions={
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": identity_pool.ref,
                    },
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "unauthenticated",
                    },
                },
                assume_role_action="sts:AssumeRoleWithWebIdentity",
            ),
        )
        # NOT recommended for production code - only give read permissions for unauthenticated resources
        files_bucket.grant_read(unauthenticated_role)
        files_bucket.grant_put(unauthenticated_role)
        files_bucket.grant_delete(unauthenticated_role)

        unauthenticated_role.add_to_policy(
            iam.PolicyStatement(
                resources=["*"], actions=["transcribe:StartStreamTranscriptionWebSocket"]
            )
        )

        # Add policy to enable Amazon Polly text-to-speech
        # TODO the transcribe/audio notes taking was actually from dev hub. transcribe might work with LS
        unauthenticated_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonPollyFullAccess")
        )

        cognito.CfnIdentityPoolRoleAttachment(
            stack,
            "role-attachment",
            identity_pool_id=identity_pool.ref,
            roles={"unauthenticated": unauthenticated_role.role_arn},
        )
        cdk.CfnOutput(stack, "FilesBucket", value=files_bucket.bucket_name)
        cdk.CfnOutput(stack, "GatewayUrl", value=api.url)
        cdk.CfnOutput(stack, "IdentityPoolId", value=identity_pool.ref)
        cdk.CfnOutput(stack, "Region", value=stack.region)

        # provisioning
        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        provisioner.provision()
        yield provisioner
        provisioner.teardown()

    def test_something(self, infrastructure):
        outputs = infrastructure.get_stack_outputs("NoteTakingStack")
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
