import json
import os

import pytest
import requests
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack import config
from localstack.testing.config import TEST_AWS_ACCESS_KEY_ID
from localstack.testing.pytest import markers
from localstack.utils.aws.request_context import mock_aws_request_headers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until
from localstack.utils.testutil import create_zip_file


class TestCdkInit:
    @pytest.mark.parametrize("bootstrap_version", ["10", "11", "12"])
    @markers.aws.validated
    def test_cdk_bootstrap(self, deploy_cfn_template, bootstrap_version, aws_client):
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                f"../../../templates/cdk_bootstrap_v{bootstrap_version}.yaml",
            ),
            parameters={"FileAssetsBucketName": f"cdk-bootstrap-{short_uid()}"},
        )
        init_stack_result = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/cdk_init_template.yaml"
            )
        )
        assert init_stack_result.outputs["BootstrapVersionOutput"] == bootstrap_version
        stack_res = aws_client.cloudformation.describe_stack_resources(
            StackName=init_stack_result.stack_id, LogicalResourceId="CDKMetadata"
        )
        assert len(stack_res["StackResources"]) == 1
        assert stack_res["StackResources"][0]["LogicalResourceId"] == "CDKMetadata"

    @markers.aws.unknown
    def test_cdk_bootstrap_redeploy(
        self,
        is_change_set_finished,
        cleanup_stacks,
        cleanup_changesets,
        region_name,
    ):
        """Test that simulates a sequence of commands executed by CDK when running 'cdk bootstrap' twice"""

        base_folder = os.path.dirname(os.path.realpath(__file__))
        requests_file = os.path.join(base_folder, "../../../files/cdk-bootstrap-requests.json")
        operations = json.loads(load_file(requests_file))

        change_set_name = "cdk-deploy-change-set-a4b98b18"
        stack_name = "CDKToolkit-a4b98b18"
        try:
            headers = mock_aws_request_headers(
                "cloudformation",
                TEST_AWS_ACCESS_KEY_ID,
                region_name,
            )
            base_url = config.internal_service_url()
            for op in operations:
                url = f"{base_url}{op['path']}"
                data = op["data"]
                requests.request(method=op["method"], url=url, headers=headers, data=data)
                if "Action=ExecuteChangeSet" in data:
                    assert wait_until(
                        is_change_set_finished(change_set_name, stack_name=stack_name),
                        _max_wait=20,
                        strategy="linear",
                    )
        finally:
            # clean up
            cleanup_changesets([change_set_name])
            cleanup_stacks([stack_name])

    # TODO: remove this and replace with CDK test
    @markers.aws.unknown
    def test_cdk_template(self, deploy_cfn_template, s3_create_bucket, aws_client):
        bucket = f"bucket-{short_uid()}"
        key = f"key-{short_uid()}"
        path = os.path.join(os.path.dirname(__file__), "../../../templates/asset")

        s3_create_bucket(Bucket=bucket)
        aws_client.s3.put_object(
            Bucket=bucket, Key=key, Body=create_zip_file(path, get_content=True)
        )

        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/cdktemplate.json")
        )

        stack = deploy_cfn_template(
            template=template,
            parameters={
                "AssetParameters1S3BucketEE4ED9A8": bucket,
                "AssetParameters1S3VersionKeyE160C88A": key,
            },
        )

        resp = aws_client.lambda_.list_functions()
        functions = [func for func in resp["Functions"] if stack.stack_name in func["FunctionName"]]

        assert len(functions) == 2
        assert (
            len([func for func in functions if func["Handler"] == "index.createUserHandler"]) == 1
        )
        assert (
            len([func for func in functions if func["Handler"] == "index.authenticateUserHandler"])
            == 1
        )


class TestCdkSampleApp:
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Attributes.Policy.Statement..Condition",
            "$..Attributes.Policy.Statement..Resource",
            "$..StackResourceSummaries..PhysicalResourceId",
        ]
    )
    @markers.aws.validated
    def test_cdk_sample(self, deploy_cfn_template, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.sns_api())
        snapshot.add_transformer(
            SortingTransformer("StackResourceSummaries", lambda x: x["LogicalResourceId"]),
            priority=-1,
        )

        deploy = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/cfn_cdk_sample_app.yaml"
            ),
            max_wait=120,
        )

        queue_url = deploy.outputs["QueueUrl"]

        queue_attr_policy = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["Policy"]
        )
        snapshot.match("queue_attr_policy", queue_attr_policy)
        stack_resources = aws_client.cloudformation.list_stack_resources(StackName=deploy.stack_id)
        snapshot.match("stack_resources", stack_resources)

        # physical resource id of the queue policy AWS::SQS::QueuePolicy
        queue_policy_resource = aws_client.cloudformation.describe_stack_resource(
            StackName=deploy.stack_id, LogicalResourceId="CdksampleQueuePolicyFA91005A"
        )
        snapshot.add_transformer(
            snapshot.transform.regex(
                queue_policy_resource["StackResourceDetail"]["PhysicalResourceId"],
                "<queue-policy-physid>",
            )
        )
        # TODO: make sure phys id of the resource conforms to this format: stack-d98dcad5-CdksampleQueuePolicyFA91005A-1WYVV4PMCWOYI
