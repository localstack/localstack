import json
import os

import pytest
import requests

from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until
from localstack.utils.testutil import create_zip_file


class TestCdkInit:
    @pytest.mark.parametrize("bootstrap_version", ["10", "11", "12"])
    def test_cdk_bootstrap(self, deploy_cfn_template, cfn_client, bootstrap_version):
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), f"../templates/cdk_bootstrap_v{bootstrap_version}.yaml"
            )
        )
        init_stack_result = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../templates/cdk_init_template.yaml"
            )
        )
        assert init_stack_result.outputs["BootstrapVersionOutput"] == bootstrap_version
        stack_res = cfn_client.describe_stack_resources(
            StackName=init_stack_result.stack_id, LogicalResourceId="CDKMetadata"
        )
        assert len(stack_res["StackResources"]) == 1
        assert stack_res["StackResources"][0]["LogicalResourceId"] == "CDKMetadata"

    def test_cdk_bootstrap_redeploy(
        self, is_change_set_finished, cleanup_stacks, cleanup_changesets
    ):
        """Test that simulates a sequence of commands executed by CDK when running 'cdk bootstrap' twice"""

        base_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
        requests_file = os.path.join(base_folder, "files", "cdk-bootstrap-requests.json")
        operations = json.loads(load_file(requests_file))

        change_set_name = "cdk-deploy-change-set-a4b98b18"
        stack_name = "CDKToolkit-a4b98b18"
        try:
            headers = aws_stack.mock_aws_request_headers("cloudformation")
            base_url = config.get_edge_url()
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
    def test_cdk_template(self, s3_client, lambda_client, deploy_cfn_template, s3_create_bucket):
        bucket = f"bucket-{short_uid()}"
        key = f"key-{short_uid()}"
        path = os.path.join(os.path.dirname(__file__), "../templates/asset")

        s3_create_bucket(Bucket=bucket)
        s3_client.put_object(Bucket=bucket, Key=key, Body=create_zip_file(path, get_content=True))

        template = load_file(
            os.path.join(os.path.dirname(__file__), "../templates/cdktemplate.json")
        )

        stack = deploy_cfn_template(
            template=template,
            parameters={
                "AssetParameters1S3BucketEE4ED9A8": bucket,
                "AssetParameters1S3VersionKeyE160C88A": key,
            },
        )

        resp = lambda_client.list_functions()
        functions = [func for func in resp["Functions"] if stack.stack_name in func["FunctionName"]]

        assert len(functions) == 2
        assert (
            len([func for func in functions if func["Handler"] == "index.createUserHandler"]) == 1
        )
        assert (
            len([func for func in functions if func["Handler"] == "index.authenticateUserHandler"])
            == 1
        )
