import json
import os

import pytest
import requests

from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.files import load_file
from localstack.utils.sync import wait_until


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
