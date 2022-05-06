import pytest


class TestCdkInit:
    @pytest.mark.parametrize("bootstrap_version", ["10", "11", "12"])
    def test_cdk_bootstrap(self, deploy_cfn_template, cfn_client, bootstrap_version):
        deploy_cfn_template(template_file_name=f"cdk_bootstrap_v{bootstrap_version}.yaml")
        init_stack_result = deploy_cfn_template(template_file_name="cdk_init_template.yaml")
        assert init_stack_result.outputs["BootstrapVersionOutput"] == bootstrap_version
        stack_res = cfn_client.describe_stack_resources(
            StackName=init_stack_result.stack_id, LogicalResourceId="CDKMetadata"
        )
        assert len(stack_res["StackResources"]) == 1
        assert stack_res["StackResources"][0]["LogicalResourceId"] == "CDKMetadata"
