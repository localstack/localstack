def test_cdk_bootstrap(deploy_cfn_template, cfn_client):
    deploy_cfn_template(template_file_name="cdk_bootstrap_v10.yaml")
    init_stack_result = deploy_cfn_template(template_file_name="cdk_init_template.yaml")
    assert init_stack_result.outputs["BootstrapVersionOutput"] == "10"
    stack_res = cfn_client.describe_stack_resources(
        StackName=init_stack_result.stack_id, LogicalResourceId="CDKMetadata"
    )
    assert len(stack_res["StackResources"]) == 1
    assert stack_res["StackResources"][0]["LogicalResourceId"] == "CDKMetadata"
