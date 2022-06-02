import os.path

import pytest


@pytest.mark.aws_validated
def test_sam_policies(deploy_cfn_template, cfn_client, iam_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.iam_api())
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/sam_function-policies.yaml"
        )
    )
    role_name = stack.outputs["HelloWorldFunctionIamRoleName"]

    roles = iam_client.list_attached_role_policies(RoleName=role_name)
    assert "AmazonSNSFullAccess" in [p["PolicyName"] for p in roles["AttachedPolicies"]]
    snapshot.match("list_attached_role_policies", roles)
