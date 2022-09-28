import json
import os
import os.path

import pytest

from localstack.utils.files import load_file
from localstack.utils.strings import short_uid, to_str


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


def test_sam_template(lambda_client, deploy_cfn_template):

    # deploy template
    func_name = f"test-{short_uid()}"
    template = (
        load_file(os.path.join(os.path.dirname(__file__), "../templates/template4.yaml"))
        % func_name
    )
    deploy_cfn_template(template=template)

    # run Lambda test invocation
    result = lambda_client.invoke(FunctionName=func_name)
    result = json.loads(to_str(result["Payload"].read()))
    assert result == {"hello": "world"}
