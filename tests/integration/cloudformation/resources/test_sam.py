import json
import os
import os.path

from localstack.testing.pytest.marking import Markers
from localstack.utils.strings import short_uid, to_str


@Markers.parity.aws_validated
def test_sam_policies(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.iam_api())
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sam_function-policies.yaml"
        )
    )
    role_name = stack.outputs["HelloWorldFunctionIamRoleName"]

    roles = aws_client.iam.list_attached_role_policies(RoleName=role_name)
    assert "AmazonSNSFullAccess" in [p["PolicyName"] for p in roles["AttachedPolicies"]]
    snapshot.match("list_attached_role_policies", roles)


def test_sam_template(deploy_cfn_template, aws_client):

    # deploy template
    func_name = f"test-{short_uid()}"
    deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/template4.yaml"),
        parameters={"FunctionName": func_name},
    )

    # run Lambda test invocation
    result = aws_client.awslambda.invoke(FunctionName=func_name)
    result = json.loads(to_str(result["Payload"].read()))
    assert result == {"hello": "world"}
