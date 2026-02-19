# LocalStack Resource Provider Scaffolding v1
import os

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers

RESOURCE_GETATT_TARGETS = ["Path", "UserName", "Id", "Arn", "PermissionsBoundary"]


class TestAttributeAccess:
    @pytest.mark.parametrize("attribute", RESOURCE_GETATT_TARGETS)
    @pytest.mark.skipif(condition=not is_aws_cloud(), reason="Exploratory test only")
    @markers.aws.validated
    def test_getatt(
        self,
        aws_client,
        deploy_cfn_template,
        attribute,
        snapshot,
    ):
        """
        Use this test to find out which properties support GetAtt access

        Fn::GetAtt documentation: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-getatt.html
        """

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "templates/user_getatt_exploration.yaml",
            ),
            parameters={"AttributeName": attribute},
        )
        snapshot.match("stack_outputs", stack.outputs)

        # check physical resource id
        res = aws_client.cloudformation.describe_stack_resource(
            StackName=stack.stack_name, LogicalResourceId="MyResource"
        )["StackResourceDetail"]
        snapshot.match("physical_resource_id", res.get("PhysicalResourceId"))
