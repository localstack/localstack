import os

import pytest

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.fixtures import StackDeployError

RESOURCE_GETATT_TARGETS = [
    "DomainName",
    "EngineVersion",
    "DomainEndpoint",
    "Id",
    "Arn",
    "DomainArn",
]


class TestAttributeAccess:
    @pytest.mark.parametrize("attribute", RESOURCE_GETATT_TARGETS)
    @pytest.mark.xfail(
        reason="Some tests are expected to fail, since they try to access invalid CFn attributes",
        raises=StackDeployError,
    )
    @pytest.mark.skipif(condition=not is_aws_cloud(), reason="Exploratory test only")
    @markers.aws.unknown
    def test_getattr(
        self,
        aws_client: ServiceLevelClientFactory,
        deploy_cfn_template,
        attribute,
        snapshot,
    ):
        """
        Capture the behaviour of getting all available attributes of the model
        """

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "templates/domain.yaml",
            ),
            parameters={"AttributeName": attribute},
        )
        snapshot.match("stack_outputs", stack.outputs)

        # check physical resource id
        res = aws_client.cloudformation.describe_stack_resource(
            StackName=stack.stack_name, LogicalResourceId="MyResource"
        )["StackResourceDetail"]
        snapshot.match("physical_resource_id", res.get("PhysicalResourceId"))
