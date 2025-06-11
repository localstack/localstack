import os

import pytest

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers

pytestmark = pytest.mark.skipif(
    condition=not is_v2_engine() and not is_aws_cloud(),
    reason="Only targeting the new engine",
)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..Group.Description", "$..Group.GroupArn"])
def test_group_defaults(aws_client, deploy_cfn_template, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../../../templates/resource_group_defaults.yml"
        ),
    )

    resource_group = aws_client.resource_groups.get_group(GroupName=stack.outputs["ResourceGroup"])
    snapshot.match("resource-group", resource_group)
