# flake8: noqa
import pytest

from localstack.testing.aws.util import is_aws_cloud

pytestmark = [pytest.mark.skip(reason="in progress")]


@pytest.mark.skipif(condition=not is_aws_cloud(), reason="Not supported yet")
class TestNative:
    """
    WARNING: Not all CloudFormation resource types are supported by Cloud Control!
    """

    def test_lifecycle(
        self,
        aws_client,
        snapshot,
    ):
        # aws_client.cloudcontrol.create_resource()
        # create
        # read
        # list
        # update
        # delete
        ...
