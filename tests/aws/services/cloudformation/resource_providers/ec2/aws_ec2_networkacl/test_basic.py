import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


class TestBasicCRD:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..NetworkAcls..Entries",
            "$..NetworkAcls..Tags",
            "$..NetworkAcls..Tags..Key",
            "$..NetworkAcls..Tags..Value",
            "$..NetworkAcls..VpcId",
        ]
    )
    def test_black_box(self, deploy_cfn_template, aws_client, snapshot):
        """
        Simple test that
        - deploys a stack containing the resource
        - verifies that the resource has been created correctly by querying the service directly
        - deletes the stack ensuring that the delete operation has been implemented correctly
        - verifies that the resource no longer exists by querying the service directly
        """
        snapshot.add_transformer(snapshot.transform.key_value("NetworkAclId"))

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "templates/basic.yml",
            ),
        )
        snapshot.match("stack-outputs", stack.outputs)

        network_acl_id = stack.outputs["NetworkAclId"]
        snapshot.match(
            "describe-resource",
            aws_client.ec2.describe_network_acls(NetworkAclIds=[network_acl_id]),
        )

        # verify that the delete operation works
        stack.destroy()

        # fetch the resource again and assert that it no longer exists
        with pytest.raises(ClientError):
            aws_client.ec2.describe_network_acls(NetworkAclIds=[network_acl_id])
