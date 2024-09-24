# ruff: noqa
# LocalStack Resource Provider Scaffolding v1
import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestParity:
    """
    Pro-active parity-focused tests that go into more detailed than the basic test skeleton

    TODO: add more focused detailed tests for updates, different combinations, etc.
        Use snapshots here to capture detailed parity with AWS

    Other ideas for tests in here:
        - Negative test: invalid combination of properties
        - Negative test: missing required properties
    """

    @markers.aws.validated
    def test_create_with_full_properties(self, aws_client, deploy_cfn_template, snapshot, cleanups):
        """A sort of smoke test that simply covers as many properties as possible"""
        # TODO: keep extending this test with more properties for higher parity with the official resource on AWS
        user_name = f"test-user-{short_uid()}"
        group_name_1 = f"test-group-{short_uid()}"
        group_name_2 = f"test-group-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(user_name, "<user-name>"))
        snapshot.add_transformer(snapshot.transform.regex(group_name_1, "<group-name-1>"))
        snapshot.add_transformer(snapshot.transform.regex(group_name_2, "<group-name-2>"))
        snapshot.add_transformer(snapshot.transform.key_value("UserId", "user-id"))
        snapshot.add_transformer(snapshot.transform.key_value("GroupId", "group-id"))

        # it is up to you if you want to "inject" existing groups here by using a parameter
        # alternatively you can also just add another resource to the template creating a group and referencing it directly
        cleanups.append(lambda: aws_client.iam.delete_group(GroupName=group_name_1))
        cleanups.append(lambda: aws_client.iam.delete_group(GroupName=group_name_2))
        aws_client.iam.create_group(GroupName=group_name_1)
        aws_client.iam.create_group(GroupName=group_name_2)

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "templates/user_full.yaml",
            ),
            parameters={
                "CustomUserName": user_name,
                "CustomGroups": ",".join([group_name_1, group_name_2]),
            },
        )
        snapshot.match("stack-outputs", stack.outputs)
        snapshot.match("describe-user-resource", aws_client.iam.get_user(UserName=user_name))
        snapshot.match(
            "describe-user-group-association",
            aws_client.iam.list_groups_for_user(UserName=user_name),
        )

        # verify that the delete operation works
        stack.destroy()

        # fetch the resource again and assert that it no longer exists
        with pytest.raises(ClientError):
            aws_client.iam.get_user(UserName=user_name)


@pytest.mark.skip(reason="TODO")
class TestSamples:
    """User-provided samples and other reactively added scenarios (e.g. reported and reproduced GitHub issues)"""

    ...
