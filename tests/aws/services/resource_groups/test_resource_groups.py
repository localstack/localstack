import contextlib
import json

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@pytest.fixture
def resourcegroups_create_group(aws_client):
    groups = []

    def _create_group(**kwargs):
        response = aws_client.resource_groups.create_group(**kwargs)
        groups.append(response["Group"]["Name"])
        return response

    yield _create_group

    for group_name in groups:
        with contextlib.suppress(
            ClientError, KeyError
        ):  # adding KeyError to the list because Moto has a bug
            aws_client.resource_groups.delete_group(GroupName=group_name)


@pytest.fixture(autouse=True)
def resource_groups_snapshot_transformers(snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("Name"),
            snapshot.transform.key_value("NextToken"),
        ]
    )


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..GroupArn",  # Moto is always returning the region as `us-west-1`, seems to be hard-coded
        "$..GroupConfiguration",
        "$..NextToken",
    ]
)
class TestResourceGroups:
    @markers.aws.validated
    def test_create_group(self, aws_client, resourcegroups_create_group, snapshot):
        name = f"resource_group-{short_uid()}"
        response = resourcegroups_create_group(
            Name=name,
            Description="description",
            ResourceQuery={
                "Type": "TAG_FILTERS_1_0",
                "Query": json.dumps(
                    {
                        "ResourceTypeFilters": ["AWS::AllSupported"],
                        "TagFilters": [
                            {
                                "Key": "resources_tag_key",
                                "Values": ["resources_tag_value"],
                            }
                        ],
                    }
                ),
            },
            Tags={"resource_group_tag_key": "resource_group_tag_value"},
        )
        snapshot.match("create-group", response)
        assert name == response["Group"]["Name"]
        assert "TAG_FILTERS_1_0" == response["ResourceQuery"]["Type"]
        assert "resource_group_tag_value" == response["Tags"]["resource_group_tag_key"]

        response = aws_client.resource_groups.get_group(GroupName=name)
        snapshot.match("get-group", response)
        assert "description" == response["Group"]["Description"]

        response = aws_client.resource_groups.list_groups()
        snapshot.match("list-groups", response)
        assert 1 == len(response["GroupIdentifiers"])
        assert 1 == len(response["Groups"])

        response = aws_client.resource_groups.delete_group(GroupName=name)
        snapshot.match("delete-group", response)
        assert name == response["Group"]["Name"]

        response = aws_client.resource_groups.list_groups()
        snapshot.match("list-groups-after-delete", response)
        assert 0 == len(response["GroupIdentifiers"])
        assert 0 == len(response["Groups"])
