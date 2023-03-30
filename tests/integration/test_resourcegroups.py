import json

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class TestResourceGroups:
    def test_create_group(self):
        resource_group_client = aws_stack.create_external_boto_client("resource-groups")
        name = "resource_group-{}".format(short_uid())
        response = resource_group_client.create_group(
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
        assert name == response["Group"]["Name"]
        assert "TAG_FILTERS_1_0" == response["ResourceQuery"]["Type"]
        assert "resource_group_tag_value" == response["Tags"]["resource_group_tag_key"]

        response = resource_group_client.get_group(GroupName=name)
        assert "description" == response["Group"]["Description"]

        response = resource_group_client.list_groups()
        assert 1 == len(response["GroupIdentifiers"])
        assert 1 == len(response["Groups"])

        response = resource_group_client.delete_group(GroupName=name)
        assert name == response["Group"]["Name"]

        response = resource_group_client.list_groups()
        assert 0 == len(response["GroupIdentifiers"])
        assert 0 == len(response["Groups"])
