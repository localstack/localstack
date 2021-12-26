import json
import unittest

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class TestResourceGroups(unittest.TestCase):
    def setUp(self):
        self.resource_group_client = aws_stack.create_external_boto_client("resource-groups")

    def test_create_group(self):
        name = "resource_group-{}".format(short_uid())
        response = self.resource_group_client.create_group(
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
        self.assertEqual(name, response["Group"]["Name"])
        self.assertEqual("TAG_FILTERS_1_0", response["ResourceQuery"]["Type"])
        self.assertEqual("resource_group_tag_value", response["Tags"]["resource_group_tag_key"])

        response = self.resource_group_client.get_group(GroupName=name)
        self.assertEqual("description", response["Group"]["Description"])

        response = self.resource_group_client.list_groups()
        self.assertEqual(1, len(response["GroupIdentifiers"]))
        self.assertEqual(1, len(response["Groups"]))

        response = self.resource_group_client.delete_group(GroupName=name)
        self.assertEqual(name, response["Group"]["Name"])

        response = self.resource_group_client.list_groups()
        self.assertEqual(0, len(response["GroupIdentifiers"]))
        self.assertEqual(0, len(response["Groups"]))
