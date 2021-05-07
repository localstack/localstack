import unittest
import json
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class TestResourceGroups(unittest.TestCase):
    def setUp(self):
        self.resource_group_client = aws_stack.connect_to_service('resource-groups')

    def test_create_group(self):
        name = 'resource_group-{}'.format(short_uid())
        response = self.resource_group_client.create_group(
            Name=name,
            Description='description',
            ResourceQuery={
                'Type': 'TAG_FILTERS_1_0',
                'Query': json.dumps(
                    {
                        'ResourceTypeFilters': ['AWS::AllSupported'],
                        'TagFilters': [
                            {'Key': 'resources_tag_key', 'Values': ['resources_tag_value']}
                        ],
                    }
                ),
            },
            Tags={'resource_group_tag_key': 'resource_group_tag_value'},
        )
        self.assertEqual(response['Group']['Name'], name)
        self.assertEqual(response['ResourceQuery']['Type'], 'TAG_FILTERS_1_0')
        self.assertEqual(response['Tags']['resource_group_tag_key'], 'resource_group_tag_value')

        response = self.resource_group_client.get_group(GroupName=name)
        self.assertEqual(response['Group']['Description'], 'description')

        response = self.resource_group_client.list_groups()
        self.assertEqual(len(response['GroupIdentifiers']), 1)
        self.assertEqual(len(response['Groups']), 1)

        response = self.resource_group_client.delete_group(GroupName=name)
        self.assertEqual(response['Group']['Name'], name)

        response = self.resource_group_client.list_groups()
        self.assertEqual(len(response['GroupIdentifiers']), 0)
        self.assertEqual(len(response['Groups']), 0)
