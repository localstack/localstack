import contextlib
import json
import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid
from localstack.utils.sync import retry


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


@pytest.fixture
def sqs_create_queue_in_region(aws_client_factory):
    region_queue_urls = {}

    def factory(region, **kwargs):
        if "QueueName" not in kwargs:
            kwargs["QueueName"] = "test-queue-%s" % short_uid()
        response = aws_client_factory(region_name=region).sqs.create_queue(**kwargs)
        url = response["QueueUrl"]
        region_queue_urls.setdefault(region, []).append(url)

        return url

    yield factory

    # cleanup
    for queues_region, queue_urls in region_queue_urls.items():
        sqs_client = aws_client_factory(region_name=queues_region).sqs
        for queue_url in queue_urls:
            with contextlib.suppress(ClientError):
                sqs_client.delete_queue(QueueUrl=queue_url)


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
    """
    List of Services integrations with resourcegroups
    see: https://docs.aws.amazon.com/ARG/latest/userguide/integrated-services-list.html
    List of supported resources:
    see: https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html
    """

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

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="Not implemented in moto (ListGroupResources)"
    )
    def test_resource_groups_tag_query(
        self, aws_client, snapshot, resourcegroups_create_group, s3_bucket, sqs_create_queue
    ):
        snapshot.add_transformer(snapshot.transform.resource_name())
        group_name = f"resource_group-{short_uid()}"
        response = resourcegroups_create_group(
            Name=group_name,
            Description="test-tag-query",
            ResourceQuery={
                "Type": "TAG_FILTERS_1_0",
                "Query": json.dumps(
                    {
                        "ResourceTypeFilters": ["AWS::AllSupported"],
                        "TagFilters": [
                            {
                                "Key": "Stage",
                                "Values": ["test-resource-group"],
                            }
                        ],
                    }
                ),
            },
            Tags={"GroupTag": "GroupTag1"},
        )
        snapshot.match("create-group", response)

        response = aws_client.resource_groups.list_group_resources(Group=group_name)
        snapshot.match("list-group-resources-empty", response)

        # create SQS queue
        tagged_queue_url = sqs_create_queue()
        # tag queue
        tags = {"Stage": "test-resource-group"}
        aws_client.sqs.tag_queue(QueueUrl=tagged_queue_url, Tags=tags)

        aws_client.s3.put_bucket_tagging(
            Bucket=s3_bucket, Tagging={"TagSet": [{"Key": "Stage", "Value": "test-resource-group"}]}
        )

        not_tagged_queue_url = sqs_create_queue()
        tags = {"Stage": "not-part-resource-group"}
        aws_client.sqs.tag_queue(QueueUrl=not_tagged_queue_url, Tags=tags)

        response = aws_client.resource_groups.list_group_resources(Group=group_name)
        snapshot.match("list-group-resources", response)

        queue_tags = aws_client.sqs.list_queue_tags(QueueUrl=tagged_queue_url)
        snapshot.match("get-queue-tags", queue_tags)

        aws_client.sqs.untag_queue(QueueUrl=tagged_queue_url, TagKeys=["Stage"])

        def _get_group_resources():
            _response = aws_client.resource_groups.list_group_resources(Group=group_name)
            assert len(response["Resources"]) == 1
            return _response

        response = retry(_get_group_resources, retries=3, sleep=1)
        snapshot.match("list-group-resources-after-queue-removal", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="Not implemented in moto (ListGroupResources)"
    )
    def test_resource_groups_different_region(
        self,
        aws_client_factory,
        snapshot,
        resourcegroups_create_group,
        sqs_create_queue_in_region,
        region_name,
    ):
        """Resource groups can only have resources from the same Region, the one of the group"""
        region_1 = region_name
        region_2 = "us-east-2"
        resourcegroups_client = aws_client_factory(region_name=region_1).resource_groups
        snapshot.add_transformer(snapshot.transform.resource_name())
        group_name = f"resource_group-{short_uid()}"
        response = resourcegroups_create_group(
            Name=group_name,
            Description="test-tag-query",
            ResourceQuery={
                "Type": "TAG_FILTERS_1_0",
                "Query": json.dumps(
                    {
                        "ResourceTypeFilters": ["AWS::AllSupported"],
                        "TagFilters": [
                            {
                                "Key": "Stage",
                                "Values": ["test-resource-group"],
                            }
                        ],
                    }
                ),
            },
            Tags={"GroupTag": "GroupTag1"},
        )
        snapshot.match("create-group", response)

        # create 2 SQS queues in different regions with tags
        tags = {"Stage": "test-resource-group"}
        sqs_create_queue_in_region(region=region_1, tags=tags)
        sqs_create_queue_in_region(region=region_2, tags=tags)

        response = resourcegroups_client.list_group_resources(Group=group_name)
        snapshot.match("list-group-resources", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="Not implemented in moto (ListGroupResources)"
    )
    def test_resource_type_filters(
        self, aws_client, snapshot, resourcegroups_create_group, s3_bucket, sqs_create_queue
    ):
        """Resource group can filter with a ResourceType, like `AWS::S3::Bucket`"""
        snapshot.add_transformer(snapshot.transform.resource_name())
        group_name = f"resource_group-{short_uid()}"
        response = resourcegroups_create_group(
            Name=group_name,
            Description="test-tag-query",
            ResourceQuery={
                "Type": "TAG_FILTERS_1_0",
                "Query": json.dumps(
                    {
                        "ResourceTypeFilters": ["AWS::S3::Bucket"],
                        "TagFilters": [
                            {
                                "Key": "Stage",
                                "Values": ["test-resource-group"],
                            }
                        ],
                    }
                ),
            },
            Tags={"GroupTag": "GroupTag1"},
        )
        snapshot.match("create-group", response)

        # create SQS queue with tags
        sqs_create_queue(tags={"Stage": "test-resource-group"})

        aws_client.s3.put_bucket_tagging(
            Bucket=s3_bucket, Tagging={"TagSet": [{"Key": "Stage", "Value": "test-resource-group"}]}
        )

        response = aws_client.resource_groups.list_group_resources(Group=group_name)
        snapshot.match("list-group-resources", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="Not implemented in moto (ListGroupResources)"
    )
    def test_cloudformation_query(
        self, aws_client, deploy_cfn_template, snapshot, resourcegroups_create_group
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("StackIdentifier"),
                snapshot.transform.resource_name(),
            ]
        )
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/deploy_template_2.yaml"
            ),
            parameters={"CompanyName": "MyCompany", "MyEmail1": "my@email.com"},
        )
        assert len(stack.outputs) == 3
        topic_arn = stack.outputs["MyTopic"]

        group_name = f"resource_group-{short_uid()}"
        response = resourcegroups_create_group(
            Name=group_name,
            Description="test-cfn-query",
            ResourceQuery={
                "Type": "CLOUDFORMATION_STACK_1_0",
                "Query": json.dumps(
                    {
                        "ResourceTypeFilters": ["AWS::AllSupported"],
                        "StackIdentifier": stack.stack_id,
                    }
                ),
            },
        )
        snapshot.match("create-group", response)

        response = aws_client.resource_groups.list_group_resources(Group=group_name)
        snapshot.match("list-group-resources", response)

        assert topic_arn in [
            resource["ResourceArn"] for resource in response["ResourceIdentifiers"]
        ]

        stack.destroy()

        response = aws_client.resource_groups.list_group_resources(Group=group_name)
        snapshot.match("list-group-resources-after-destroy", response)

        with pytest.raises(ClientError) as e:
            resourcegroups_create_group(
                Name="going-to-fail",
                Description="test-cfn-query",
                ResourceQuery={
                    "Type": "CLOUDFORMATION_STACK_1_0",
                    "Query": json.dumps(
                        {
                            "ResourceTypeFilters": ["AWS::AllSupported"],
                            "StackIdentifier": stack.stack_id,
                        }
                    ),
                },
            )
        snapshot.match("create-group-with-delete-stack", e.value.response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="Not implemented in moto (SearchResources)"
    )
    def test_search_resources(self, aws_client, sqs_create_queue, snapshot):
        snapshot.add_transformer(snapshot.transform.resource_name())
        # create SQS queue with tags
        queue_url = sqs_create_queue(tags={"Stage": "test-resource-group"})
        queue_tags = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        snapshot.match("queue-tags", queue_tags)

        def _get_resources(resource_types: list[str], expected: int):
            _response = aws_client.resource_groups.search_resources(
                ResourceQuery={
                    "Type": "TAG_FILTERS_1_0",
                    "Query": json.dumps(
                        {
                            "ResourceTypeFilters": resource_types,
                            "TagFilters": [
                                {
                                    "Key": "Stage",
                                    "Values": ["test-resource-group"],
                                }
                            ],
                        }
                    ),
                }
            )
            assert len(_response["ResourceIdentifiers"]) == expected
            return _response

        retries = 10 if is_aws_cloud() else 3
        sleep = 1 if is_aws_cloud() else 0.1

        response = retry(
            _get_resources,
            resource_types=["AWS::AllSupported"],
            expected=1,
            retries=retries,
            sleep=sleep,
        )
        snapshot.match("list-group-resources-sqs", response)

        response = retry(
            _get_resources, resource_types=["AWS::S3::Bucket"], expected=0, retries=1, sleep=1
        )
        snapshot.match("list-group-resources-s3", response)
