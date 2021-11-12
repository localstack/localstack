import pytest

from localstack import config
from localstack.dashboard.infra import (
    find_edges_for_source,
    find_node_by_attribute,
    find_node_by_id,
)
from localstack.services.internal import ResourceGraph


def serve_resource_graph(data):
    return ResourceGraph().serve_resource_graph(data)


class TestResourceGraph:
    request_data = {"awsEnvironment": "%s:aws" % config.DEFAULT_REGION}

    def test_empty_data_arg(self):
        with pytest.raises(ValueError):
            serve_resource_graph({})

    def test_basic_return_types(self):
        graph = serve_resource_graph(self.request_data)

        assert graph is not None
        assert isinstance(graph["edges"], list), "type of edges is %s" % type(graph["edges"])
        assert isinstance(graph["nodes"], list), "type of nodes is %s" % type(graph["nodes"])

    def test_s3_notification_edges(
        self, s3_client, s3_bucket, sqs_client, sqs_create_queue, sns_topic
    ):
        # TODO: add LambdaFunctionConfigurations

        sqs_queue_url_1 = sqs_create_queue()
        sqs_queue_url_2 = sqs_create_queue()

        sqs_queue_1 = sqs_client.get_queue_attributes(
            QueueUrl=sqs_queue_url_1, AttributeNames=["All"]
        )
        sqs_queue_2 = sqs_client.get_queue_attributes(
            QueueUrl=sqs_queue_url_2, AttributeNames=["All"]
        )

        queue_arn_1 = sqs_queue_1["Attributes"]["QueueArn"]
        queue_arn_2 = sqs_queue_2["Attributes"]["QueueArn"]
        topic_arn = sns_topic["Attributes"]["TopicArn"]

        s3_client.put_bucket_notification_configuration(
            Bucket=s3_bucket,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {
                        "QueueArn": queue_arn_1,
                        "Events": ["s3:ObjectCreated:*"],
                    },
                    {
                        "QueueArn": queue_arn_2,
                        "Events": ["s3:ObjectRemoved:*"],
                    },
                ],
                "TopicConfigurations": [
                    {
                        "TopicArn": topic_arn,
                        "Events": ["s3:ObjectRemoved:*"],
                    },
                ],
            },
        )

        graph = serve_resource_graph(self.request_data)

        bucket_node = find_node_by_attribute(graph, "name", s3_bucket)
        assert bucket_node is not None, "%s not in graph %s" % (s3_bucket, graph)
        bucket_edges = find_edges_for_source(graph, bucket_node["id"])
        assert len(bucket_edges) == 3, "did not find edges in %s" % graph["edges"]

        target_arns = []
        for edge in bucket_edges:
            assert edge["source"] == bucket_node["id"]
            target = find_node_by_id(graph, edge["target"])

            assert target is not None
            target_arns.append(target["arn"])

        expected_arns = [topic_arn, queue_arn_1, queue_arn_2]

        target_arns.sort()
        expected_arns.sort()

        assert target_arns == expected_arns

    def test_dynamodb_nodes(self, dynamodb_create_table):
        table_1 = dynamodb_create_table()
        table_2 = dynamodb_create_table()

        table_1_arn = table_1["TableDescription"]["TableArn"]
        table_2_arn = table_2["TableDescription"]["TableArn"]

        graph = serve_resource_graph(self.request_data)

        node_arns = [node["arn"] for node in graph["nodes"]]

        assert table_1_arn in node_arns
        assert table_2_arn in node_arns

    # TODO: more tests
