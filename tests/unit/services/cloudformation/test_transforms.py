from unittest.mock import MagicMock

from localstack.services.cloudformation.engine.transformers import (
    expand_fn_foreach,
)


class TestExpandForeach:
    def test_expand_aws_example(self):
        foreach_body = [
            "TopicName",
            ["a", "b", "c"],
            {
                "SnsTopic${TopicName}": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": {"Fn::Join": [".", [{"Ref": "TopicName"}, "fifo"]]},
                        "FifoTopic": True,
                    },
                }
            },
        ]

        expanded = expand_fn_foreach(foreach_body, resolve_context=MagicMock())

        assert expanded == {
            "SnsTopica": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": "a.fifo",
                    "FifoTopic": True,
                },
            },
            "SnsTopicb": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": "b.fifo",
                    "FifoTopic": True,
                },
            },
            "SnsTopicc": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": "c.fifo",
                    "FifoTopic": True,
                },
            },
        }
