import copy
import json

import pytest

from localstack.testing.snapshots.transformer import TransformContext
from localstack.testing.snapshots.transformer_utility import TransformerUtility


class TestTransformer:
    def test_key_value_replacement(self):
        input = {
            "hello": "world",
            "hello2": "again",
            "path": {"to": {"anotherkey": "hi", "inside": {"hello": "inside"}}},
        }

        key_value = TransformerUtility.key_value(
            "hello", "placeholder", reference_replacement=False
        )

        expected_key_value = {
            "hello": "placeholder",
            "hello2": "again",
            "path": {"to": {"anotherkey": "hi", "inside": {"hello": "placeholder"}}},
        }

        copied = copy.deepcopy(input)
        ctx = TransformContext()
        assert key_value.transform(copied, ctx=ctx) == expected_key_value
        assert ctx.serialized_replacements == []

        copied = copy.deepcopy(input)
        key_value = TransformerUtility.key_value("hello", "placeholder", reference_replacement=True)
        expected_key_value_reference = {
            "hello": "<placeholder:1>",
            "hello2": "again",
            "path": {"to": {"anotherkey": "hi", "<placeholder:2>": {"hello": "<placeholder:2>"}}},
        }
        assert key_value.transform(copied, ctx=ctx) == copied
        assert len(ctx.serialized_replacements) == 2

        tmp = json.dumps(copied, default=str)
        for sr in ctx.serialized_replacements:
            tmp = sr(tmp)

        assert json.loads(tmp) == expected_key_value_reference

    @pytest.mark.parametrize("type", ["key_value", "jsonpath"])
    def test_replacement_with_reference(self, type):
        input = {
            "also-me": "b",
            "path": {
                "to": {"anotherkey": "hi", "test": {"hello": "replaceme"}},
                "another": {"key": "this/replaceme/hello"},
            },
            "b": {"a/b/replaceme.again": "bb"},
            "test": {"inside": {"path": {"to": {"test": {"hello": "also-me"}}}}},
        }

        expected = {
            "<MYVALUE:2>": "b",
            "path": {
                "to": {"anotherkey": "hi", "test": {"hello": "<MYVALUE:1>"}},
                "another": {"key": "this/<MYVALUE:1>/hello"},
            },
            "b": {"a/b/<MYVALUE:1>.again": "bb"},
            "test": {"inside": {"path": {"to": {"test": {"hello": "<MYVALUE:2>"}}}}},
        }
        replacement = "MYVALUE"
        if type == "key_value":
            transformer = TransformerUtility.key_value(
                "hello", replacement, reference_replacement=True
            )
        else:
            transformer = TransformerUtility.jsonpath(
                "$..path.to.test.hello", replacement, reference_replacement=True
            )

        copied = copy.deepcopy(input)
        ctx = TransformContext()

        assert transformer.transform(copied, ctx=ctx) == copied
        assert len(ctx.serialized_replacements) == 2

        tmp = json.dumps(copied, default=str)
        for sr in ctx.serialized_replacements:
            tmp = sr(tmp)

        assert json.loads(tmp) == expected

    def test_regex(self):
        input = {
            "hello": "world",
            "hello2": "again",
            "path": {"to": {"anotherkey": "hi", "inside": {"hello": "inside"}}},
        }

        expected = {
            "new-value": "world",
            "new-value2": "again",
            "path": {"to": {"anotherkey": "hi", "inside": {"new-value": "inside"}}},
        }

        transformer = TransformerUtility.regex("hello", "new-value")

        ctx = TransformContext()
        output = transformer.transform(json.dumps(input), ctx=ctx)
        for sr in ctx.serialized_replacements:
            output = sr(output)
        assert json.loads(output) == expected

    def test_log_stream_name(self):
        input = {
            "Payload": {
                "context": {
                    "functionVersion": "$LATEST",
                    "functionName": "my-function",
                    "memoryLimitInMB": "128",
                    "logGroupName": "/aws/lambda/my-function",
                    "logStreamName": "2022/05/31/[$LATEST]ced3cafaaf284d8199e02909ac87e2f5",
                    "clientContext": {
                        "custom": {"foo": "bar"},
                        "client": {"snap": ["crackle", "pop"]},
                        "env": {"fizz": "buzz"},
                    },
                    "invokedFunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:my-function",
                }
            }
        }
        transformers = TransformerUtility.lambda_api()
        ctx = TransformContext()
        for t in transformers:
            t.transform(input, ctx=ctx)

        output = json.dumps(input)
        for sr in ctx.serialized_replacements:
            output = sr(output)

        expected = {
            "Payload": {
                "context": {
                    "functionVersion": "$LATEST",
                    "functionName": "<resource:1>",
                    "memoryLimitInMB": "128",
                    "logGroupName": "/aws/lambda/<resource:1>",
                    "logStreamName": "<log-stream-name:1>",
                    "clientContext": {
                        "custom": {"foo": "bar"},
                        "client": {"snap": ["crackle", "pop"]},
                        "env": {"fizz": "buzz"},
                    },
                    "invokedFunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:<resource:1>",
                }
            }
        }
        assert expected == json.loads(output)
