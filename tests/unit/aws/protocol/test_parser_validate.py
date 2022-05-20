from urllib.parse import urlencode

import pytest

from localstack.aws.protocol.parser import create_parser
from localstack.aws.protocol.validate import (
    InvalidLength,
    InvalidRange,
    MissingRequiredField,
    ParamValidator,
    validate_request,
)
from localstack.aws.spec import load_service
from localstack.http import Request as HttpRequest


class TestExceptions:
    def test_missing_required_field_restjson(self):
        parser = create_parser(load_service("opensearch"))

        op, params = parser.parse(
            HttpRequest(
                "POST",
                "/2021-01-01/tags",
                body='{"ARN":"somearn"}',
            )
        )

        with pytest.raises(MissingRequiredField) as e:
            validate_request(op, params).raise_first()

        assert e.value.error.reason == "missing required field"
        assert e.value.required_name == "TagList"

    def test_missing_required_field_query(self):
        parser = create_parser(load_service("sqs"))

        op, params = parser.parse(
            HttpRequest(
                "POST",
                "/",
                body=(
                    "Action=SendMessage&Version=2012-11-05&"
                    "QueueUrl=http%3A%2F%2Flocalhost%3A4566%2F000000000000%2Ftf-acc-test-queue&"
                ),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        )

        validator = ParamValidator()
        errors = validator.validate(params, op.input_shape)
        assert errors.has_errors()

        with pytest.raises(MissingRequiredField) as e:
            errors.raise_first()

        assert e.match("MessageBody")
        assert e.value.error.reason == "missing required field"
        assert e.value.required_name == "MessageBody"

    def test_missing_required_field_restxml(self):
        parser = create_parser(load_service("route53"))

        op, params = parser.parse(
            HttpRequest(
                "POST",
                "/2013-04-01/hostedzone",
                body="<CreateHostedZoneRequest><Name>foobar.com</Name></CreateHostedZoneRequest>",
            )
        )

        with pytest.raises(MissingRequiredField) as e:
            validate_request(op, params).raise_first()

        assert e.value.error.reason == "missing required field"
        assert e.value.required_name == "CallerReference"

    def test_invalid_range_query(self):
        parser = create_parser(load_service("sts"))

        op, params = parser.parse(
            HttpRequest(
                "POST",
                "/",
                body=urlencode(
                    query={
                        "Action": "AssumeRole",
                        "RoleArn": "arn:aws:iam::000000000000:role/foobared",
                        "RoleSessionName": "foobared",
                        "DurationSeconds": "100",
                    }
                ),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        )

        with pytest.raises(InvalidRange) as e:
            validate_request(op, params).raise_first()

        e.match("DurationSeconds")

    def test_invalid_length_query(self):
        parser = create_parser(load_service("sts"))

        op, params = parser.parse(
            HttpRequest(
                "POST",
                "/",
                body=urlencode(
                    query={
                        "Action": "AssumeRole",
                        "RoleArn": "arn:aws",  # min=8
                        "RoleSessionName": "foobared",
                    }
                ),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        )

        with pytest.raises(InvalidLength) as e:
            validate_request(op, params).raise_first()

        e.match("RoleArn")
