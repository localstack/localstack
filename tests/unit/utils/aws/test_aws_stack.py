import pytest
from botocore.utils import InvalidArnException

from localstack.utils.aws.arns import extract_region_from_arn, lambda_function_name, parse_arn
from localstack.utils.aws.aws_stack import inject_region_into_env, inject_test_credentials_into_env


def test_inject_test_credentials_into_env_already_with_none_adds_both():
    env = {}
    inject_test_credentials_into_env(env)
    assert env.get("AWS_ACCESS_KEY_ID") == "test"
    assert env.get("AWS_SECRET_ACCESS_KEY") == "test"


def test_inject_test_credentials_into_env_already_with_access_key_does_nothing():
    access_key = "an-access-key"
    expected_env = {"AWS_ACCESS_KEY_ID": access_key}
    env = expected_env.copy()
    inject_test_credentials_into_env(env)
    assert env == expected_env


def test_inject_test_credentials_into_env_already_with_secret_key_does_nothing():
    secret_key = "a-secret-key"
    expected_env = {"AWS_SECRET_ACCESS_KEY": secret_key}
    env = expected_env.copy()
    inject_test_credentials_into_env(env)
    assert env == expected_env


def test_inject_region_into_env_already_with_none_adds_region():
    env = {}
    region = "a-test-region"
    inject_region_into_env(env, region)
    assert env.get("AWS_REGION") == region


def test_inject_region_into_env_already_with_region_overwrites_it():
    env = {"AWS_REGION": "another-region"}
    region = "a-test-region"
    inject_region_into_env(env, region)
    assert env.get("AWS_REGION") == region


class TestArn:
    def test_parse_arn(self):
        arn = parse_arn("arn:aws:lambda:aws-region:acct-id:function:helloworld:42")
        assert arn["partition"] == "aws"
        assert arn["service"] == "lambda"
        assert arn["region"] == "aws-region"
        assert arn["account"] == "acct-id"
        assert arn["resource"] == "function:helloworld:42"

    def test_parse_arn_invalid(self):
        with pytest.raises(InvalidArnException):
            parse_arn("arn:aws:lambda:aws-region:acct-id")

        with pytest.raises(InvalidArnException):
            parse_arn("")

    def test_extract_region_from_arn(self):
        assert (
            extract_region_from_arn("arn:aws:lambda:aws-region:acct-id:function:helloworld:42")
            == "aws-region"
        )
        assert extract_region_from_arn("foo:bar") is None
        assert extract_region_from_arn("") is None

    def test_lambda_function_name(self):
        assert (
            lambda_function_name("arn:aws:lambda:aws-region:acct-id:function:helloworld:42")
            == "helloworld"
        )
        assert lambda_function_name("helloworld") == "helloworld"

    def test_lambda_function_name_invalid(self):
        with pytest.raises(InvalidArnException):
            assert lambda_function_name("arn:aws:lambda:aws-region:acct-id") is None

        with pytest.raises(ValueError):
            assert lambda_function_name("arn:aws:sqs:aws-region:acct-id:foo") is None
