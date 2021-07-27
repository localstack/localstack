import pytest

from localstack.utils.aws.aws_stack import inject_test_credentials_into_env, ENV_ACCESS_KEY, ENV_SECRET_KEY, inject_region_into_env


class SomeClass:
    pass


def test_inject_test_credentials_into_env_already_with_none_adds_both():
    env = {}
    inject_test_credentials_into_env(env)
    assert env[ENV_ACCESS_KEY] == "test"
    assert env[ENV_SECRET_KEY] == "test"


def test_inject_test_credentials_into_env_already_with_access_key_does_nothing():
    access_key = "an-access-key"
    env = {ENV_ACCESS_KEY: access_key}
    inject_test_credentials_into_env(env)
    assert env[ENV_ACCESS_KEY] == access_key
    assert ENV_SECRET_KEY not in env


def test_inject_test_credentials_into_env_already_with_secret_key_does_nothing():
    secret_key = "a-secret-key"
    env = {ENV_SECRET_KEY: secret_key}
    inject_test_credentials_into_env(env)
    assert env[ENV_SECRET_KEY] == secret_key
    assert ENV_ACCESS_KEY not in env


def test_inject_region_into_env_already_with_none_adds_region():
    env = {}
    region = "a-test-region"
    inject_region_into_env(env, region)
    assert env["AWS_REGION"] == region


def test_inject_region_into_env_already_with_region_overwrites_it():
    env = {"AWS_REGION": "another-region"}
    region = "a-test-region"
    inject_region_into_env(env, region)
    assert env["AWS_REGION"] == region
