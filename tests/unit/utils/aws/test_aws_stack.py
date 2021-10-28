from localstack.utils.aws.aws_stack import (
    ENV_ACCESS_KEY,
    ENV_SECRET_KEY,
    inject_region_into_env,
    inject_test_credentials_into_env,
)


def test_inject_test_credentials_into_env_already_with_none_adds_both():
    env = {}
    inject_test_credentials_into_env(env)
    assert env.get(ENV_ACCESS_KEY) == "test"
    assert env.get(ENV_SECRET_KEY) == "test"


def test_inject_test_credentials_into_env_already_with_access_key_does_nothing():
    access_key = "an-access-key"
    expected_env = {ENV_ACCESS_KEY: access_key}
    env = expected_env.copy()
    inject_test_credentials_into_env(env)
    assert env == expected_env


def test_inject_test_credentials_into_env_already_with_secret_key_does_nothing():
    secret_key = "a-secret-key"
    expected_env = {ENV_SECRET_KEY: secret_key}
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
