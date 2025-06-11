import pytest

from localstack.aws.api import RequestContext
from localstack.aws.api.kms import (
    CreateKeyRequest,
    DryRunOperationException,
    UnsupportedOperationException,
)
from localstack.services.kms.exceptions import ValidationException
from localstack.services.kms.provider import KmsProvider
from localstack.services.kms.utils import (
    execute_dry_run_capable,
    validate_alias_name,
)


def test_alias_name_validator():
    with pytest.raises(Exception):
        validate_alias_name("test-alias")


@pytest.fixture
def provider():
    return KmsProvider()


def test_execute_dry_run_capable_runs_when_not_dry():
    result = execute_dry_run_capable(lambda: 1 + 1, dry_run=False)
    assert result == 2


def test_execute_dry_run_capable_raises_when_dry():
    with pytest.raises(DryRunOperationException):
        execute_dry_run_capable(lambda: "should not run", dry_run=True)


@pytest.mark.parametrize(
    "invalid_spec",
    [
        "INVALID_SPEC",
        "AES_256",  # Symmetric, not key pair
        "",
        "foo",
    ],
)
@pytest.mark.parametrize("dry_run", [True, False])
def test_generate_data_key_pair_invalid_spec_raises_unsupported_exception(
    provider, invalid_spec, dry_run
):
    # Arrange
    context = RequestContext(None)
    context.account_id = "000000000000"
    context.region = "us-east-1"

    key_request = CreateKeyRequest(Description="Test key")
    key = provider.create_key(context, key_request)
    key_id = key["KeyMetadata"]["KeyId"]

    # Act & Assert
    with pytest.raises(UnsupportedOperationException):
        provider.generate_data_key_pair(
            context=context,
            key_id=key_id,
            key_pair_spec=invalid_spec,
            dry_run=dry_run,
        )


@pytest.mark.parametrize(
    "invalid_spec",
    [
        "RSA_1024",
        "ECC_FAKE",  # Symmetric, not key pair
        "HMAC_222",
    ],
)
@pytest.mark.parametrize("dry_run", [True, False])
def test_generate_data_key_pair_invalid_spec_raises_validation_exception(
    provider, invalid_spec, dry_run
):
    # Arrange
    context = RequestContext(None)
    context.account_id = "000000000000"
    context.region = "us-east-1"

    key_request = CreateKeyRequest(Description="Test key")
    key = provider.create_key(context, key_request)
    key_id = key["KeyMetadata"]["KeyId"]

    # Act & Assert
    with pytest.raises(ValidationException):
        provider.generate_data_key_pair(
            context=context,
            key_id=key_id,
            key_pair_spec=invalid_spec,
            dry_run=dry_run,
        )


def test_generate_data_key_pair_real_key(provider):
    # Arrange
    account_id = "000000000000"
    region_name = "us-east-1"
    context = RequestContext(None)
    context.account_id = account_id
    context.region = region_name

    # Note: we're using `provider.create_key` to set up the test, which introduces a hidden dependency.
    # If `create_key` fails or changes its behavior, this test might fail incorrectly even if the logic
    # under test (`generate_data_key_pair`) is still correct. Ideally, we would decouple the store
    # through dependency injection (e.g., by abstracting the KMS store), so that
    # we could stub it or inject a pre-populated instance directly in the test setup.
    key_request = CreateKeyRequest(Description="Test key")
    key = provider.create_key(context, key_request)
    key_id = key["KeyMetadata"]["KeyId"]

    # # Act
    response = provider.generate_data_key_pair(
        context=context,
        key_id=key_id,
        key_pair_spec="RSA_2048",
        dry_run=False,
    )

    # # Assert
    assert response["KeyId"] == key["KeyMetadata"]["Arn"]
    assert response["KeyPairSpec"] == "RSA_2048"


def test_generate_data_key_pair_dry_run(provider):
    # Arrange
    account_id = "000000000000"
    region_name = "us-east-1"
    context = RequestContext(None)
    context.account_id = account_id
    context.region = region_name

    # Note: we're using `provider.create_key` to set up the test, which introduces a hidden dependency.
    # If `create_key` fails or changes its behavior, this test might fail incorrectly even if the logic
    # under test (`generate_data_key_pair`) is still correct. Ideally, we would decouple the store
    # through dependency injection (e.g., by abstracting the KMS store), so that
    # we could stub it or inject a pre-populated instance directly in the test setup.
    key_request = CreateKeyRequest(Description="Test key")
    key = provider.create_key(context, key_request)
    key_id = key["KeyMetadata"]["KeyId"]

    # Act & Assert
    with pytest.raises(DryRunOperationException):
        provider.generate_data_key_pair(
            context=context,
            key_id=key_id,
            key_pair_spec="RSA_2048",
            dry_run=True,
        )


def test_generate_data_key_pair_without_plaintext(provider):
    # Arrange
    account_id = "000000000000"
    region_name = "us-east-1"
    context = RequestContext(None)
    context.account_id = account_id
    context.region = region_name

    # Note: we're using `provider.create_key` to set up the test, which introduces a hidden dependency.
    # If `create_key` fails or changes its behavior, this test might fail incorrectly even if the logic
    # under test (`generate_data_key_pair_without_plaintext`) is still correct. Ideally, we would decouple
    # the store through dependency injection to isolate test concerns.
    key_request = CreateKeyRequest(Description="Test key")
    key = provider.create_key(context, key_request)
    key_id = key["KeyMetadata"]["KeyId"]

    # Act
    response = provider.generate_data_key_pair_without_plaintext(
        context=context,
        key_id=key_id,
        key_pair_spec="RSA_2048",
        dry_run=False,
    )

    # Assert
    assert response["KeyId"] == key["KeyMetadata"]["Arn"]
    assert response["KeyPairSpec"] == "RSA_2048"
    assert "PrivateKeyPlaintext" not in response  # Confirm plaintext was removed


def test_generate_data_key_pair_without_plaintext_dry_run(provider):
    # Arrange
    account_id = "000000000000"
    region_name = "us-east-1"
    context = RequestContext(None)
    context.account_id = account_id
    context.region = region_name

    key_request = CreateKeyRequest(Description="Test key")
    key = provider.create_key(context, key_request)
    key_id = key["KeyMetadata"]["KeyId"]

    # Act & Assert
    with pytest.raises(DryRunOperationException):
        provider.generate_data_key_pair_without_plaintext(
            context=context,
            key_id=key_id,
            key_pair_spec="RSA_2048",
            dry_run=True,
        )
