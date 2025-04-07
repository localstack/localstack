import pytest

from localstack.services.kms.exceptions import DryRunOperationException, ValidationException
from localstack.services.kms.provider import KmsProvider, kms_stores
from localstack.services.kms.models import KmsKey
from localstack.aws.api.kms import (
    CreateKeyRequest
)
from localstack.aws.api import RequestContext

from localstack.services.kms.utils import validate_alias_name


def test_alias_name_validator():
    with pytest.raises(Exception):
        validate_alias_name("test-alias")

@pytest.fixture
def provider():
    return KmsProvider()


@pytest.fixture
def mock_key():
    # You can mock this more fully based on what _get_kms_key expects
    return KmsKey(
        metadata={
            "Arn": "arn:aws:kms:us-east-1:000000000000:key/abc123",
        }
    )

@pytest.mark.parametrize("invalid_spec", [
    "INVALID_SPEC",
    "RSA_1024",         # Not supported by AWS
    "ECC_FAKE",         # Invalid ECC curve
    "AES_256",          # Symmetric, not key pair
    ""
])
@pytest.mark.parametrize("dry_run", [
    True, False
])
def test_generate_data_key_pair_invalid_spec(provider, invalid_spec, dry_run):
    # Arrange
    context = RequestContext()
    context.account_id = "000000000000"
    context.region = "us-east-1"

    key_request = CreateKeyRequest(Description="Test key")
    key = provider.create_key(context, key_request)
    key_id = key["KeyMetadata"]["KeyId"]

    # Act & Assert
    with pytest.raises(ValidationException) as exc:
        provider.generate_data_key_pair(
            context=context,
            key_id=key_id,
            key_pair_spec=invalid_spec,
            dry_run=dry_run,
        )

    assert "1 validation error detected" in str(exc.value)
    assert invalid_spec in str(exc.value)

def test_generate_data_key_pair_real_key(provider):
    # Arrange
    account_id = "000000000000"
    region_name = "us-east-1"
    context = RequestContext()
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
    context = RequestContext()
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
    with pytest.raises(DryRunOperationException) as exc_info:
        provider.generate_data_key_pair(
            context=context,
            key_id=key_id,
            key_pair_spec="RSA_2048",
            dry_run=True,  # <-- this is the core of the dry-run test
        )

def test_generate_data_key_pair_without_plaintext(provider):
    # Arrange
    account_id = "000000000000"
    region_name = "us-east-1"
    context = RequestContext()
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
    context = RequestContext()
    context.account_id = account_id
    context.region = region_name

    key_request = CreateKeyRequest(Description="Test key")
    key = provider.create_key(context, key_request)
    key_id = key["KeyMetadata"]["KeyId"]

    # Act & Assert
    with pytest.raises(DryRunOperationException) as exc_info:
        provider.generate_data_key_pair_without_plaintext(
            context=context,
            key_id=key_id,
            key_pair_spec="RSA_2048",
            dry_run=True,
        )