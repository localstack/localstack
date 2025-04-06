import pytest

from localstack.services.kms.exceptions import DryRunOperationException
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