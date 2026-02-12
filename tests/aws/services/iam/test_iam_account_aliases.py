"""
Tests for IAM Account Alias operations.

Migrated from moto's test suite to LocalStack with snapshot testing for AWS parity validation.
"""

import pytest

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@pytest.fixture
def account_alias(aws_client):
    """Fixture to create and cleanup account aliases."""
    aliases_created = []

    def _create_alias(alias: str):
        aws_client.iam.create_account_alias(AccountAlias=alias)
        aliases_created.append(alias)
        return alias

    yield _create_alias

    # Cleanup: delete any aliases created during the test
    for alias in aliases_created:
        try:
            aws_client.iam.delete_account_alias(AccountAlias=alias)
        except Exception:
            pass


class TestIAMAccountAliases:
    """Tests for IAM Account Alias operations."""

    @markers.aws.validated
    def test_account_alias_lifecycle(self, aws_client, snapshot, account_alias):
        """Test create, list, and delete account alias operations."""
        alias = f"alias-{short_uid()}"

        # List aliases - should be empty initially
        list_response = aws_client.iam.list_account_aliases()
        snapshot.match("list-empty", list_response)

        # Create account alias
        create_response = aws_client.iam.create_account_alias(AccountAlias=alias)
        snapshot.match("create-alias", create_response)

        # List aliases - should contain the created alias
        list_response = aws_client.iam.list_account_aliases()
        snapshot.match("list-after-create", list_response)

        # Delete account alias
        delete_response = aws_client.iam.delete_account_alias(AccountAlias=alias)
        snapshot.match("delete-alias", delete_response)

        # List aliases - should be empty again
        list_response = aws_client.iam.list_account_aliases()
        snapshot.match("list-after-delete", list_response)
