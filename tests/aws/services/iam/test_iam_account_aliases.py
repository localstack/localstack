"""
Tests for IAM Account Alias operations.

Migrated from moto's test suite to LocalStack with snapshot testing for AWS parity validation.
"""

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


class TestIAMAccountAliases:
    """Tests for IAM Account Alias operations."""

    @markers.aws.validated
    def test_account_alias_lifecycle(self, aws_client, snapshot):
        """Test create, list, and delete account alias operations."""
        alias = f"alias-{short_uid()}"

        # List aliases - alias should not be found
        list_response = aws_client.iam.list_account_aliases()
        assert alias not in list_response["AccountAliases"]

        # Create account alias
        create_response = aws_client.iam.create_account_alias(AccountAlias=alias)
        snapshot.match("create-alias", create_response)

        # List aliases - should contain the created alias
        list_response = aws_client.iam.list_account_aliases()
        assert alias in list_response["AccountAliases"]

        # Delete account alias
        delete_response = aws_client.iam.delete_account_alias(AccountAlias=alias)
        snapshot.match("delete-alias", delete_response)

        # List aliases - should be empty again
        list_response = aws_client.iam.list_account_aliases()
        assert alias not in list_response["AccountAliases"]
