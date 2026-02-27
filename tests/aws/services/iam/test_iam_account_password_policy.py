"""
Tests for IAM Account Password Policy operations.

Migrated from moto tests: moto-repo/tests/test_iam/test_iam.py
"""

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers


class TestAccountPasswordPolicy:
    """Tests for IAM account password policy operations."""

    @markers.aws.validated
    def test_update_account_password_policy_defaults(self, aws_client, snapshot, cleanups):
        """Test updating password policy with default values."""
        response = aws_client.iam.update_account_password_policy()
        snapshot.match("update", response)

        response = aws_client.iam.get_account_password_policy()
        snapshot.match("password-policy-defaults", response)

        cleanups.append(lambda: aws_client.iam.delete_account_password_policy())

    @markers.aws.validated
    def test_update_account_password_policy_custom_values(self, aws_client, snapshot, cleanups):
        """Test updating password policy with custom values for all parameters."""
        aws_client.iam.update_account_password_policy(
            AllowUsersToChangePassword=True,
            HardExpiry=True,
            MaxPasswordAge=60,
            MinimumPasswordLength=10,
            PasswordReusePrevention=3,
            RequireLowercaseCharacters=True,
            RequireNumbers=True,
            RequireSymbols=True,
            RequireUppercaseCharacters=True,
        )

        response = aws_client.iam.get_account_password_policy()
        snapshot.match("password-policy-custom", response)

        cleanups.append(lambda: aws_client.iam.delete_account_password_policy())

    @markers.aws.validated
    def test_update_account_password_policy_validation_errors(self, aws_client, snapshot):
        """Test validation errors when updating password policy with invalid values."""
        with pytest.raises(ClientError) as exc:
            aws_client.iam.update_account_password_policy(
                MaxPasswordAge=1096,  # Max is 1095
                MinimumPasswordLength=129,  # Max is 128
                PasswordReusePrevention=25,  # Max is 24
            )
        snapshot.match("validation-errors", exc.value.response)

    @markers.aws.validated
    def test_get_account_password_policy_not_found(self, aws_client, snapshot):
        """Test error when getting password policy that doesn't exist."""
        # Ensure no policy exists
        try:
            aws_client.iam.delete_account_password_policy()
        except ClientError:
            pass  # Policy doesn't exist, which is what we want

        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_account_password_policy()
        snapshot.match("policy-not-found", exc.value.response)

    @markers.aws.validated
    def test_delete_account_password_policy(self, aws_client, snapshot):
        """Test deleting an existing password policy."""
        # Create a policy first
        aws_client.iam.update_account_password_policy()

        # Verify it exists
        assert aws_client.iam.get_account_password_policy()

        # Delete it
        delete_response = aws_client.iam.delete_account_password_policy()
        snapshot.match("delete-response", delete_response)

        # Verify it's gone
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_account_password_policy()
        snapshot.match("policy-deleted-not-found", exc.value.response)

    @markers.aws.validated
    def test_delete_account_password_policy_not_found(self, aws_client, snapshot):
        """Test error when deleting password policy that doesn't exist."""
        # Ensure no policy exists
        try:
            aws_client.iam.delete_account_password_policy()
        except ClientError:
            pass  # Policy doesn't exist, which is what we want

        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_account_password_policy()
        snapshot.match("delete-not-found", exc.value.response)
