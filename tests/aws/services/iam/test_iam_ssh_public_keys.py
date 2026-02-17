"""
Tests for IAM SSH Public Key operations.

Migrated from moto tests: moto-repo/tests/test_iam/test_iam.py
"""

import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@pytest.fixture
def public_key():
    """Generate a valid SSH public key for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
    )
    # IAM expects a string, not bytes
    return public_key_bytes.decode("utf-8")


class TestSSHPublicKeys:
    """Tests for IAM SSH public key operations."""

    @markers.aws.validated
    def test_upload_ssh_public_key(self, aws_client, create_user, snapshot, cleanups, public_key):
        """Test uploading an SSH public key for a user."""
        user_name = f"test-user-{short_uid()}"
        create_user(UserName=user_name)

        response = aws_client.iam.upload_ssh_public_key(
            UserName=user_name, SSHPublicKeyBody=public_key
        )
        pubkey = response["SSHPublicKey"]
        cleanups.append(
            lambda: aws_client.iam.delete_ssh_public_key(
                UserName=user_name, SSHPublicKeyId=pubkey["SSHPublicKeyId"]
            )
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("SSHPublicKeyBody", "ssh-public-key"),
                snapshot.transform.key_value("SSHPublicKeyId", "ssh-public-key-id"),
                snapshot.transform.key_value("UserName"),
                snapshot.transform.key_value("Fingerprint"),
            ]
        )
        snapshot.match("upload-response", response)

    @markers.aws.validated
    def test_get_ssh_public_key(self, aws_client, create_user, snapshot, cleanups, public_key):
        """Test retrieving an SSH public key by ID."""
        user_name = f"test-user-{short_uid()}"
        create_user(UserName=user_name)

        # Upload a key first
        upload_response = aws_client.iam.upload_ssh_public_key(
            UserName=user_name, SSHPublicKeyBody=public_key
        )
        ssh_public_key_id = upload_response["SSHPublicKey"]["SSHPublicKeyId"]
        cleanups.append(
            lambda: aws_client.iam.delete_ssh_public_key(
                UserName=user_name, SSHPublicKeyId=ssh_public_key_id
            )
        )

        # Get the key
        response = aws_client.iam.get_ssh_public_key(
            UserName=user_name, SSHPublicKeyId=ssh_public_key_id, Encoding="SSH"
        )
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("SSHPublicKeyBody", "ssh-public-key"),
                snapshot.transform.key_value("SSHPublicKeyId", "ssh-public-key-id"),
                snapshot.transform.key_value("UserName"),
                snapshot.transform.key_value("Fingerprint"),
            ]
        )
        snapshot.match("get-response", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_get_ssh_public_key_not_found(self, aws_client, create_user, snapshot):
        """Test error when getting a non-existent SSH public key."""
        user_name = f"test-user-{short_uid()}"
        create_user(UserName=user_name)

        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_ssh_public_key(
                UserName=user_name, SSHPublicKeyId="APKAXXXXXXXXXXXXXXXXX", Encoding="SSH"
            )
        snapshot.match("get-not-found", exc.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..IsTruncated"])
    def test_list_ssh_public_keys(self, aws_client, create_user, snapshot, cleanups, public_key):
        """Test listing SSH public keys for a user."""
        user_name = f"test-user-{short_uid()}"
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("SSHPublicKeyId", "ssh-public-key-id"),
                snapshot.transform.key_value("UserName"),
            ]
        )
        create_user(UserName=user_name)

        # List should be empty initially
        response = aws_client.iam.list_ssh_public_keys(UserName=user_name)
        snapshot.match("list-empty", response)
        assert len(response["SSHPublicKeys"]) == 0

        # Upload a key
        upload_response = aws_client.iam.upload_ssh_public_key(
            UserName=user_name, SSHPublicKeyBody=public_key
        )
        ssh_public_key_id = upload_response["SSHPublicKey"]["SSHPublicKeyId"]
        cleanups.append(
            lambda: aws_client.iam.delete_ssh_public_key(
                UserName=user_name, SSHPublicKeyId=ssh_public_key_id
            )
        )

        # List should now have one key
        response = aws_client.iam.list_ssh_public_keys(UserName=user_name)
        snapshot.match("list-with-key", response)

    @markers.aws.validated
    def test_update_ssh_public_key(self, aws_client, create_user, snapshot, cleanups, public_key):
        """Test updating an SSH public key status."""
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("SSHPublicKeyBody", "ssh-public-key"),
                snapshot.transform.key_value("SSHPublicKeyId", "ssh-public-key-id"),
                snapshot.transform.key_value("UserName"),
                snapshot.transform.key_value("Fingerprint"),
            ]
        )
        user_name = f"test-user-{short_uid()}"
        create_user(UserName=user_name)

        # Upload a key
        upload_response = aws_client.iam.upload_ssh_public_key(
            UserName=user_name, SSHPublicKeyBody=public_key
        )
        ssh_public_key_id = upload_response["SSHPublicKey"]["SSHPublicKeyId"]
        cleanups.append(
            lambda: aws_client.iam.delete_ssh_public_key(
                UserName=user_name, SSHPublicKeyId=ssh_public_key_id
            )
        )
        assert upload_response["SSHPublicKey"]["Status"] == "Active"

        # Update status to Inactive
        update_response = aws_client.iam.update_ssh_public_key(
            UserName=user_name, SSHPublicKeyId=ssh_public_key_id, Status="Inactive"
        )
        snapshot.match("update-response", update_response)

        # Verify the status changed
        get_response = aws_client.iam.get_ssh_public_key(
            UserName=user_name, SSHPublicKeyId=ssh_public_key_id, Encoding="SSH"
        )
        snapshot.match("get-after-update", get_response)
        assert get_response["SSHPublicKey"]["Status"] == "Inactive"

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_update_ssh_public_key_not_found(self, aws_client, create_user, snapshot):
        """Test error when updating a non-existent SSH public key."""
        user_name = f"test-user-{short_uid()}"
        create_user(UserName=user_name)

        with pytest.raises(ClientError) as exc:
            aws_client.iam.update_ssh_public_key(
                UserName=user_name, SSHPublicKeyId="APKAXXXXXXXXXXXXXXXXX", Status="Inactive"
            )
        snapshot.match("update-not-found", exc.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..IsTruncated"])
    def test_delete_ssh_public_key(self, aws_client, create_user, snapshot, public_key):
        """Test deleting an SSH public key."""
        user_name = f"test-user-{short_uid()}"
        create_user(UserName=user_name)

        # Upload a key
        upload_response = aws_client.iam.upload_ssh_public_key(
            UserName=user_name, SSHPublicKeyBody=public_key
        )
        ssh_public_key_id = upload_response["SSHPublicKey"]["SSHPublicKeyId"]

        # Verify it exists
        response = aws_client.iam.list_ssh_public_keys(UserName=user_name)
        assert len(response["SSHPublicKeys"]) == 1

        # Delete it
        delete_response = aws_client.iam.delete_ssh_public_key(
            UserName=user_name, SSHPublicKeyId=ssh_public_key_id
        )
        snapshot.match("delete-response", delete_response)

        # Verify it's gone
        response = aws_client.iam.list_ssh_public_keys(UserName=user_name)
        snapshot.match("list-after-delete", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_delete_ssh_public_key_not_found(self, aws_client, create_user, snapshot):
        """Test error when deleting a non-existent SSH public key."""
        user_name = f"test-user-{short_uid()}"
        create_user(UserName=user_name)

        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_ssh_public_key(
                UserName=user_name, SSHPublicKeyId="APKAXXXXXXXXXXXXXXXXX"
            )
        snapshot.match("delete-not-found", exc.value.response)
