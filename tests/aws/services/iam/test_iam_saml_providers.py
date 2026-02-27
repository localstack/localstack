"""
Tests for IAM SAML Provider operations.

Migrated from moto tests: moto-repo/tests/test_iam/test_iam.py
"""

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


class TestSAMLProviders:
    """Tests for IAM SAML provider operations."""

    @markers.aws.validated
    def test_create_saml_provider(
        self, aws_client, account_id, snapshot, cleanups, saml_metadata, create_saml_provider
    ):
        """Test creating a SAML provider."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        response = create_saml_provider(Name=provider_name, SAMLMetadataDocument=saml_metadata)
        snapshot.add_transformer(snapshot.transform.regex(provider_name, "<provider-name>"))
        snapshot.match("create-response", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..AssertionEncryptionMode", "$..PrivateKeyList", "$..Tags", "$..SAMLProviderUUID"]
    )
    def test_get_saml_provider(
        self, aws_client, snapshot, cleanups, saml_metadata, create_saml_provider
    ):
        """Test retrieving a SAML provider."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        create_response = create_saml_provider(
            Name=provider_name, SAMLMetadataDocument=saml_metadata
        )
        provider_arn = create_response["SAMLProviderArn"]

        response = aws_client.iam.get_saml_provider(SAMLProviderArn=provider_arn)
        snapshot.add_transformer(
            snapshot.transform.key_value("SAMLProviderUUID", "saml-provider-uuid")
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("SAMLMetadataDocument", "saml-metatada-document")
        )
        snapshot.match("get-response", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_get_saml_provider_not_found(self, aws_client, account_id, snapshot, partition):
        """Test error when getting a non-existent SAML provider."""
        fake_arn = f"arn:{partition}:iam::{account_id}:saml-provider/NonExistentProvider"

        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_saml_provider(SAMLProviderArn=fake_arn)
        snapshot.match("get-not-found", exc.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..AssertionEncryptionMode", "$..PrivateKeyList", "$..Tags", "$..SAMLProviderUUID"]
    )
    def test_update_saml_provider(
        self, aws_client, snapshot, cleanups, saml_metadata, create_saml_provider
    ):
        """Test updating a SAML provider's metadata document."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        snapshot.add_transformer(
            snapshot.transform.key_value("SAMLMetadataDocument", "saml-metadata-document")
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("SAMLProviderUUID", "saml-provider-uuid")
        )
        snapshot.add_transformer(snapshot.transform.regex(provider_name, "<provider-name>"))

        create_response = create_saml_provider(
            Name=provider_name, SAMLMetadataDocument=saml_metadata
        )
        provider_arn = create_response["SAMLProviderArn"]

        # Generate new metadata for the update
        updated_metadata = saml_metadata.replace("test-idp.example.com", "updated-idp.example.com")

        # Update with new metadata
        update_response = aws_client.iam.update_saml_provider(
            SAMLProviderArn=provider_arn, SAMLMetadataDocument=updated_metadata
        )
        snapshot.match("update-response", update_response)

        # Verify the update
        get_response = aws_client.iam.get_saml_provider(SAMLProviderArn=provider_arn)
        assert "updated-idp.example.com" in get_response["SAMLMetadataDocument"]

        snapshot.match("get-after-update", get_response)

    @markers.aws.validated
    def test_list_saml_providers(
        self, aws_client, snapshot, cleanups, saml_metadata, create_saml_provider
    ):
        """Test listing SAML providers."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        # List should not contain our provider initially
        initial_response = aws_client.iam.list_saml_providers()
        provider_list = [
            provider
            for provider in initial_response.get("SAMLProviderList", [])
            if provider_name in provider["Arn"]
        ]
        assert len(provider_list) == 0

        # Create a provider
        create_saml_provider(Name=provider_name, SAMLMetadataDocument=saml_metadata)

        # List should now include our provider
        response = aws_client.iam.list_saml_providers()
        provider_list = [
            provider
            for provider in response.get("SAMLProviderList", [])
            if provider_name in provider["Arn"]
        ]

        snapshot.add_transformer(snapshot.transform.regex(provider_name, "<provider-name>"))
        snapshot.match("list-response", provider_list)

    @markers.aws.validated
    def test_delete_saml_provider(self, aws_client, snapshot, saml_metadata, create_saml_provider):
        """Test deleting a SAML provider."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        # Create a provider
        create_response = create_saml_provider(
            Name=provider_name, SAMLMetadataDocument=saml_metadata
        )
        provider_arn = create_response["SAMLProviderArn"]

        # Verify it exists
        response = aws_client.iam.list_saml_providers()
        provider_arns = [p["Arn"] for p in response["SAMLProviderList"]]
        assert provider_arn in provider_arns

        # Delete it
        delete_response = aws_client.iam.delete_saml_provider(SAMLProviderArn=provider_arn)
        snapshot.match("delete-response", delete_response)

        # Verify it's gone
        response = aws_client.iam.list_saml_providers()
        provider_arns = [p["Arn"] for p in response["SAMLProviderList"]]
        assert provider_arn not in provider_arns

    @markers.aws.validated
    def test_delete_saml_provider_not_found(self, aws_client, account_id, snapshot, partition):
        """Test error when deleting a non-existent SAML provider."""
        fake_arn = f"arn:{partition}:iam::{account_id}:saml-provider/NonExistentProvider"

        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_saml_provider(SAMLProviderArn=fake_arn)
        snapshot.match("delete-not-found", exc.value.response)
