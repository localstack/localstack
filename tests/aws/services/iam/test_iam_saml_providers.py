"""
Tests for IAM SAML Provider operations.

Migrated from moto tests: moto-repo/tests/test_iam/test_iam.py
"""

import datetime

import pytest
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid

SAML_METADATA_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://test-idp.example.com/saml">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{certificate}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test-idp.example.com/saml/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://test-idp.example.com/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


@pytest.fixture
def saml_metadata():
    """Generate valid SAML metadata with a real X.509 certificate."""
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Generate a self-signed certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test-idp.example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # Get the certificate in PEM format and extract the base64 part
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_base64 = (
        cert_pem.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "")
    )

    return SAML_METADATA_TEMPLATE.format(certificate=cert_base64).replace("\n", "")


class TestSAMLProviders:
    """Tests for IAM SAML provider operations."""

    @markers.aws.validated
    def test_create_saml_provider(
        self, aws_client, account_id, snapshot, cleanups, saml_metadata, partition
    ):
        """Test creating a SAML provider."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        response = aws_client.iam.create_saml_provider(
            Name=provider_name, SAMLMetadataDocument=saml_metadata
        )
        provider_arn = response["SAMLProviderArn"]
        cleanups.append(lambda: aws_client.iam.delete_saml_provider(SAMLProviderArn=provider_arn))
        snapshot.add_transformer(snapshot.transform.regex(provider_name, "<provider-name>"))
        snapshot.match("create-response", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..AssertionEncryptionMode", "$..PrivateKeyList", "$..Tags", "$..SAMLProviderUUID"]
    )
    def test_get_saml_provider(self, aws_client, snapshot, cleanups, saml_metadata):
        """Test retrieving a SAML provider."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        create_response = aws_client.iam.create_saml_provider(
            Name=provider_name, SAMLMetadataDocument=saml_metadata
        )
        provider_arn = create_response["SAMLProviderArn"]
        cleanups.append(lambda: aws_client.iam.delete_saml_provider(SAMLProviderArn=provider_arn))

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
    def test_update_saml_provider(self, aws_client, snapshot, cleanups, saml_metadata):
        """Test updating a SAML provider's metadata document."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        snapshot.add_transformer(
            snapshot.transform.key_value("SAMLMetadataDocument", "saml-metadata-document")
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("SAMLProviderUUID", "saml-provider-uuid")
        )
        snapshot.add_transformer(snapshot.transform.regex(provider_name, "<provider-name>"))

        create_response = aws_client.iam.create_saml_provider(
            Name=provider_name, SAMLMetadataDocument=saml_metadata
        )
        provider_arn = create_response["SAMLProviderArn"]
        cleanups.append(lambda: aws_client.iam.delete_saml_provider(SAMLProviderArn=provider_arn))

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
    def test_list_saml_providers(self, aws_client, snapshot, cleanups, saml_metadata):
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
        create_response = aws_client.iam.create_saml_provider(
            Name=provider_name, SAMLMetadataDocument=saml_metadata
        )
        provider_arn = create_response["SAMLProviderArn"]
        cleanups.append(lambda: aws_client.iam.delete_saml_provider(SAMLProviderArn=provider_arn))

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
    def test_delete_saml_provider(self, aws_client, snapshot, saml_metadata):
        """Test deleting a SAML provider."""
        provider_name = f"TestSAMLProvider-{short_uid()}"

        # Create a provider
        create_response = aws_client.iam.create_saml_provider(
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
    @pytest.mark.skip(reason="TODO: exception not raised")
    def test_delete_saml_provider_not_found(self, aws_client, account_id, snapshot, partition):
        """Test error when deleting a non-existent SAML provider."""
        fake_arn = f"arn:{partition}:iam::{account_id}:saml-provider/NonExistentProvider"

        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_saml_provider(SAMLProviderArn=fake_arn)
        snapshot.match("delete-not-found", exc.value.response)
