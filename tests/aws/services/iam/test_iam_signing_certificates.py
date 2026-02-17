import logging
from datetime import UTC, datetime, timedelta

import pytest
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# TODO remove after new IAM implementation of signing certificates
pytestmark = pytest.mark.skip


def create_certificate() -> str:
    """
    Generate a valid X.509 certificate for testing signing certificate upload.
    Returns the certificate as a PEM-encoded string.
    """
    # Generate a private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    # Create a self-signed certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(key, hashes.SHA256(), default_backend())
    )

    # Return as PEM-encoded string
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())
    snapshot.add_transformer(snapshot.transform.key_value("CertificateId"))
    # Certificate body is generated dynamically each time, use reference_replacement=False
    snapshot.add_transformer(
        snapshot.transform.key_value(
            "CertificateBody", value_replacement="<certificate-body>", reference_replacement=False
        )
    )


class TestSigningCertificate:
    """Tests for signing certificate operations."""

    @markers.aws.validated
    def test_signing_certificate_lifecycle(self, aws_client, snapshot, create_user):
        """Test upload, list, update status, and delete signing certificate operations."""
        # Create a user
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user", create_user_response)

        # Generate a valid certificate
        cert_body = create_certificate()

        # Upload signing certificate
        upload_response = aws_client.iam.upload_signing_certificate(
            UserName=user_name, CertificateBody=cert_body
        )
        snapshot.match("upload-certificate", upload_response)
        cert_id = upload_response["Certificate"]["CertificateId"]

        # List signing certificates
        list_response = aws_client.iam.list_signing_certificates(UserName=user_name)
        snapshot.match("list-certificates", list_response)

        # Update certificate status to Inactive
        update_inactive_response = aws_client.iam.update_signing_certificate(
            UserName=user_name, CertificateId=cert_id, Status="Inactive"
        )
        snapshot.match("update-certificate-inactive", update_inactive_response)

        # Verify status changed
        list_after_inactive = aws_client.iam.list_signing_certificates(UserName=user_name)
        snapshot.match("list-certificates-after-inactive", list_after_inactive)

        # Update certificate status back to Active
        update_active_response = aws_client.iam.update_signing_certificate(
            UserName=user_name, CertificateId=cert_id, Status="Active"
        )
        snapshot.match("update-certificate-active", update_active_response)

        # Verify status changed back
        list_after_active = aws_client.iam.list_signing_certificates(UserName=user_name)
        snapshot.match("list-certificates-after-active", list_after_active)

        # Delete signing certificate
        delete_response = aws_client.iam.delete_signing_certificate(
            UserName=user_name, CertificateId=cert_id
        )
        snapshot.match("delete-certificate", delete_response)

        # Verify certificate is deleted
        list_after_delete = aws_client.iam.list_signing_certificates(UserName=user_name)
        snapshot.match("list-certificates-after-delete", list_after_delete)
        assert len(list_after_delete["Certificates"]) == 0

    @markers.aws.validated
    def test_signing_certificate_errors(self, aws_client, snapshot, create_user, cleanups):
        """Test error cases for signing certificate operations."""
        # Create a user
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user", create_user_response)

        # Generate valid certificates for testing
        cert_body_1 = create_certificate()
        cert_body_2 = create_certificate()
        cert_body_3 = create_certificate()

        # Try to upload certificate for non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.upload_signing_certificate(
                UserName="nonexistent-user", CertificateBody=cert_body_1
            )
        snapshot.match("upload-nonexistent-user-error", exc.value.response)

        # Try to list certificates for a non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.list_signing_certificates(UserName="nonexistent-user")
        snapshot.match("list-certificates-nonexistent-user-error", exc.value.response)

        # Try to delete certificates for a non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_signing_certificate(
                UserName="nonexistent-user", CertificateId="NONEXISTENTCERTID12345678901"
            )
        snapshot.match("delete-certificate-nonexistent-user-error", exc.value.response)

        # Try to update certificates for a non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.update_signing_certificate(
                UserName="nonexistent-user",
                CertificateId="NONEXISTENTCERTID12345678901",
                Status="Inactive",
            )
        snapshot.match("update-certificate-nonexistent-user-error", exc.value.response)

        # Try to upload invalid certificate body
        with pytest.raises(ClientError) as exc:
            aws_client.iam.upload_signing_certificate(
                UserName=user_name, CertificateBody="invalid-certificate-body"
            )
        snapshot.match("upload-invalid-certificate-error", exc.value.response)

        # Try to update non-existent certificate
        with pytest.raises(ClientError) as exc:
            aws_client.iam.update_signing_certificate(
                UserName=user_name, CertificateId="NONEXISTENTCERTID12345678901", Status="Inactive"
            )
        snapshot.match("update-nonexistent-certificate-error", exc.value.response)

        # Try to delete non-existent certificate
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_signing_certificate(
                UserName=user_name, CertificateId="NONEXISTENTCERTID12345678901"
            )
        snapshot.match("delete-nonexistent-certificate-error", exc.value.response)

        # Upload two certificates (max per user is typically 2)
        upload_1 = aws_client.iam.upload_signing_certificate(
            UserName=user_name, CertificateBody=cert_body_1
        )
        snapshot.match("upload-certificate-1", upload_1)
        cleanups.append(
            lambda: aws_client.iam.delete_signing_certificate(
                UserName=user_name, CertificateId=upload_1["Certificate"]["CertificateId"]
            )
        )

        upload_2 = aws_client.iam.upload_signing_certificate(
            UserName=user_name, CertificateBody=cert_body_2
        )
        snapshot.match("upload-certificate-2", upload_2)
        cleanups.append(
            lambda: aws_client.iam.delete_signing_certificate(
                UserName=user_name, CertificateId=upload_2["Certificate"]["CertificateId"]
            )
        )

        # Try to upload a third certificate (should exceed limit)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.upload_signing_certificate(
                UserName=user_name, CertificateBody=cert_body_3
            )
        snapshot.match("upload-exceeds-limit-error", exc.value.response)
