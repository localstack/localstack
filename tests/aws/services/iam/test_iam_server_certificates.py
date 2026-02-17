"""
Tests for IAM Server Certificate operations.

Migrated from moto's test suite to LocalStack with snapshot testing for AWS parity validation.
"""

import datetime
import logging

import pytest
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# TODO remove after new IAM implementation of server certificates
pytestmark = pytest.mark.skip


def create_certificate_with_chain() -> tuple[str, str, str]:
    root_cert, root_key = root_certificate()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LocalStack"),
            x509.NameAttribute(NameOID.COMMON_NAME, "LS Tests Cert"),
        ]
    )

    # we only create a root key and a leaf here, no intermediate
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            # Our intermediate will be valid for ~3 years
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365 * 3)
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    return (
        root_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        leaf_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
    )


def root_certificate() -> tuple[Certificate, RSAPrivateKey]:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PyCA Docs Root CA"),
        ]
    )
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            # Our certificate will be valid for ~10 years
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365 * 10)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return root_cert, root_key


def root_certificate_as_string() -> tuple[str, str]:
    root_cert, root_key = root_certificate()
    return root_cert.public_bytes(serialization.Encoding.PEM).decode(
        "utf-8"
    ), root_key.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())
    snapshot.add_transformer(snapshot.transform.key_value("ServerCertificateName"))
    snapshot.add_transformer(snapshot.transform.key_value("ServerCertificateId"))
    # reference replacement does not work with big blobs
    snapshot.add_transformer(
        snapshot.transform.key_value("CertificateBody", reference_replacement=False)
    )
    snapshot.add_transformer(
        snapshot.transform.key_value("CertificateChain", reference_replacement=False)
    )


@pytest.fixture
def upload_server_certificate(aws_client):
    """Factory fixture to upload server certificates with automatic cleanup."""
    created_certs = []

    def _upload_cert(*args, **kwargs):
        response = aws_client.iam.upload_server_certificate(*args, **kwargs)
        created_certs.append(response["ServerCertificateMetadata"]["ServerCertificateName"])
        return response

    yield _upload_cert

    for cert_name in created_certs:
        try:
            aws_client.iam.delete_server_certificate(ServerCertificateName=cert_name)
        except ClientError as e:
            LOG.debug("Could not delete server certificate %s during cleanup: %s", cert_name, e)


class TestServerCertificate:
    """Tests for server certificate operations."""

    @markers.aws.validated
    @pytest.mark.parametrize("path", [None, "/", "/test-path/"])
    def test_server_certificate_lifecycle(
        self, aws_client, snapshot, upload_server_certificate, path
    ):
        """Test upload, list, get, and delete server certificate operations."""
        cert_name = f"cert-{short_uid()}"

        # Upload server certificate
        kwargs = {}
        if path is not None:
            kwargs["Path"] = path

        cert_body, private_key = root_certificate_as_string()
        upload_response = upload_server_certificate(
            ServerCertificateName=cert_name,
            CertificateBody=cert_body,
            PrivateKey=private_key,
            **kwargs,
        )
        snapshot.match("upload-certificate", upload_response)

        # List server certificates
        list_response = aws_client.iam.list_server_certificates()
        list_response["ServerCertificateMetadataList"] = [
            c
            for c in list_response["ServerCertificateMetadataList"]
            if c["ServerCertificateName"] == cert_name
        ]
        snapshot.match("list-certificates", list_response)

        # List with path prefix (if path specified)
        if path not in [None, "/"]:
            list_with_path = aws_client.iam.list_server_certificates(PathPrefix=path)
            snapshot.match("list-certificates-with-path", list_with_path)

        # Get server certificate
        get_response = aws_client.iam.get_server_certificate(ServerCertificateName=cert_name)
        snapshot.match("get-certificate", get_response)

        # Delete server certificate
        delete_response = aws_client.iam.delete_server_certificate(ServerCertificateName=cert_name)
        snapshot.match("delete-certificate", delete_response)

        # Verify certificate no longer exists
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_server_certificate(ServerCertificateName=cert_name)
        snapshot.match("get-deleted-certificate-error", exc.value.response)

    @markers.aws.validated
    def test_server_certificate_with_chain(self, aws_client, snapshot, upload_server_certificate):
        """Test uploading server certificate with certificate chain.

        Note: This test is LocalStack-only because AWS validates that the certificate
        chain properly signs the leaf certificate. Creating a valid chain requires
        generating matching CA certificates which is complex for testing purposes.
        """
        cert_name = f"cert-chain-{short_uid()}"

        # Upload server certificate with chain
        cert_chain, cert_body, private_key = create_certificate_with_chain()
        upload_response = upload_server_certificate(
            ServerCertificateName=cert_name,
            CertificateBody=cert_body,
            PrivateKey=private_key,
            CertificateChain=cert_chain,
        )
        snapshot.match("upload-certificate-with-chain", upload_response)

        # Get certificate and verify chain is returned
        get_response = aws_client.iam.get_server_certificate(ServerCertificateName=cert_name)
        snapshot.match("get-certificate-with-chain", get_response)

    @markers.aws.validated
    def test_server_certificate_errors(self, aws_client, snapshot, upload_server_certificate):
        """Test error cases for server certificate operations."""
        cert_name = f"cert-{short_uid()}"
        nonexistent_cert = "nonexistent-certificate"
        cert_body, private_key = root_certificate_as_string()

        # Try to get non-existent certificate
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_server_certificate(ServerCertificateName=nonexistent_cert)
        snapshot.match("get-nonexistent-certificate-error", exc.value.response)

        # Try to delete non-existent certificate
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_server_certificate(ServerCertificateName=nonexistent_cert)
        snapshot.match("delete-nonexistent-certificate-error", exc.value.response)

        # Upload a certificate first
        upload_response = upload_server_certificate(
            ServerCertificateName=cert_name,
            CertificateBody=cert_body,
            PrivateKey=private_key,
        )
        snapshot.match("upload-certificate", upload_response)

        # Try to upload duplicate certificate (same name)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.upload_server_certificate(
                ServerCertificateName=cert_name,
                CertificateBody=cert_body,
                PrivateKey=private_key,
            )
        snapshot.match("upload-duplicate-certificate-error", exc.value.response)
