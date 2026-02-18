import datetime
import logging

import pytest
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

LOG = logging.getLogger(__name__)

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


@pytest.fixture
def create_saml_provider(aws_client):
    """Factory fixture to create SAML providers with automatic cleanup."""
    provider_arns = []

    def _create(**kwargs):
        response = aws_client.iam.create_saml_provider(**kwargs)
        provider_arns.append(response["SAMLProviderArn"])
        return response

    yield _create

    for arn in provider_arns:
        try:
            aws_client.iam.delete_saml_provider(SAMLProviderArn=arn)
        except Exception:
            LOG.debug("Could not delete SAML provider '%s' during cleanup", arn)


@pytest.fixture
def create_virtual_mfa_device(aws_client):
    """Factory fixture to create virtual MFA devices with automatic cleanup."""
    created_devices = []

    def _create_device(*args, **kwargs):
        response = aws_client.iam.create_virtual_mfa_device(*args, **kwargs)
        serial_number = response["VirtualMFADevice"]["SerialNumber"]
        created_devices.append(serial_number)
        return response

    yield _create_device

    # Cleanup
    for serial_number in created_devices:
        try:
            # First try to deactivate if it was enabled for a user
            # List all MFA devices to see if this one is attached to a user
            devices = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")[
                "VirtualMFADevices"
            ]
            for device in devices:
                if device["SerialNumber"] == serial_number and "User" in device:
                    try:
                        aws_client.iam.deactivate_mfa_device(
                            UserName=device["User"]["UserName"],
                            SerialNumber=serial_number,
                        )
                    except ClientError:
                        LOG.debug(
                            "Could not deactivate MFA device %s during cleanup", serial_number
                        )
            # Now delete the device
            aws_client.iam.delete_virtual_mfa_device(SerialNumber=serial_number)
        except ClientError as e:
            LOG.debug("Could not delete MFA device %s during cleanup: %s", serial_number, e)


@pytest.fixture
def create_oidc_provider(aws_client):
    """Factory fixture to create OIDC providers with automatic cleanup."""
    provider_arns = []

    def _create(**kwargs):
        response = aws_client.iam.create_open_id_connect_provider(**kwargs)
        provider_arns.append(response["OpenIDConnectProviderArn"])
        return response

    yield _create

    for arn in provider_arns:
        try:
            aws_client.iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        except Exception:
            LOG.debug("Could not delete OIDC provider '%s' during cleanup", arn)
