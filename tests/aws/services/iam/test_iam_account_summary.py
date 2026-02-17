"""
Tests for IAM GetAccountSummary operation.

Migrated from moto: tests/test_iam/test_iam.py
- test_get_account_summary()
"""

import datetime
import json
import logging

import pyotp
import pytest
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

MOCK_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Action": "s3:ListBucket", "Resource": "*", "Effect": "Allow"}],
    }
)

ASSUME_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

# SAML metadata template for SAML provider creation
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
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://test-idp.example.com/saml/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


def generate_saml_metadata():
    """Generate valid SAML metadata with a real X.509 certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_base64 = (
        cert_pem.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "")
    )
    return SAML_METADATA_TEMPLATE.format(certificate=cert_base64).replace("\n", "")


def generate_server_certificate():
    """Generate a valid server certificate and private key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
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
        .sign(private_key, hashes.SHA256())
    )
    cert_body = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return cert_body, private_key_pem


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


@pytest.fixture
def create_virtual_mfa_device(aws_client):
    """Factory fixture to create virtual MFA devices with automatic cleanup."""
    serial_numbers = []

    def _create(**kwargs):
        response = aws_client.iam.create_virtual_mfa_device(**kwargs)
        serial_numbers.append(response["VirtualMFADevice"]["SerialNumber"])
        return response

    yield _create

    for serial in serial_numbers:
        try:
            # First check if device is assigned to a user and deactivate
            devices = aws_client.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")[
                "VirtualMFADevices"
            ]
            for device in devices:
                if device["SerialNumber"] == serial and "User" in device:
                    try:
                        aws_client.iam.deactivate_mfa_device(
                            UserName=device["User"]["UserName"],
                            SerialNumber=serial,
                        )
                    except ClientError:
                        LOG.debug("Could not deactivate MFA device %s during cleanup", serial)
            aws_client.iam.delete_virtual_mfa_device(SerialNumber=serial)
        except Exception:
            LOG.debug("Could not delete MFA device '%s' during cleanup", serial)


@pytest.fixture
def create_server_certificate(aws_client):
    """Factory fixture to upload server certificates with automatic cleanup."""
    cert_names = []

    def _create(**kwargs):
        response = aws_client.iam.upload_server_certificate(**kwargs)
        cert_names.append(kwargs["ServerCertificateName"])
        return response

    yield _create

    for name in cert_names:
        try:
            aws_client.iam.delete_server_certificate(ServerCertificateName=name)
        except Exception:
            LOG.debug("Could not delete server certificate '%s' during cleanup", name)


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


# Quota keys that are consistent across accounts
QUOTA_KEYS = [
    "GroupPolicySizeQuota",
    "InstanceProfilesQuota",
    "GroupsPerUserQuota",
    "AttachedPoliciesPerUserQuota",
    "PoliciesQuota",
    "AccessKeysPerUserQuota",
    "AssumeRolePolicySizeQuota",
    "PolicyVersionsInUseQuota",
    "VersionsPerPolicyQuota",
    "AttachedPoliciesPerGroupQuota",
    "PolicySizeQuota",
    "UsersQuota",
    "ServerCertificatesQuota",
    "UserPolicySizeQuota",
    "RolesQuota",
    "SigningCertificatesPerUserQuota",
    "RolePolicySizeQuota",
    "AttachedPoliciesPerRoleQuota",
    "GroupsQuota",
]


class TestGetAccountSummary:
    """Tests for IAM GetAccountSummary API."""

    @markers.aws.validated
    def test_get_account_summary_quota_values(self, aws_client, snapshot):
        """Test that account summary returns expected quota values.

        Counter values (Users, Groups, etc.) vary based on account state,
        so we only snapshot the quota values which are consistent.
        """
        snapshot.add_transformer(snapshot.transform.iam_api())

        result = aws_client.iam.get_account_summary()

        # Extract only quota values for snapshot (counters vary by account)
        quota_values = {key: result["SummaryMap"][key] for key in QUOTA_KEYS}
        snapshot.match("account-summary-quotas", {"SummaryMap": quota_values})

    @markers.aws.validated
    def test_get_account_summary_with_resources(
        self,
        aws_client,
        snapshot,
        create_user,
        create_group,
        create_role,
        create_policy,
        create_instance_profile,
        create_oidc_provider,
        create_virtual_mfa_device,
        create_server_certificate,
        create_saml_provider,
        cleanups,
    ):
        """Test that account summary counters change after creating resources.

        This test verifies that the counters change appropriately when resources
        are created. We capture initial state, create resources, and verify the
        delta matches expectations.
        """
        snapshot.add_transformer(snapshot.transform.iam_api())

        # Get initial state
        initial_summary = aws_client.iam.get_account_summary()["SummaryMap"]

        # Create resources
        user_name = f"user-{short_uid()}"
        group_name = f"group-{short_uid()}"
        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        profile_name = f"ip-{short_uid()}"
        mfa_name = f"mfa-{short_uid()}"
        cert_name = f"cert-{short_uid()}"
        saml_name = f"saml-{short_uid()}"
        oidc_url = f"https://oidc-{short_uid()}.example.com"

        # Create user
        create_user(UserName=user_name)

        # Create group
        create_group(GroupName=group_name)

        # Create role
        create_role(RoleName=role_name, AssumeRolePolicyDocument=ASSUME_ROLE_POLICY)

        # Create policy
        policy_response = create_policy(PolicyName=policy_name, PolicyDocument=MOCK_POLICY)
        policy_arn = policy_response["Policy"]["Arn"]

        # Attach policy to role (increases policy versions in use)
        aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

        # Create instance profile
        create_instance_profile(InstanceProfileName=profile_name)

        # Create OIDC provider
        create_oidc_provider(Url=oidc_url, ThumbprintList=["a" * 40])

        # Create SAML provider
        saml_metadata = generate_saml_metadata()
        create_saml_provider(Name=saml_name, SAMLMetadataDocument=saml_metadata)

        # Create virtual MFA device
        mfa_response = create_virtual_mfa_device(VirtualMFADeviceName=mfa_name)
        mfa_serial = mfa_response["VirtualMFADevice"]["SerialNumber"]

        # Enable MFA device for the user
        seed = mfa_response["VirtualMFADevice"]["Base32StringSeed"]
        totp = pyotp.TOTP(seed)
        current_time = datetime.datetime.now()
        code1 = totp.at(current_time, counter_offset=-1)
        code2 = totp.at(current_time)

        aws_client.iam.enable_mfa_device(
            UserName=user_name,
            SerialNumber=mfa_serial,
            AuthenticationCode1=code1,
            AuthenticationCode2=code2,
        )
        cleanups.append(
            lambda: aws_client.iam.deactivate_mfa_device(
                UserName=user_name, SerialNumber=mfa_serial
            )
        )

        # Create server certificate
        cert_body, private_key = generate_server_certificate()
        create_server_certificate(
            ServerCertificateName=cert_name,
            CertificateBody=cert_body,
            PrivateKey=private_key,
        )

        # Get updated summary
        updated_summary = aws_client.iam.get_account_summary()["SummaryMap"]

        # Calculate deltas - these should be deterministic
        deltas = {
            "Users": updated_summary["Users"] - initial_summary["Users"],
            "Groups": updated_summary["Groups"] - initial_summary["Groups"],
            "Roles": updated_summary["Roles"] - initial_summary["Roles"],
            "Policies": updated_summary["Policies"] - initial_summary["Policies"],
            "InstanceProfiles": updated_summary["InstanceProfiles"]
            - initial_summary["InstanceProfiles"],
            "Providers": updated_summary["Providers"] - initial_summary["Providers"],
            "MFADevices": updated_summary["MFADevices"] - initial_summary["MFADevices"],
            "MFADevicesInUse": updated_summary["MFADevicesInUse"]
            - initial_summary["MFADevicesInUse"],
            "ServerCertificates": updated_summary["ServerCertificates"]
            - initial_summary["ServerCertificates"],
        }

        snapshot.match("resource-deltas", deltas)
