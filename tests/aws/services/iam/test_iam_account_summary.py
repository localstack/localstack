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

from aws.services.iam.test_iam_server_certificates import root_certificate_as_string
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

# These are keys which can vary depending on the current state of the account. Basically everything except quotas
ACCOUNT_SPECIFIC_SUMMARY_KEYS = [
    "AccountPasswordPresent",
    "Groups",
    "InstanceProfiles",
    "MFADevices",
    "MFADevicesInUse",
    "Policies",
    "PolicyVersionsInUse",
    "Providers",
    "Roles",
    "ServerCertificates",
    "Users",
]


@pytest.fixture
def snapshot_transformers(snapshot):
    snapshot.add_transformer(snapshot.transform.iam_api())


class TestGetAccountSummary:
    """Tests for IAM GetAccountSummary API."""

    @markers.aws.validated
    def test_get_account_summary_format(self, aws_client, snapshot):
        """Test that account summary returns expected quota values.

        Counter values (Users, Groups, etc.) vary based on account state,
        so we only snapshot the quota values which are consistent.
        """
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value(key, reference_replacement=False)
                for key in ACCOUNT_SPECIFIC_SUMMARY_KEYS
            ]
        )

        result = aws_client.iam.get_account_summary()
        snapshot.match("transformed-summary", result)

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
        upload_server_certificate,
        create_saml_provider,
        saml_metadata,
        cleanups,
    ):
        """Test that account summary counters change after creating resources.

        This test verifies that the counters change appropriately when resources
        are created. We capture initial state, create resources, and verify the
        delta matches expectations.
        """
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
        cert_body, private_key = root_certificate_as_string()
        upload_server_certificate(
            ServerCertificateName=cert_name,
            CertificateBody=cert_body,
            PrivateKey=private_key,
        )

        # Get updated summary
        updated_summary = aws_client.iam.get_account_summary()["SummaryMap"]

        # Calculate deltas - these should be deterministic
        deltas = {}
        for key in ACCOUNT_SPECIFIC_SUMMARY_KEYS:
            deltas[key] = updated_summary[key] - initial_summary[key]

        snapshot.match("resource-deltas", deltas)
