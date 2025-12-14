"""
Data models and store for the native IAM provider.

This module defines the state management layer for IAM resources using the
AccountRegionBundle pattern with CrossRegionAttribute for global IAM semantics.
"""

import json
import logging
import os
import secrets
import string
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
)
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# =============================================================================
# AWS Managed Policies Lazy Loading
# =============================================================================

# Thread-safe lock for lazy loading
_aws_managed_policies_lock = threading.Lock()
_aws_managed_policies_loaded = False
_aws_managed_policies_cache: dict[str, "ManagedPolicy"] = {}


def _load_aws_managed_policies() -> dict[str, "ManagedPolicy"]:
    """
    Load AWS managed policies from the JSON file.

    This function is called lazily when AWS managed policies are first accessed.
    The policies are cached in memory for subsequent accesses.

    :return: Dictionary mapping policy ARN to ManagedPolicy object
    """
    global _aws_managed_policies_loaded, _aws_managed_policies_cache

    if _aws_managed_policies_loaded:
        return _aws_managed_policies_cache

    with _aws_managed_policies_lock:
        # Double-check after acquiring lock
        if _aws_managed_policies_loaded:
            return _aws_managed_policies_cache

        policies_file = os.path.join(os.path.dirname(__file__), "aws_managed_policies.json")

        if not os.path.exists(policies_file):
            LOG.warning("AWS managed policies file not found: %s", policies_file)
            _aws_managed_policies_loaded = True
            return _aws_managed_policies_cache

        try:
            with open(policies_file, "r") as f:
                raw_policies = json.load(f)

            for policy_name, policy_data in raw_policies.items():
                arn = policy_data.get("Arn", f"arn:aws:iam::aws:policy/{policy_name}")
                document = policy_data.get("Document", {})

                # Create policy version
                version = PolicyVersion(
                    version_id=policy_data.get("DefaultVersionId", "v1"),
                    document=json.dumps(document) if isinstance(document, dict) else document,
                    is_default_version=True,
                    create_date=datetime.fromisoformat(
                        policy_data.get("CreateDate", "2015-02-06T18:39:46+00:00").replace(
                            "+00:00", ""
                        )
                    ),
                )

                # Parse dates
                create_date = policy_data.get("CreateDate", "2015-02-06T18:39:46+00:00")
                update_date = policy_data.get("UpdateDate", create_date)

                # Create managed policy
                policy = ManagedPolicy(
                    policy_name=policy_name,
                    policy_id=f"ANPA{policy_name[:16].upper()}",  # Generate deterministic ID
                    arn=arn,
                    path=policy_data.get("Path", "/"),
                    create_date=datetime.fromisoformat(create_date.replace("+00:00", "")),
                    update_date=datetime.fromisoformat(update_date.replace("+00:00", "")),
                    description=f"AWS managed policy: {policy_name}",
                    default_version_id=policy_data.get("DefaultVersionId", "v1"),
                    is_attachable=True,
                    versions=[version],
                )

                _aws_managed_policies_cache[arn] = policy

            LOG.debug("Loaded %d AWS managed policies", len(_aws_managed_policies_cache))

        except Exception as e:
            LOG.error("Failed to load AWS managed policies: %s", e)

        _aws_managed_policies_loaded = True
        return _aws_managed_policies_cache


def get_aws_managed_policies() -> dict[str, "ManagedPolicy"]:
    """
    Get all AWS managed policies (lazily loaded).

    :return: Dictionary mapping policy ARN to ManagedPolicy object
    """
    return _load_aws_managed_policies()


def get_aws_managed_policy(arn: str) -> Optional["ManagedPolicy"]:
    """
    Get a specific AWS managed policy by ARN.

    :param arn: The policy ARN
    :return: ManagedPolicy object or None if not found
    """
    policies = _load_aws_managed_policies()
    return policies.get(arn)

# =============================================================================
# ID Generation Utilities
# =============================================================================

# AWS IAM ID prefixes
# See: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
ID_PREFIX_USER = "AIDA"  # IAM user
ID_PREFIX_ROLE = "AROA"  # IAM role
ID_PREFIX_GROUP = "AGPA"  # IAM group
ID_PREFIX_POLICY = "ANPA"  # Customer managed policy
ID_PREFIX_INSTANCE_PROFILE = "AIPA"  # Instance profile
ID_PREFIX_ACCESS_KEY = "AKIA"  # Access key (AWS format)
ID_PREFIX_ACCESS_KEY_LOCALSTACK = "LKIA"  # Access key (LocalStack format)
ID_PREFIX_SERVER_CERT = "ASCA"  # Server certificate
ID_PREFIX_SSH_KEY = "APKA"  # SSH public key
ID_PREFIX_MFA = "mfa/"  # MFA device (used in ARN path)


def _generate_id(prefix: str, length: int = 16) -> str:
    """
    Generate an AWS-style ID with the given prefix.

    AWS IDs typically consist of a 4-character prefix followed by
    alphanumeric characters (uppercase letters and digits).

    :param prefix: The ID prefix (e.g., 'AIDA', 'AROA')
    :param length: The length of the random suffix (default: 16)
    :return: Generated ID string
    """
    charset = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(charset) for _ in range(length))
    return f"{prefix}{suffix}"


def generate_user_id() -> str:
    """Generate a unique IAM user ID (AIDA + 16 alphanumeric)."""
    return _generate_id(ID_PREFIX_USER)


def generate_role_id() -> str:
    """Generate a unique IAM role ID (AROA + 16 alphanumeric)."""
    return _generate_id(ID_PREFIX_ROLE)


def generate_group_id() -> str:
    """Generate a unique IAM group ID (AGPA + 16 alphanumeric)."""
    return _generate_id(ID_PREFIX_GROUP)


def generate_policy_id() -> str:
    """Generate a unique IAM managed policy ID (ANPA + 16 alphanumeric)."""
    return _generate_id(ID_PREFIX_POLICY)


def generate_instance_profile_id() -> str:
    """Generate a unique instance profile ID (AIPA + 16 alphanumeric)."""
    return _generate_id(ID_PREFIX_INSTANCE_PROFILE)


def generate_access_key_id(use_localstack_prefix: bool = False) -> str:
    """
    Generate a unique access key ID.

    :param use_localstack_prefix: If True, use LKIA prefix instead of AKIA
    :return: Generated access key ID
    """
    prefix = ID_PREFIX_ACCESS_KEY_LOCALSTACK if use_localstack_prefix else ID_PREFIX_ACCESS_KEY
    return _generate_id(prefix)


def generate_secret_access_key() -> str:
    """
    Generate a secret access key (40 characters, base64-like).

    AWS secret access keys are 40 characters using base64 charset.
    """
    charset = string.ascii_letters + string.digits + "+/"
    return "".join(secrets.choice(charset) for _ in range(40))


def generate_service_specific_credential_id(account_id: str) -> str:
    """
    Generate a service-specific credential ID.

    These IDs have the prefix ACCA and encode the account ID similar to access keys.
    Format: ACCA + encoded_account_part + random_suffix (21 chars total)

    :param account_id: The AWS account ID
    :return: Generated credential ID
    """
    import base64

    # AWS role alphabet used for encoding
    AWS_ROLE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    ACCOUNT_OFFSET = 549755813888  # Used by AWS to encode account IDs

    account_id_nr = int(account_id)
    id_with_offset = account_id_nr // 2 + ACCOUNT_OFFSET

    # Convert to bytes and base32 encode
    account_bytes = int.to_bytes(id_with_offset, byteorder="big", length=5)
    account_part = base64.b32encode(account_bytes).decode("utf-8")

    # Add middle character based on account ID parity
    if account_id_nr % 2:
        middle_char = secrets.choice(AWS_ROLE_ALPHABET[16:])
    else:
        middle_char = secrets.choice(AWS_ROLE_ALPHABET[:16])

    prefix = "ACCA"
    semi_fixed_part = prefix + account_part + middle_char

    # Generate random suffix to reach total length of 21
    charset = string.ascii_uppercase + string.digits
    suffix_length = 21 - len(semi_fixed_part)
    suffix = "".join(secrets.choice(charset) for _ in range(suffix_length))

    return semi_fixed_part + suffix


def generate_server_certificate_id() -> str:
    """Generate a unique server certificate ID (ASCA + 16 alphanumeric)."""
    return _generate_id(ID_PREFIX_SERVER_CERT)


def generate_ssh_public_key_id() -> str:
    """Generate a unique SSH public key ID (APKA + 16 alphanumeric)."""
    return _generate_id(ID_PREFIX_SSH_KEY)


def generate_certificate_id() -> str:
    """Generate a signing certificate ID (24 characters alphanumeric)."""
    return _generate_id("", length=24)


def generate_credential_id() -> str:
    """Generate a service-specific credential ID (20 alphanumeric)."""
    return _generate_id("ACCA", length=17)  # ACCA + 17 = 21 total


def generate_deletion_task_id() -> str:
    """Generate a deletion task ID for service-linked roles."""
    return f"task/{short_uid()}-{short_uid()}"


# =============================================================================
# ARN Construction Utilities
# =============================================================================


def build_user_arn(account_id: str, path: str, user_name: str) -> str:
    """Build an IAM user ARN."""
    # Normalize path to ensure proper format
    if not path.startswith("/"):
        path = f"/{path}"
    if not path.endswith("/"):
        path = f"{path}/"
    if path == "//":
        path = "/"
    return f"arn:aws:iam::{account_id}:user{path}{user_name}"


def build_role_arn(account_id: str, path: str, role_name: str) -> str:
    """Build an IAM role ARN."""
    if not path.startswith("/"):
        path = f"/{path}"
    if not path.endswith("/"):
        path = f"{path}/"
    if path == "//":
        path = "/"
    return f"arn:aws:iam::{account_id}:role{path}{role_name}"


def build_group_arn(account_id: str, path: str, group_name: str) -> str:
    """Build an IAM group ARN."""
    if not path.startswith("/"):
        path = f"/{path}"
    if not path.endswith("/"):
        path = f"{path}/"
    if path == "//":
        path = "/"
    return f"arn:aws:iam::{account_id}:group{path}{group_name}"


def build_policy_arn(account_id: str, path: str, policy_name: str) -> str:
    """Build an IAM managed policy ARN."""
    if not path.startswith("/"):
        path = f"/{path}"
    if not path.endswith("/"):
        path = f"{path}/"
    if path == "//":
        path = "/"
    return f"arn:aws:iam::{account_id}:policy{path}{policy_name}"


def build_instance_profile_arn(account_id: str, path: str, profile_name: str) -> str:
    """Build an instance profile ARN."""
    if not path.startswith("/"):
        path = f"/{path}"
    if not path.endswith("/"):
        path = f"{path}/"
    if path == "//":
        path = "/"
    return f"arn:aws:iam::{account_id}:instance-profile{path}{profile_name}"


def build_mfa_device_arn(account_id: str, device_name: str) -> str:
    """Build an MFA device ARN (serial number)."""
    return f"arn:aws:iam::{account_id}:mfa/{device_name}"


def build_saml_provider_arn(account_id: str, provider_name: str) -> str:
    """Build a SAML provider ARN."""
    return f"arn:aws:iam::{account_id}:saml-provider/{provider_name}"


def build_oidc_provider_arn(account_id: str, provider_url: str) -> str:
    """
    Build an OIDC provider ARN.

    Note: The URL should not include the protocol (https://).
    """
    # Remove protocol if present
    url = provider_url.replace("https://", "").replace("http://", "")
    return f"arn:aws:iam::{account_id}:oidc-provider/{url}"


def build_server_certificate_arn(account_id: str, path: str, cert_name: str) -> str:
    """Build a server certificate ARN."""
    if not path.startswith("/"):
        path = f"/{path}"
    if not path.endswith("/"):
        path = f"{path}/"
    if path == "//":
        path = "/"
    return f"arn:aws:iam::{account_id}:server-certificate{path}{cert_name}"


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class LoginProfile:
    """Console access credentials for a user."""

    user_name: str
    create_date: datetime = field(default_factory=datetime.utcnow)
    password_reset_required: bool = False
    # Note: Password is not stored in the model for security reasons
    # In a real implementation, a hashed password would be stored


@dataclass
class RoleLastUsed:
    """Role usage tracking information."""

    last_used_date: Optional[datetime] = None
    region: Optional[str] = None


@dataclass
class AccessKeyLastUsed:
    """Tracking information for access key usage."""

    access_key_id: str
    last_used_date: Optional[datetime] = None
    service_name: Optional[str] = None
    region: Optional[str] = None


@dataclass
class PolicyVersion:
    """A specific version of a managed policy."""

    version_id: str
    document: str
    is_default_version: bool = False
    create_date: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PermissionsBoundary:
    """Permission boundary attached to a user or role."""

    permissions_boundary_arn: str
    permissions_boundary_type: str = "Policy"


@dataclass
class User:
    """IAM user identity that can authenticate and be assigned permissions."""

    user_name: str
    user_id: str
    arn: str
    path: str = "/"
    create_date: datetime = field(default_factory=datetime.utcnow)
    password_last_used: Optional[datetime] = None
    permission_boundary: Optional[PermissionsBoundary] = None
    tags: dict[str, str] = field(default_factory=dict)

    # Group membership (group names)
    groups: list[str] = field(default_factory=list)

    # Inline policies (policy_name -> policy_document)
    inline_policies: dict[str, str] = field(default_factory=dict)

    # Attached managed policy ARNs
    attached_policies: list[str] = field(default_factory=list)

    # Login profile for console access
    login_profile: Optional[LoginProfile] = None

    # MFA device serial numbers
    mfa_devices: list[str] = field(default_factory=list)

    # Access key IDs
    access_keys: list[str] = field(default_factory=list)

    # Service-specific credential IDs
    service_specific_credentials: list[str] = field(default_factory=list)

    # SSH public key IDs
    ssh_public_keys: list[str] = field(default_factory=list)

    # Signing certificate IDs
    signing_certificates: list[str] = field(default_factory=list)


@dataclass
class Role:
    """IAM role that can be assumed by trusted entities."""

    role_name: str
    role_id: str
    arn: str
    assume_role_policy_document: str
    path: str = "/"
    create_date: datetime = field(default_factory=datetime.utcnow)
    description: Optional[str] = None
    max_session_duration: int = 3600  # 1 hour default
    permission_boundary: Optional[PermissionsBoundary] = None
    tags: dict[str, str] = field(default_factory=dict)

    # Inline policies (policy_name -> policy_document)
    inline_policies: dict[str, str] = field(default_factory=dict)

    # Attached managed policy ARNs
    attached_policies: list[str] = field(default_factory=list)

    # Instance profile names this role belongs to
    instance_profiles: list[str] = field(default_factory=list)

    # Last usage information
    last_used: Optional[RoleLastUsed] = None

    # Service-linked role fields
    is_service_linked: bool = False
    service_name: Optional[str] = None


@dataclass
class Group:
    """Collection of IAM users for bulk permission assignment."""

    group_name: str
    group_id: str
    arn: str
    path: str = "/"
    create_date: datetime = field(default_factory=datetime.utcnow)

    # Member user names
    users: list[str] = field(default_factory=list)

    # Inline policies (policy_name -> policy_document)
    inline_policies: dict[str, str] = field(default_factory=dict)

    # Attached managed policy ARNs
    attached_policies: list[str] = field(default_factory=list)

    # Tags (added in recent AWS updates)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class ManagedPolicy:
    """Standalone policy that can be attached to multiple principals."""

    policy_name: str
    policy_id: str
    arn: str
    path: str = "/"
    create_date: datetime = field(default_factory=datetime.utcnow)
    update_date: datetime = field(default_factory=datetime.utcnow)
    description: Optional[str] = None
    default_version_id: str = "v1"
    is_attachable: bool = True
    tags: dict[str, str] = field(default_factory=dict)

    # Policy versions (max 5)
    versions: list[PolicyVersion] = field(default_factory=list)

    # Tracking which entities have this policy attached
    # (computed dynamically, not persisted)
    attachment_count: int = 0

    def get_default_version(self) -> Optional[PolicyVersion]:
        """
        Get the default policy version.

        :return: The PolicyVersion marked as default, or None if no default exists
        """
        for version in self.versions:
            if version.is_default_version:
                return version
        return None

    def get_version(self, version_id: str) -> Optional[PolicyVersion]:
        """
        Get a specific policy version by ID.

        :param version_id: The version identifier (e.g., 'v1', 'v2')
        :return: The PolicyVersion with the given ID, or None if not found
        """
        for version in self.versions:
            if version.version_id == version_id:
                return version
        return None


@dataclass
class InstanceProfile:
    """Container for roles that can be assumed by EC2 instances."""

    instance_profile_name: str
    instance_profile_id: str
    arn: str
    path: str = "/"
    create_date: datetime = field(default_factory=datetime.utcnow)
    tags: dict[str, str] = field(default_factory=dict)

    # Role names (max 1 in AWS)
    roles: list[str] = field(default_factory=list)


@dataclass
class AccessKey:
    """Credential pair for programmatic AWS access."""

    access_key_id: str
    secret_access_key: str
    user_name: str
    status: str = "Active"  # Active or Inactive
    create_date: datetime = field(default_factory=datetime.utcnow)


@dataclass
class VirtualMFADevice:
    """Software-based MFA device."""

    serial_number: str  # ARN format
    base32_string_seed: Optional[str] = None  # Only returned on create
    qr_code_png: Optional[bytes] = None  # Only returned on create
    enable_date: Optional[datetime] = None
    user_arn: Optional[str] = None  # Set on EnableMfaDevice
    user_name: Optional[str] = None  # Set on EnableMfaDevice
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class SAMLProvider:
    """SAML 2.0 identity provider for federation."""

    arn: str
    name: str
    saml_metadata_document: str
    create_date: datetime = field(default_factory=datetime.utcnow)
    valid_until: Optional[datetime] = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class OIDCProvider:
    """OpenID Connect identity provider for web identity federation."""

    arn: str
    url: str
    create_date: datetime = field(default_factory=datetime.utcnow)
    client_id_list: list[str] = field(default_factory=list)
    thumbprint_list: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class ServerCertificate:
    """SSL/TLS certificate for HTTPS."""

    server_certificate_name: str
    server_certificate_id: str
    arn: str
    path: str = "/"
    certificate_body: str = ""
    certificate_chain: Optional[str] = None
    upload_date: datetime = field(default_factory=datetime.utcnow)
    expiration: Optional[datetime] = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class ServiceSpecificCredential:
    """Credentials for specific AWS services (CodeCommit, Cassandra)."""

    service_specific_credential_id: str
    user_name: str
    service_name: str
    service_user_name: str
    service_password: str  # Only returned on create/reset
    status: str = "Active"  # Active or Inactive
    create_date: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SSHPublicKey:
    """SSH public key for CodeCommit access."""

    ssh_public_key_id: str
    user_name: str
    ssh_public_key_body: str
    fingerprint: str
    status: str = "Active"  # Active or Inactive
    upload_date: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SigningCertificate:
    """X.509 signing certificate."""

    certificate_id: str
    user_name: str
    certificate_body: str
    status: str = "Active"  # Active or Inactive
    upload_date: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PasswordPolicy:
    """Account-level password requirements."""

    minimum_password_length: int = 6
    require_symbols: bool = False
    require_numbers: bool = False
    require_uppercase_characters: bool = False
    require_lowercase_characters: bool = False
    allow_users_to_change_password: bool = True
    expire_passwords: bool = False
    max_password_age: int = 0  # 0 means never
    password_reuse_prevention: int = 0  # 0 means no prevention
    hard_expiry: bool = False


@dataclass
class ServiceLinkedRoleDeletionTask:
    """Tracking deletion of service-linked roles."""

    task_id: str
    role_name: str
    status: str = "IN_PROGRESS"  # IN_PROGRESS, SUCCEEDED, FAILED, NOT_STARTED
    reason: Optional[str] = None
    create_date: datetime = field(default_factory=datetime.utcnow)


# =============================================================================
# IAM Store
# =============================================================================


class IamStore(BaseStore):
    """
    Store for IAM resources.

    Uses CrossRegionAttribute for all IAM resources because IAM is a global
    service in AWS - resources created in one region are visible in all regions.
    """

    # Principal resources (keyed by name)
    users: dict[str, User] = CrossRegionAttribute(default=dict)
    groups: dict[str, Group] = CrossRegionAttribute(default=dict)
    roles: dict[str, Role] = CrossRegionAttribute(default=dict)
    instance_profiles: dict[str, InstanceProfile] = CrossRegionAttribute(default=dict)

    # Customer managed policies (keyed by ARN)
    policies: dict[str, ManagedPolicy] = CrossRegionAttribute(default=dict)

    # Credentials (keyed by ID)
    access_keys: dict[str, AccessKey] = CrossRegionAttribute(default=dict)
    access_key_last_used: dict[str, AccessKeyLastUsed] = CrossRegionAttribute(default=dict)

    # MFA devices (keyed by serial number/ARN)
    virtual_mfa_devices: dict[str, VirtualMFADevice] = CrossRegionAttribute(default=dict)

    # Identity providers (keyed by ARN)
    saml_providers: dict[str, SAMLProvider] = CrossRegionAttribute(default=dict)
    oidc_providers: dict[str, OIDCProvider] = CrossRegionAttribute(default=dict)

    # Certificates (keyed by name)
    server_certificates: dict[str, ServerCertificate] = CrossRegionAttribute(default=dict)

    # Service-specific credentials (keyed by credential ID)
    service_specific_credentials: dict[str, ServiceSpecificCredential] = CrossRegionAttribute(
        default=dict
    )

    # SSH public keys (keyed by key ID)
    ssh_public_keys: dict[str, SSHPublicKey] = CrossRegionAttribute(default=dict)

    # Signing certificates (keyed by certificate ID)
    signing_certificates: dict[str, SigningCertificate] = CrossRegionAttribute(default=dict)

    # Account settings
    account_aliases: list[str] = CrossRegionAttribute(default=list)
    password_policy: Optional[PasswordPolicy] = CrossRegionAttribute(default=None)

    # Service-linked role deletion tasks (keyed by task ID)
    slr_deletion_tasks: dict[str, ServiceLinkedRoleDeletionTask] = CrossRegionAttribute(
        default=dict
    )

    # Credential report storage
    _credential_report: Optional[bytes] = CrossRegionAttribute(default=None)
    _credential_report_generated: Optional[datetime] = CrossRegionAttribute(default=None)

    # Index for looking up access keys by user
    # This is rebuilt on state load
    _access_key_by_user: dict[str, list[str]] = CrossRegionAttribute(default=dict)

    def get_user(self, user_name: str) -> Optional[User]:
        """
        Get a user by name.

        :param user_name: The name of the IAM user
        :return: The User object if found, None otherwise
        """
        return self.users.get(user_name)

    def get_role(self, role_name: str) -> Optional[Role]:
        """
        Get a role by name.

        :param role_name: The name of the IAM role
        :return: The Role object if found, None otherwise
        """
        return self.roles.get(role_name)

    def get_group(self, group_name: str) -> Optional[Group]:
        """
        Get a group by name.

        :param group_name: The name of the IAM group
        :return: The Group object if found, None otherwise
        """
        return self.groups.get(group_name)

    def get_policy_by_arn(self, policy_arn: str) -> Optional[ManagedPolicy]:
        """
        Get a managed policy by ARN (customer or AWS managed).

        This method first checks customer-managed policies, then falls back
        to AWS managed policies (which are loaded lazily).

        :param policy_arn: The full ARN of the managed policy
        :return: The ManagedPolicy object if found, None otherwise
        """
        # Check customer policies first
        if policy_arn in self.policies:
            return self.policies[policy_arn]
        # Check AWS managed policies (lazy loaded)
        return get_aws_managed_policy(policy_arn)

    def get_access_key(self, access_key_id: str) -> Optional[AccessKey]:
        """
        Get an access key by ID.

        :param access_key_id: The access key ID (e.g., AKIA...)
        :return: The AccessKey object if found, None otherwise
        """
        return self.access_keys.get(access_key_id)

    def get_instance_profile(self, profile_name: str) -> Optional[InstanceProfile]:
        """
        Get an instance profile by name.

        :param profile_name: The name of the instance profile
        :return: The InstanceProfile object if found, None otherwise
        """
        return self.instance_profiles.get(profile_name)

    def rebuild_indexes(self) -> None:
        """
        Rebuild internal indexes after state load.

        Called by on_after_state_load() in the provider.
        """
        # Rebuild access key by user index
        self._access_key_by_user.clear()
        for key_id, key in self.access_keys.items():
            if key.user_name not in self._access_key_by_user:
                self._access_key_by_user[key.user_name] = []
            self._access_key_by_user[key.user_name].append(key_id)


# Global IAM store bundle
# Note: validate=False because IAM is a global service without regional endpoints
# in the AWS commercial partition. Requests come with region context but IAM
# data is shared across all regions via CrossRegionAttribute.
iam_stores = AccountRegionBundle("iam", IamStore, validate=False)
