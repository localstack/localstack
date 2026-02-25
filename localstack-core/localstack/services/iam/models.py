"""
Store and entity definitions for IAM service.
"""

import dataclasses
from dataclasses import field
from datetime import datetime

from localstack.aws.api.iam import (
    Group,
    InstanceProfile,
    LoginProfile,
    MFADevice,
    PasswordPolicy,
    Policy,
    PolicyVersion,
    Role,
    ServiceSpecificCredential,
    SSHPublicKey,
    User,
    VirtualMFADevice,
    clientIDListType,
    tagListType,
    thumbprintListType,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


@dataclasses.dataclass
class RoleEntity:
    """Wrapper for Role with inline policies and managed policy tracking."""

    role: Role  # From localstack.aws.api.iam
    inline_policies: dict[str, str] = field(default_factory=dict)  # policy_name -> document
    attached_policy_arns: list[str] = field(
        default_factory=list
    )  # ARNs of attached managed policies
    linked_service: str | None = None  # For service-linked roles


@dataclasses.dataclass
class SAMLProvider:
    arn: str
    name: str
    saml_metadata_document: str
    create_date: datetime = field(default_factory=datetime.utcnow)
    valid_until: datetime | None = None
    tags: tagListType = field(default_factory=list)


@dataclasses.dataclass
class UserEntity:
    """Wrapper for User with inline policies and managed policy tracking."""

    user: User  # From localstack.aws.api.iam
    inline_policies: dict[str, str] = field(
        default_factory=dict
    )  # policy_name -> document (URL-quoted)
    attached_policy_arns: list[str] = field(
        default_factory=list
    )  # ARNs of attached managed policies
    login_profile: LoginProfile | None = None  # Login profile for console access
    password: str | None = None  # Password for login profile (never in API responses)
    service_specific_credentials: list[ServiceSpecificCredential] = field(default_factory=list)
    ssh_public_keys: dict[str, SSHPublicKey] = field(default_factory=dict)  # key_id -> SSHPublicKey
    mfa_devices: list[str] = field(default_factory=list)


@dataclasses.dataclass
class ManagedPolicyEntity:
    """Wrapper for Policy with version tracking."""

    policy: Policy  # From localstack.aws.api.iam
    versions: dict[str, PolicyVersion] = field(default_factory=dict)  # version_id -> PolicyVersion
    next_version_num: int = 2  # Next version number (v1 is created with policy)


@dataclasses.dataclass
class GroupEntity:
    """Wrapper for Group with inline policies, managed policy tracking, and membership."""

    group: Group  # From localstack.aws.api.iam
    inline_policies: dict[str, str] = field(default_factory=dict)  # policy_name -> document
    attached_policy_arns: list[str] = field(
        default_factory=list
    )  # ARNs of attached managed policies
    member_user_names: list[str] = field(default_factory=list)  # User names in this group


@dataclasses.dataclass
class OIDCProvider:
    arn: str
    url: str
    create_date: datetime = field(default_factory=datetime.utcnow)
    client_id_list: clientIDListType = field(default_factory=list)
    thumbprint_list: thumbprintListType = field(default_factory=list)
    tags: tagListType = field(default_factory=list)


@dataclasses.dataclass
class InstanceProfileEntity:
    """Wrapper for InstanceProfile with role tracking."""

    instance_profile: InstanceProfile  # From localstack.aws.api.iam
    role_name: str | None = None  # Name of the attached role (max 1 role per profile)


@dataclasses.dataclass
class MFADeviceEntity:
    device_name: str
    path: str
    device: VirtualMFADevice | MFADevice
    user_name: str | None = None


class IamStore(BaseStore):
    # Customer-managed policies keyed by ARN
    # Using CrossRegionAttribute since IAM is a global service (policies are account-wide)
    MANAGED_POLICIES: dict[str, ManagedPolicyEntity] = CrossRegionAttribute(default=dict)
    # Roles keyed by role name (unique per account)
    # Using CrossRegionAttribute since IAM is a global service
    ROLES: dict[str, RoleEntity] = CrossRegionAttribute(default=dict)
    # Instance profiles keyed by profile name (unique per account)
    # Using CrossRegionAttribute since IAM is a global service
    INSTANCE_PROFILES: dict[str, InstanceProfileEntity] = CrossRegionAttribute(default=dict)
    # Users keyed by user name (unique per account)
    # Using CrossRegionAttribute since IAM is a global service
    USERS: dict[str, UserEntity] = CrossRegionAttribute(default=dict)
    # Groups keyed by group name (unique per account)
    # Using CrossRegionAttribute since IAM is a global service
    GROUPS: dict[str, GroupEntity] = CrossRegionAttribute(default=dict)

    PASSWORD_POLICY: PasswordPolicy | None = CrossRegionAttribute(default=None)

    # SAML providers: maps provider_arn -> SAMLProvider
    # Account-scoped (IAM is global within an account)
    SAML_PROVIDERS: dict[str, SAMLProvider] = CrossRegionAttribute(default=dict)

    # OIDC providers: maps provider_arn -> OIDCProvider
    # Account-scoped (IAM is global within an account)
    OIDC_PROVIDERS: dict[str, OIDCProvider] = CrossRegionAttribute(default=dict)

    # MFA devices assigned to users: maps serial_number -> list of MFADevice
    # Account-scoped (IAM is global within an account)
    MFA_DEVICES: dict[str, MFADeviceEntity] = CrossRegionAttribute(default=dict)


iam_stores = AccountRegionBundle("iam", IamStore, validate=False)
