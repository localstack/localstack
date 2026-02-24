"""
Store and entity definitions for IAM service.
"""

import dataclasses
from dataclasses import field

from localstack.aws.api.iam import (
    AccessKey,
    AccessKeyLastUsed,
    Group,
    LoginProfile,
    Policy,
    PolicyVersion,
    Role,
    ServiceSpecificCredential,
    User,
)
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


@dataclasses.dataclass
class AwsManagedPolicy:
    """Tracks account-specific state for AWS managed policies (currently just attachment count)."""

    attachment_count: int = 0


@dataclasses.dataclass
class AccessKeyEntity:
    """Wrapper for AccessKey with last used tracking."""

    access_key: AccessKey  # UserName, AccessKeyId, Status, SecretAccessKey, CreateDate
    last_used: AccessKeyLastUsed | None = None


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
    access_keys: dict[str, AccessKeyEntity] = field(default_factory=dict)  # access_key_id -> entity


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


# Using CrossRegionAttributes since IAM is a global service
class IamStore(BaseStore):
    # Customer-managed policies keyed by ARN
    MANAGED_POLICIES: dict[str, ManagedPolicyEntity] = CrossRegionAttribute(default=dict)
    # Roles keyed by role name (unique per account)
    ROLES: dict[str, RoleEntity] = CrossRegionAttribute(default=dict)
    # Users keyed by user name (unique per account)
    USERS: dict[str, UserEntity] = CrossRegionAttribute(default=dict)
    # Groups keyed by group name (unique per account)
    # Using CrossRegionAttribute since IAM is a global service
    GROUPS: dict[str, GroupEntity] = CrossRegionAttribute(default=dict)
    # Attachment counts for AWS managed policies, keyed by the policy ARN.
    # A key is present only when the policy has been attached at least once.
    AWS_MANAGED_POLICIES: dict[str, AwsManagedPolicy] = CrossRegionAttribute(default=dict)
    # Index for efficient access key lookups: access_key_id -> user_name
    ACCESS_KEY_INDEX: dict[str, str] = CrossRegionAttribute(default=dict)


# validate=False because IAM is a global service without region-specific endpoints
iam_stores = AccountRegionBundle("iam", IamStore, validate=False)
