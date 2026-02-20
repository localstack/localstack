"""
Store and entity definitions for IAM service.
"""

import dataclasses
from dataclasses import field

from localstack.aws.api.iam import Policy, PolicyVersion, Role
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
class ManagedPolicyEntity:
    """Wrapper for Policy with version tracking."""

    policy: Policy  # From localstack.aws.api.iam
    versions: dict[str, PolicyVersion] = field(default_factory=dict)  # version_id -> PolicyVersion
    next_version_num: int = 2  # Next version number (v1 is created with policy)


class IamStore(BaseStore):
    # Customer-managed policies keyed by ARN
    # Using CrossRegionAttribute since IAM is a global service (policies are account-wide)
    MANAGED_POLICIES: dict[str, ManagedPolicyEntity] = CrossRegionAttribute(default=dict)
    # Roles keyed by role name (unique per account)
    # Using CrossRegionAttribute since IAM is a global service
    ROLES: dict[str, RoleEntity] = CrossRegionAttribute(default=dict)


# validate=False because IAM is a global service without region-specific endpoints
iam_stores = AccountRegionBundle("iam", IamStore, validate=False)
