"""
Store and entity definitions for IAM service.
"""

import dataclasses
from dataclasses import field

from localstack.aws.api.iam import Policy, PolicyVersion
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


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


# validate=False because IAM is a global service without region-specific endpoints
iam_stores = AccountRegionBundle("iam", IamStore, validate=False)
