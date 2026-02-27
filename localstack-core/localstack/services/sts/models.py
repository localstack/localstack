from dataclasses import dataclass, field
from datetime import UTC, datetime

from localstack.aws.api.sts import Tag
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
)

# Constants
DEFAULT_SESSION_DURATION = 3600  # 1 hour
MIN_SESSION_DURATION = 900  # 15 minutes
MAX_SESSION_DURATION = 43200  # 12 hours
MAX_ROLE_SESSION_NAME_LENGTH = 64
MAX_FEDERATION_TOKEN_POLICY_LENGTH = 2048


@dataclass
class TemporaryCredentials:
    """Represents a set of temporary credentials with session configuration."""

    # Credential fields
    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    account_id: str
    arn: str
    user_id: str
    source_identity: str | None = None

    # Session configuration fields (merged from SessionConfig)
    # <lower-case-tag-key> => {"Key": <case-preserved-tag-key>, "Value": <tag-value>}
    tags: dict[str, Tag] = field(default_factory=dict)
    # list of lowercase transitive tag keys
    transitive_tags: list[str] = field(default_factory=list)
    # other stored context variables
    iam_context: dict[str, str | list[str]] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if the credentials have expired."""
        return datetime.now(UTC) > self.expiration


class STSStore(BaseStore):
    """STS store for temporary credentials."""

    # Maps access_key_id -> TemporaryCredentials (shared across all accounts/regions)
    credentials: dict[str, TemporaryCredentials] = CrossAccountAttribute(default=dict)


sts_stores = AccountRegionBundle("sts", STSStore)
