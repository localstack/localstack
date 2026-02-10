import secrets
import string
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TypedDict

from localstack.aws.api.sts import Tag
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
    CrossRegionAttribute,
)


class SessionConfig(TypedDict):
    # <lower-case-tag-key> => {"Key": <case-preserved-tag-key>, "Value": <tag-value>}
    tags: dict[str, Tag]
    # list of lowercase transitive tag keys
    transitive_tags: list[str]
    # other stored context variables
    iam_context: dict[str, str | list[str]]


class STSStore(BaseStore):
    # maps access key ids to tagging config for the session they belong to
    sessions: dict[str, SessionConfig] = CrossRegionAttribute(default=dict)


sts_stores = AccountRegionBundle("sts", STSStore)


# Constants
DEFAULT_SESSION_DURATION = 3600  # 1 hour
MIN_SESSION_DURATION = 900  # 15 minutes
MAX_SESSION_DURATION = 43200  # 12 hours
MAX_ROLE_SESSION_NAME_LENGTH = 64
MAX_FEDERATION_TOKEN_POLICY_LENGTH = 2048


def generate_access_key_id(prefix: str = "ASIA") -> str:
    """Generate a temporary access key ID (starts with ASIA for temp credentials)."""
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(16))
    return f"{prefix}{suffix}"


def generate_secret_access_key() -> str:
    """Generate a secret access key (40 characters)."""
    chars = string.ascii_letters + string.digits + "+/"
    return "".join(secrets.choice(chars) for _ in range(40))


def generate_session_token() -> str:
    """Generate a session token."""
    chars = string.ascii_letters + string.digits + "+/="
    prefix = "FQoGZXIvYXdzE"
    body = "".join(secrets.choice(chars) for _ in range(343))
    return f"{prefix}{body}"


def generate_role_id() -> str:
    """Generate an assumed role ID (starts with AROA)."""
    chars = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(chars) for _ in range(17))
    return f"AROA{suffix}"


@dataclass
class TemporaryCredentials:
    """Represents a set of temporary credentials."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    account_id: str
    arn: str
    user_id: str
    source_identity: str | None = None

    def is_expired(self) -> bool:
        """Check if the credentials have expired."""
        return datetime.now(UTC) > self.expiration


class STSStoreV2(BaseStore):
    """STS store for v2 provider."""

    # Maps access_key_id -> TemporaryCredentials (shared across all accounts/regions)
    credentials: dict[str, TemporaryCredentials] = CrossAccountAttribute(default=dict)

    # Maps access_key_id -> SessionConfig for tag propagation (same pattern as original)
    sessions: dict[str, SessionConfig] = CrossAccountAttribute(default=dict)


sts_stores_v2 = AccountRegionBundle("sts", STSStoreV2)
