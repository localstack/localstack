from typing import TypedDict

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from localstack.aws.api.sts import Tag
from localstack.services.stores import AccountRegionBundle, BaseStore, CrossRegionAttribute


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
    # RSA signing key for JWT-based web identity tokens (lazily generated, ephemeral)
    signing_key: RSAPrivateKey | None = CrossRegionAttribute(default=lambda: None)
    # EC P-384 signing key for ES384 JWT tokens (lazily generated, ephemeral)
    ec_signing_key: EllipticCurvePrivateKey | None = CrossRegionAttribute(default=lambda: None)


sts_stores = AccountRegionBundle("sts", STSStore)
