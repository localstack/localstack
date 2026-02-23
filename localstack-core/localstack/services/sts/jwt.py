"""JWT utility functions for STS Web Identity Token support.

Supports RS256 (RSA PKCS1v15 + SHA-256) and ES384 (ECDSA P-384).
"""

import time
from datetime import UTC, datetime

from joserfc import jwt
from joserfc.jwk import ECKey, RSAKey

# https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html#API_GetWebIdentityToken_RequestParameters
SUPPORTED_ALGORITHMS = {"RS256", "ES384"}


def generate_rsa_signing_key() -> RSAKey:
    """Generate a new RSA 2048-bit private key for JWT signing."""
    return RSAKey.generate_key(2048, auto_kid=True)


def generate_ec_signing_key() -> ECKey:
    """Generate a new EC P-384 private key for JWT signing."""
    return ECKey.generate_key("P-384", auto_kid=True)


def public_key_to_jwk(key: RSAKey | ECKey) -> dict[str, str | list[str]]:
    """Export a public key as a JWK dict with kid, use, and alg fields."""
    alg = "ES384" if isinstance(key, ECKey) else "RS256"
    return key.as_dict(private=False, use="sig", alg=alg)


def create_jwt(
    private_key: RSAKey | ECKey,
    issuer: str,
    subject: str,
    audience: str | list[str],
    duration_seconds: int = 3600,
    algorithm: str = "RS256",
    additional_claims: dict[str, object] | None = None,
) -> tuple[str, datetime]:
    """Create a signed JWT token.

    Returns a tuple of (token_string, expiration_datetime).
    """
    now = int(time.time())
    exp = now + duration_seconds
    expiration = datetime.fromtimestamp(exp, tz=UTC)

    header = {"alg": algorithm, "typ": "JWT", "kid": private_key.kid}
    claims: dict[str, object] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": exp,
    }
    if additional_claims:
        claims = {**claims, **additional_claims}

    token = jwt.encode(header, claims, private_key, algorithms=[algorithm])
    return token, expiration
