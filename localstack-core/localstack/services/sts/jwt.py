"""JWT utility functions for STS Web Identity Token support.

Uses the ``cryptography`` library directly (no PyJWT dependency).
Supports RS256, RS384, RS512 (RSA PKCS1v15 + SHA-256/384/512) and ES384 (ECDSA P-384).
"""

import base64
import hashlib
import json
import time
from datetime import UTC, datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

SUPPORTED_ALGORITHMS = {"RS256", "RS384", "RS512", "ES384"}

_ALGORITHM_HASH_MAP: dict[str, type[hashes.HashAlgorithm]] = {
    "RS256": hashes.SHA256,
    "RS384": hashes.SHA384,
    "RS512": hashes.SHA512,
    "ES384": hashes.SHA384,
}


def _base64url_encode(data: bytes) -> str:
    """RFC 7515 base64url encoding (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    """RFC 7515 base64url decoding (adds padding back)."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def generate_rsa_signing_key() -> RSAPrivateKey:
    """Generate a new RSA 2048-bit private key for JWT signing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_ec_signing_key() -> EllipticCurvePrivateKey:
    """Generate a new EC P-384 private key for JWT signing."""
    return ec.generate_private_key(ec.SECP384R1())


def compute_kid(public_key: RSAPublicKey | EllipticCurvePublicKey) -> str:
    """Compute a JWK thumbprint (RFC 7638) as the key ID.

    Uses SHA-256 over the canonical JSON of the required JWK members, base64url-encoded.
    """
    if isinstance(public_key, EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        # P-384 coordinates are 48 bytes each
        thumbprint_input = {
            "crv": "P-384",
            "kty": "EC",
            "x": _base64url_encode(numbers.x.to_bytes(48, byteorder="big")),
            "y": _base64url_encode(numbers.y.to_bytes(48, byteorder="big")),
        }
    else:
        numbers = public_key.public_numbers()
        byte_length = (numbers.n.bit_length() + 7) // 8
        thumbprint_input = {
            "e": _base64url_encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder="big")
            ),
            "kty": "RSA",
            "n": _base64url_encode(numbers.n.to_bytes(byte_length, byteorder="big")),
        }

    # RFC 7638: canonical JSON with sorted keys, no whitespace
    canonical = json.dumps(thumbprint_input, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return _base64url_encode(digest)


def public_key_to_jwk(public_key: RSAPublicKey | EllipticCurvePublicKey) -> dict[str, str]:
    """Export a public key as a JWK dict with kid, use, and alg fields."""
    kid = compute_kid(public_key)

    if isinstance(public_key, EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-384",
            "x": _base64url_encode(numbers.x.to_bytes(48, byteorder="big")),
            "y": _base64url_encode(numbers.y.to_bytes(48, byteorder="big")),
            "kid": kid,
            "use": "sig",
            "alg": "ES384",
        }
    else:
        numbers = public_key.public_numbers()
        byte_length = (numbers.n.bit_length() + 7) // 8
        return {
            "kty": "RSA",
            "n": _base64url_encode(numbers.n.to_bytes(byte_length, byteorder="big")),
            "e": _base64url_encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder="big")
            ),
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
        }


def build_jwks(keys: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """Build a JWKS document from a list of JWK dicts."""
    return {"keys": keys}


def create_jwt(
    private_key: RSAPrivateKey | EllipticCurvePrivateKey,
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

    kid = compute_kid(private_key.public_key())
    header = {"alg": algorithm, "typ": "JWT", "kid": kid}
    payload: dict[str, object] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": now,
        "exp": exp,
    }
    if additional_claims:
        payload = {**payload, **additional_claims}

    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    hash_alg = _ALGORITHM_HASH_MAP[algorithm]()

    if algorithm.startswith("RS"):
        assert isinstance(private_key, RSAPrivateKey)
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hash_alg)
    elif algorithm == "ES384":
        assert isinstance(private_key, EllipticCurvePrivateKey)
        # Sign with ECDSA, get DER-encoded signature
        der_sig = private_key.sign(signing_input, ec.ECDSA(hash_alg))
        # Convert DER to fixed-width r||s (48+48 bytes per RFC 7518 §3.4)
        r, s = utils.decode_dss_signature(der_sig)
        signature = r.to_bytes(48, byteorder="big") + s.to_bytes(48, byteorder="big")
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    signature_b64 = _base64url_encode(signature)

    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    return token, expiration


def decode_jwt(token: str) -> tuple[dict[str, object], dict[str, object], bytes]:
    """Decode a JWT without verification.

    Returns (header, payload, signature_bytes).
    Raises ValueError if the token is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT: expected 3 dot-separated parts")

    try:
        header: dict[str, object] = json.loads(_base64url_decode(parts[0]))
        payload: dict[str, object] = json.loads(_base64url_decode(parts[1]))
        signature = _base64url_decode(parts[2])
    except Exception as e:
        raise ValueError(f"Malformed JWT: {e}") from e

    return header, payload, signature


def verify_jwt(
    token: str,
    public_key: RSAPublicKey | EllipticCurvePublicKey,
    expected_audience: str | list[str] | None = None,
) -> dict[str, object]:
    """Verify a JWT signature, expiration, and optionally audience.

    Returns the payload dict on success.
    Raises ValueError on any verification failure.
    """
    header, payload, signature = decode_jwt(token)

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {alg}")

    # Reconstruct the signing input
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

    hash_alg = _ALGORITHM_HASH_MAP[alg]()
    try:
        if alg.startswith("RS"):
            assert isinstance(public_key, RSAPublicKey)
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hash_alg)
        elif alg == "ES384":
            assert isinstance(public_key, EllipticCurvePublicKey)
            # Convert fixed-width r||s back to DER for verification
            r = int.from_bytes(signature[:48], byteorder="big")
            s = int.from_bytes(signature[48:], byteorder="big")
            der_sig = utils.encode_dss_signature(r, s)
            public_key.verify(der_sig, signing_input, ec.ECDSA(hash_alg))
    except Exception as e:
        raise ValueError(f"Invalid signature: {e}") from e

    # Check expiration
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if time.time() > exp:
            raise ValueError("Token has expired")

    # Check audience
    if expected_audience is not None:
        if isinstance(expected_audience, str):
            expected_set = {expected_audience}
        else:
            expected_set = set(expected_audience)
        token_aud = payload.get("aud")
        if isinstance(token_aud, str):
            if token_aud not in expected_set:
                raise ValueError("Audience mismatch")
        elif isinstance(token_aud, list):
            if not any(aud in token_aud for aud in expected_set):
                raise ValueError("Audience mismatch")
        else:
            raise ValueError("Audience mismatch")

    return payload
