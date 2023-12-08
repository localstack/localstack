from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

#
# SNS Server Cert
#

SNS_SERVER_PRIVATE_KEY: RSAPrivateKey = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)

SNS_SERVER_CERT_ISSUER = x509.Name(
    [
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "CH"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "LocalStack"),
        x509.NameAttribute(
            x509.NameOID.COMMON_NAME, "LocalStack TEST SNS Root Certificate Authority"
        ),
    ]
)

SNS_SERVER_CERT: str = (
    (
        x509.CertificateBuilder()
        .subject_name(SNS_SERVER_CERT_ISSUER)
        .issuer_name(SNS_SERVER_CERT_ISSUER)
        .public_key(SNS_SERVER_PRIVATE_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                crl_sign=True,
                key_cert_sign=True,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(SNS_SERVER_PRIVATE_KEY.public_key()),
            critical=False,
        )
        .sign(SNS_SERVER_PRIVATE_KEY, hashes.SHA256())
    )
    .public_bytes(serialization.Encoding.PEM)
    .decode("utf-8")
)

print(SNS_SERVER_CERT)

# x509.load_pem_x509_certificate(SNS_SERVER_CERT.encode()).public_key().verify()
#
# Utils
#


def private_key_as_pem(key: RSAPrivateKey) -> str:
    """
    Return the PEM encoded private key with no encryption.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def public_key_as_pem(key: RSAPublicKey) -> str:
    """
    Return the PEM encoded public key.
    """
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
