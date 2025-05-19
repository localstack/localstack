import io
import ipaddress
import logging
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .files import TMP_FILES, file_exists_not_empty, load_file, new_tmp_file, save_file
from .strings import short_uid, to_bytes, to_str
from .sync import synchronized
from .urls import localstack_host

LOG = logging.getLogger(__name__)

# block size for symmetric encrypt/decrypt operations
BLOCK_SIZE = 16

# lock for creating certificate files
SSL_CERT_LOCK = threading.RLock()

# markers that indicate the start/end of sections in PEM cert files
PEM_CERT_START = "-----BEGIN CERTIFICATE-----"
PEM_CERT_END = "-----END CERTIFICATE-----"
PEM_KEY_START_REGEX = r"-----BEGIN(.*)PRIVATE KEY-----"
PEM_KEY_END_REGEX = r"-----END(.*)PRIVATE KEY-----"

IPV4_REGEX = re.compile(
    r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
)


@synchronized(lock=SSL_CERT_LOCK)
def generate_ssl_cert(
    target_file=None,
    overwrite=False,
    random=False,
    return_content=False,
    serial_number=None,
):
    def all_exist(*files):
        return all(os.path.exists(f) for f in files)

    def store_cert_key_files(base_filename):
        key_file_name = "%s.key" % base_filename
        cert_file_name = "%s.crt" % base_filename
        # TODO: Cleaner code to load the cert dynamically
        # extract key and cert from target_file and store into separate files
        content = load_file(target_file)
        key_start = re.search(PEM_KEY_START_REGEX, content)
        key_start = key_start.group(0)
        key_end = re.search(PEM_KEY_END_REGEX, content)
        key_end = key_end.group(0)
        key_content = content[content.index(key_start) : content.index(key_end) + len(key_end)]
        cert_content = content[
            content.index(PEM_CERT_START) : content.rindex(PEM_CERT_END) + len(PEM_CERT_END)
        ]
        save_file(key_file_name, key_content)
        save_file(cert_file_name, cert_content)
        return cert_file_name, key_file_name

    if target_file and not overwrite and file_exists_not_empty(target_file):
        try:
            cert_file_name, key_file_name = store_cert_key_files(target_file)
        except Exception as e:
            # fall back to temporary files if we cannot store/overwrite the files above
            LOG.info(
                "Error storing key/cert SSL files (falling back to random tmp file names): %s", e
            )
            target_file_tmp = new_tmp_file()
            cert_file_name, key_file_name = store_cert_key_files(target_file_tmp)
        if all_exist(cert_file_name, key_file_name):
            return target_file, cert_file_name, key_file_name
    if random and target_file:
        if "." in target_file:
            target_file = target_file.replace(".", ".%s." % short_uid(), 1)
        else:
            target_file = "%s.%s" % (target_file, short_uid())

    # create a key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    host_definition = localstack_host()

    issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "AU"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Some-State"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Some-Locality"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "LocalStack Org"),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "Testing"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "cryptography.io"),
        ]
    )

    # create a self-signed cert
    public_key = private_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial_number or 1001)
        .not_valid_before(datetime.now(tz=timezone.utc))
        .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(days=365 * 2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                crl_sign=False,
                key_cert_sign=False,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )

    dns = [
        "localhost",
        "test.localhost.atlassian.io",
        "localhost.localstack.cloud",
        host_definition.host,
        "127.0.0.1",
    ]
    # SSL treats IP addresses differently from regular host names
    # https://cabforum.org/working-groups/server/guidance-ip-addresses-certificates/
    x509_names_or_ips = [
        x509.IPAddress(ipaddress.IPv4Address(name))
        if IPV4_REGEX.match(name)
        else x509.DNSName(name)
        for name in dns
    ]
    builder = builder.add_extension(x509.SubjectAlternativeName(x509_names_or_ips), critical=False)

    builder = builder.add_extension(
        x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=True
    )

    cert = builder.sign(private_key, hashes.SHA256())

    private_key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_file = io.StringIO()
    key_file = io.StringIO()
    cert_file.write(to_str(cert.public_bytes(serialization.Encoding.PEM)))
    key_file.write(to_str(private_key_bytes))
    cert_file_content = cert_file.getvalue().strip()
    key_file_content = key_file.getvalue().strip()
    file_content = "%s\n%s" % (key_file_content, cert_file_content)
    if target_file:
        key_file_name = "%s.key" % target_file
        cert_file_name = "%s.crt" % target_file
        # check existence to avoid permission denied issues:
        # https://github.com/localstack/localstack/issues/1607
        if not all_exist(target_file, key_file_name, cert_file_name):
            for i in range(2):
                try:
                    save_file(target_file, file_content)
                    save_file(key_file_name, key_file_content)
                    save_file(cert_file_name, cert_file_content)
                    break
                except Exception as e:
                    if i > 0:
                        raise
                    LOG.info(
                        "Unable to store certificate file under %s, using tmp file instead: %s",
                        target_file,
                        e,
                    )
                    # Fix for https://github.com/localstack/localstack/issues/1743
                    target_file = "%s.pem" % new_tmp_file()
                    key_file_name = "%s.key" % target_file
                    cert_file_name = "%s.crt" % target_file
            TMP_FILES.append(target_file)
            TMP_FILES.append(key_file_name)
            TMP_FILES.append(cert_file_name)
        if not return_content:
            return target_file, cert_file_name, key_file_name
    return file_content


def pad(s: bytes) -> bytes:
    return s + to_bytes((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE))


def unpad(s: bytes) -> bytes:
    return s[0 : -s[-1]]


def encrypt(key: bytes, message: bytes, iv: bytes = None, aad: bytes = None) -> Tuple[bytes, bytes]:
    iv = iv or b"0" * BLOCK_SIZE
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    encrypted = encryptor.update(pad(message)) + encryptor.finalize()
    return encrypted, encryptor.tag


def decrypt(
    key: bytes, encrypted: bytes, iv: bytes = None, tag: bytes = None, aad: bytes = None
) -> bytes:
    iv = iv or b"0" * BLOCK_SIZE
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(aad)
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    decrypted = unpad(decrypted)
    return decrypted
