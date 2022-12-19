import io
import logging
import os
import re
import threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .files import TMP_FILES, file_exists_not_empty, load_file, new_tmp_file, save_file
from .strings import short_uid, to_bytes, to_str
from .sync import synchronized

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


@synchronized(lock=SSL_CERT_LOCK)
def generate_ssl_cert(
    target_file=None,
    overwrite=False,
    random=False,
    return_content=False,
    serial_number=None,
):
    # Note: Do NOT import "OpenSSL" at the root scope
    # (Our test Lambdas are importing this file but don't have the module installed)
    from OpenSSL import crypto

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
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # create a self-signed cert
    cert = crypto.X509()
    subj = cert.get_subject()
    subj.C = "AU"
    subj.ST = "Some-State"
    subj.L = "Some-Locality"
    subj.O = "LocalStack Org"  # noqa
    subj.OU = "Testing"
    subj.CN = "localhost"
    # Note: new requirements for recent OSX versions: https://support.apple.com/en-us/HT210176
    # More details: https://www.iol.unh.edu/blog/2019/10/10/macos-catalina-and-chrome-trust
    serial_number = serial_number or 1001
    cert.set_version(2)
    cert.set_serial_number(serial_number)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(2 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    alt_names = (
        b"DNS:localhost,DNS:test.localhost.atlassian.io,DNS:localhost.localstack.cloud,IP:127.0.0.1"
    )
    cert.add_extensions(
        [
            crypto.X509Extension(b"subjectAltName", False, alt_names),
            crypto.X509Extension(b"basicConstraints", True, b"CA:false"),
            crypto.X509Extension(
                b"keyUsage", True, b"nonRepudiation,digitalSignature,keyEncipherment"
            ),
            crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth"),
        ]
    )
    cert.sign(k, "SHA256")

    cert_file = io.StringIO()
    key_file = io.StringIO()
    cert_file.write(to_str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
    key_file.write(to_str(crypto.dump_privatekey(crypto.FILETYPE_PEM, k)))
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


def encrypt(key: bytes, message: bytes, iv: bytes = None) -> bytes:
    iv = iv or b"0" * BLOCK_SIZE
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(pad(message)) + encryptor.finalize()
    return encrypted


def decrypt(key: bytes, encrypted: bytes, iv: bytes = None) -> bytes:
    iv = iv or b"0" * BLOCK_SIZE
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    decrypted = unpad(decrypted)
    return decrypted
