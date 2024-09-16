import logging
import os

from localstack import config
from localstack.constants import API_ENDPOINT, ASSETS_ENDPOINT
from localstack.utils.crypto import generate_ssl_cert
from localstack.utils.http import download
from localstack.utils.time import now
from localstack.version import __version__ as version

LOG = logging.getLogger(__name__)

# Download URLs
SSL_CERT_URL = f"{ASSETS_ENDPOINT}/local-certs/localstack.cert.key?version={version}"
SSL_CERT_URL_FALLBACK = f"{API_ENDPOINT}/proxy/localstack.cert.key?version={version}"

# path for test certificate
_SERVER_CERT_PEM_FILE = "server.test.pem"


def install_predefined_cert_if_available():
    try:
        if config.SKIP_SSL_CERT_DOWNLOAD:
            LOG.debug("Skipping download of local SSL cert, as SKIP_SSL_CERT_DOWNLOAD=1")
            return
        setup_ssl_cert()
    except Exception:
        pass


def setup_ssl_cert() -> None:
    target_file = get_cert_pem_file_path()

    # cache file for 6 hours (non-enterprise) or forever (enterprise)
    if os.path.exists(target_file):
        cache_duration_secs = 24 * 60 * 60
        mod_time = os.path.getmtime(target_file)
        if mod_time > (now() - cache_duration_secs):
            LOG.debug("Using cached SSL certificate (less than 6hrs since last update).")
            return

    # download certificate from GitHub artifacts
    LOG.debug("Attempting to download local SSL certificate file")

    # apply timeout (and fall back to using self-signed certs)
    timeout = 5  # slightly higher timeout for our proxy
    try:
        download(SSL_CERT_URL, target_file, timeout=timeout, quiet=True)
        LOG.debug("SSL certificate downloaded successfully")
    except Exception:
        # try fallback URL, directly from our API proxy
        try:
            download(SSL_CERT_URL_FALLBACK, target_file, timeout=timeout, quiet=True)
            LOG.debug("SSL certificate downloaded successfully")
        except Exception as e:
            LOG.info(
                "Unable to download local test SSL certificate from %s to %s (using self-signed cert as fallback): %s",
                SSL_CERT_URL_FALLBACK,
                target_file,
                e,
            )
            raise


def get_cert_pem_file_path():
    return config.CUSTOM_SSL_CERT_PATH or os.path.join(config.dirs.cache, _SERVER_CERT_PEM_FILE)


def create_ssl_cert(serial_number=None):
    cert_pem_file = get_cert_pem_file_path()
    return generate_ssl_cert(cert_pem_file, serial_number=serial_number)
