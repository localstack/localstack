"""
Utilities related to Java runtime.
"""

import logging
from os import environ
from urllib.parse import urlparse

from localstack import config
from localstack.utils.files import new_tmp_file, rm_rf
from localstack.utils.run import run

LOG = logging.getLogger(__name__)


#
# Network
#


def java_system_properties_proxy() -> dict[str, str]:
    """
    Returns Java system properties for network proxy settings as per LocalStack configuration.

    See: https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html
    """
    props = {}

    for scheme, default_port, proxy_url in [
        ("http", 80, config.OUTBOUND_HTTP_PROXY),
        ("https", 443, config.OUTBOUND_HTTPS_PROXY),
    ]:
        if proxy_url:
            parsed_url = urlparse(proxy_url)
            port = parsed_url.port or default_port

            props[f"{scheme}.proxyHost"] = parsed_url.hostname
            props[f"{scheme}.proxyPort"] = str(port)

    return props


#
# SSL
#


def build_trust_store(
    keytool_path: str, pem_bundle_path: str, env_vars: dict[str, str], store_passwd: str
) -> str:
    """
    Build a TrustStore in JKS format from a PEM certificate bundle.

    :param keytool_path: path to the `keytool` binary.
    :param pem_bundle_path: path to the PEM bundle.
    :param env_vars: environment variables passed during `keytool` execution. This should contain JAVA_HOME and other relevant variables.
    :param store_passwd: store password to use.
    :return: path to the truststore file.
    """
    store_path = new_tmp_file(suffix=".jks")
    rm_rf(store_path)

    LOG.debug("Building JKS trust store for %s at %s", pem_bundle_path, store_path)
    cmd = f"{keytool_path} -importcert -trustcacerts -alias localstack -file {pem_bundle_path} -keystore {store_path} -storepass {store_passwd} -noprompt"
    run(cmd, env_vars=env_vars)

    return store_path


def java_system_properties_ssl(keytool_path: str, env_vars: dict[str, str]) -> dict[str, str]:
    """
    Returns Java system properties for SSL settings as per LocalStack configuration.

    See https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#CustomizingStores
    """
    props = {}

    if ca_bundle := environ.get("REQUESTS_CA_BUNDLE"):
        store_passwd = "localstack"
        store_path = build_trust_store(keytool_path, ca_bundle, env_vars, store_passwd)
        props["javax.net.ssl.trustStore"] = store_path
        props["javax.net.ssl.trustStorePassword"] = store_passwd
        props["javax.net.ssl.trustStoreType"] = "jks"

    return props


#
# Other
#


def system_properties_to_cli_args(properties: dict[str, str]) -> list[str]:
    """
    Convert a dict of Java system properties to a list of CLI arguments.

    e.g.::

        {
          'java.sys.foo': 'bar',
          'java.sys.lorem': 'ipsum'
        }

    returns::

        [
          '-Djava.sys.foo=bar',
          '-Djava.sys.lorem=ipsum',
        ]
    """
    args = []

    for arg_name, arg_value in properties.items():
        args.append(f"-D{arg_name}={arg_value}")

    return args
