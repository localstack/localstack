"""
Utilities related to Java runtime environments.
"""

from urllib.parse import urlparse

from localstack.config import OUTBOUND_HTTP_PROXY, OUTBOUND_HTTPS_PROXY


def java_proxy_system_properties() -> list[str]:
    """
    Returns Java system properties for network proxy settings as per LocalStack configuration.

    See: https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html
    """
    props = {}

    for scheme, var in [
        ("http", OUTBOUND_HTTP_PROXY),
        ("https", OUTBOUND_HTTPS_PROXY),
    ]:
        if var:
            netloc = urlparse(OUTBOUND_HTTP_PROXY).netloc
            url = netloc.split(":")
            if len(url) == 2:
                hostname, port = url
            else:
                hostname, port = url, 80

            props[f"{scheme}.proxyHost"] = hostname
            props[f"{scheme}.proxyPort"] = port

    return props


def java_proxy_cli_args() -> list[str]:
    """
    Returns Java CLI arguments for network proxy settings as per LocalStack configuration.
    """
    args = []

    props = java_proxy_system_properties()

    for arg_name, arg_value in props.items():
        args.append(f"-D{arg_name}={arg_value}")

    return args
