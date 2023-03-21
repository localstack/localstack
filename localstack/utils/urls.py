import logging
from dataclasses import dataclass
from typing import Optional

from localstack import config, constants

LOG = logging.getLogger(__name__)


def path_from_url(url: str) -> str:
    return f'/{url.partition("://")[2].partition("/")[2]}' if "://" in url else url


def hostname_from_url(url: str) -> str:
    return url.split("://")[-1].split("/")[0].split(":")[0]


@dataclass
class HostDefinition:
    host: str
    port: int

    def host_and_port(self):
        return f"{self.host}:{self.port}"

    def to_url(self, scheme: str) -> str:
        return f"{scheme}://{self.host}:{self.port}"


def localstack_host(
    use_hostname_external: bool = False,
    use_localstack_hostname: bool = False,
    use_localhost_cloud: bool = False,
    custom_port: Optional[int] = None,
) -> HostDefinition:
    """
    Determine the host and port to return to the user based on:
    - the user's configuration (e.g environment variable overrides)
    - the defaults of the system
    """
    port = config.EDGE_PORT
    if custom_port is not None:
        port = custom_port

    # v2 override
    host_definition = _parse_localstack_host_envar(port)
    if host_definition is not None:
        return host_definition

    # deprecation path

    host = config.LOCALHOST
    if use_hostname_external:
        host = config.HOSTNAME_EXTERNAL
    elif use_localstack_hostname:
        host = config.LOCALSTACK_HOSTNAME
    elif use_localhost_cloud:
        host = constants.LOCALHOST_HOSTNAME

    return HostDefinition(host=host, port=port)


def _parse_localstack_host_envar(custom_port: Optional[int] = None) -> Optional[HostDefinition]:
    """
    Parse the LOCALSTACK_HOST environment variable into <hostname>:<port>

    Note: both hostname and port are optional

    If `custom_port` is supplied then this value is used in preference to any defaults set by configuration.

    Examples:
        - "foobar" | "foobar:" => {"host": "foobar", "port": 4566}
        - ":10101" => {"host": "localhost.localstack.cloud", "port": 10101}
        - "foobar:10101" => {"host": "foobar", "port": 10101}
        - "" => {"host": "localhost.localstack.cloud", "port": 4566} (default/fallback case)
    """
    envar_value = config.LOCALSTACK_HOST.strip()
    if not envar_value:
        # the user did not set the value
        return None

    if ":" in envar_value:
        # the variable contains both hostname and port specification, with either half possibly being default
        hostname, port_str = envar_value.split(":", 1)
        if not hostname.strip():
            # default to localhost.localstack.cloud
            hostname = constants.LOCALHOST_HOSTNAME

        port = config.EDGE_PORT
        if port_str.strip():
            try:
                port = int(port_str.strip())
            except (ValueError, TypeError):
                LOG.warning(
                    f"invalid port specified: {port_str}, must be an integer; falling back to defaults"
                )
        if custom_port is not None:
            port = custom_port

        definition = HostDefinition(host=hostname, port=port)

    else:
        # we must just have a hostname
        hostname = envar_value
        port = custom_port if custom_port is not None else config.EDGE_PORT
        definition = HostDefinition(host=hostname, port=port)

    return definition
