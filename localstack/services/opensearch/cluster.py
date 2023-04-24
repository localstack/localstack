import dataclasses
import logging
import os
import threading
from typing import Dict, List, NamedTuple, Optional, Tuple
from urllib.parse import urlparse

import requests
from werkzeug.routing import Rule

from localstack import config, constants
from localstack.aws.api.opensearch import (
    AdvancedSecurityOptionsInput,
    EngineType,
    ValidationException,
)
from localstack.http.client import SimpleRequestsClient
from localstack.http.proxy import ProxyHandler
from localstack.services.edge import ROUTER
from localstack.services.infra import DEFAULT_BACKEND_HOST
from localstack.services.opensearch import versions
from localstack.services.opensearch.packages import elasticsearch_package, opensearch_package
from localstack.utils.common import (
    ShellCommandThread,
    chmod_r,
    get_free_tcp_port,
    is_root,
    mkdir,
    rm_rf,
)
from localstack.utils.run import FuncThread
from localstack.utils.serving import Server
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)
INTERNAL_USER_AUTH = ("localstack-internal", "localstack-internal")

CommandSettings = Dict[str, str]


class Directories(NamedTuple):
    install: str
    tmp: str
    mods: str
    data: str
    backup: str


def get_cluster_health_status(url: str, auth: Tuple[str, str] | None) -> Optional[str]:
    """
    Queries the health endpoint of OpenSearch/Elasticsearch and returns either the status ('green', 'yellow',
    ...) or None if the response returned a non-200 response.
    Authentication needs to be set in case the security plugin is enabled.
    """
    resp = requests.get(url + "/_cluster/health", verify=False, auth=auth)

    if resp and resp.ok:
        opensearch_status = resp.json()
        opensearch_status = opensearch_status["status"]
        return opensearch_status

    return None


def init_directories(dirs: Directories):
    """Makes sure the directories exist and have the necessary permissions."""
    LOG.debug("initializing cluster directories %s", dirs)
    chmod_r(dirs.install, 0o777)

    if not config.dirs.data or not dirs.data.startswith(config.dirs.data):
        # only clear previous data if it's not in DATA_DIR
        rm_rf(dirs.data)

    rm_rf(dirs.tmp)
    mkdir(dirs.tmp)
    chmod_r(dirs.tmp, 0o777)

    mkdir(dirs.data)
    chmod_r(dirs.data, 0o777)

    mkdir(dirs.backup)
    chmod_r(dirs.backup, 0o777)

    # clear potentially existing lock files (which cause problems since ES 7.10)
    for d, dirs, files in os.walk(dirs.data, True):
        for f in files:
            if f.endswith(".lock"):
                rm_rf(os.path.join(d, f))


def resolve_directories(version: str, cluster_path: str, data_root: str = None) -> Directories:
    """
    Determines directories to find the opensearch binary as well as where to store the instance data.

    :param version: the full OpenSearch/Elasticsearch version (to resolve the install dir)
    :param cluster_path: the path between data_root and the actual data directories
    :param data_root: the root of the data dir (will be resolved to TMP_PATH or DATA_DIR by default)
    :returns: a Directories data structure
    """
    # where to find cluster binary and the modules
    engine_type, install_version = versions.get_install_type_and_version(version)
    install_dir = opensearch_package.get_installed_dir(version)

    modules_dir = os.path.join(install_dir, "modules")

    if not data_root:
        data_root = config.dirs.data or config.dirs.tmp

    if engine_type == EngineType.OpenSearch:
        data_path = os.path.join(data_root, "opensearch", cluster_path)
    else:
        data_path = os.path.join(data_root, "elasticsearch", cluster_path)

    tmp_dir = os.path.join(data_path, "tmp")
    data_dir = os.path.join(data_path, "data")
    backup_dir = os.path.join(data_path, "backup")

    return Directories(install_dir, tmp_dir, modules_dir, data_dir, backup_dir)


def build_cluster_run_command(cluster_bin: str, settings: CommandSettings) -> List[str]:
    """
    Takes the command settings dict and builds the actual command (which can then be executed as a shell command).

    :param cluster_bin: path to the OpenSearch/Elasticsearch binary (including the binary)
    :param settings: dictionary where each item will be set as a command arguments
    :return: list of strings for the command with the settings to be executed as a shell command
    """
    cmd_settings = [f"-E {k}={v}" for k, v, in settings.items()]
    return [cluster_bin] + cmd_settings


class CustomEndpoint:
    """
    Encapsulates a custom endpoint (combines CustomEndpoint and CustomEndpointEnabled within the DomainEndpointOptions
    of the cluster, i.e. combines two fields from the AWS OpenSearch service model).
    """

    enabled: bool
    endpoint: str

    def __init__(self, enabled: bool, endpoint: str) -> None:
        """
        :param enabled: true if the custom endpoint is enabled (refers to DomainEndpointOptions#CustomEndpointEnabled)
        :param endpoint: defines the endpoint (i.e. the URL - refers to DomainEndpointOptions#CustomEndpoint)
        """
        self.enabled = enabled
        self.endpoint = endpoint

        if self.endpoint:
            self.url = urlparse(endpoint)
        else:
            self.url = None


@dataclasses.dataclass
class SecurityOptions:
    """DTO which encapsulates the currently supported security options."""

    enabled: bool
    master_username: str | None
    master_password: str | None

    @property
    def auth(self) -> Tuple[str, str] | None:
        """Returns an auth tuple which can be used for HTTP requests or None, if disabled."""
        return None if not self.enabled else (self.master_username, self.master_password)

    @staticmethod
    def from_input(
        advanced_security_options: Optional[AdvancedSecurityOptionsInput],
    ) -> "SecurityOptions":
        """
        Parses the given AdvancedSecurityOptionsInput, performs some validation, and returns the parsed SecurityOptions.
        If unsupported settings are used, the SecurityOptions are disabled and a warning is logged.

        :param advanced_security_options: of the domain which will be created
        :return: parsed SecurityOptions
        :raises: ValidationException in case the given AdvancedSecurityOptions are invalid
        """
        if advanced_security_options is None:
            return SecurityOptions(enabled=False, master_username=None, master_password=None)
        if not advanced_security_options.get("InternalUserDatabaseEnabled", False):
            LOG.warning(
                "AdvancedSecurityOptions are set, but InternalUserDatabase is disabled. Disabling security options."
            )
            return SecurityOptions(enabled=False, master_username=None, master_password=None)

        master_username = advanced_security_options.get("MasterUserOptions", {}).get(
            "MasterUserName", None
        )
        master_password = advanced_security_options.get("MasterUserOptions", {}).get(
            "MasterUserPassword", None
        )
        if not master_username and not master_password:
            raise ValidationException(
                "You must provide a master username and password when the internal user database is enabled."
            )
        if not master_username or not master_password:
            raise ValidationException("You must provide a master username and password together.")

        return SecurityOptions(
            enabled=advanced_security_options["Enabled"] or False,
            master_username=master_username,
            master_password=master_password,
        )


def register_cluster(
    host: str, path: str, forward_url: str, custom_endpoint: CustomEndpoint
) -> List[Rule]:
    """
    Registers routes for a cluster at the edge router.
    Depending on which endpoint strategy is employed, and if a custom endpoint is enabled, different routes are
    registered.
    This method is tightly coupled with `cluster_manager.build_cluster_endpoint`, which already creates the
    endpoint URL according to the configuration used here.

    :param host: hostname of the inbound address without scheme or port
    :param path: path of the inbound address
    :param forward_url: whole address for outgoing traffic (including the protocol)
    :param custom_endpoint: Object that stores a custom address and if its enabled.
            If a custom_endpoint is set AND enabled, the specified address takes precedence
            over any strategy currently active, and overwrites any host/path combination.
    :return: a list of generated router rules, which can be used for removal
    """
    # custom backends overwrite the usual forward_url
    forward_url = config.OPENSEARCH_CUSTOM_BACKEND or forward_url

    # if the opensearch security plugin is enabled, only TLS connections are allowed, but the cert cannot be verified
    client = SimpleRequestsClient()
    client.session.verify = False
    endpoint = ProxyHandler(forward_url, client)

    rules = []
    strategy = config.OPENSEARCH_ENDPOINT_STRATEGY
    # custom endpoints override any endpoint strategy
    if custom_endpoint and custom_endpoint.enabled:
        LOG.debug(f"Registering route from {host}{path} to {endpoint.proxy.forward_base_url}")
        assert not (
            host == config.LOCALSTACK_HOSTNAME and (not path or path == "/")
        ), "trying to register an illegal catch all route"
        rules.append(
            ROUTER.add(
                path=path,
                endpoint=endpoint,
                host=f"{host}<port:port>",
            )
        )
        rules.append(
            ROUTER.add(
                f"{path}/<path:path>",
                endpoint=endpoint,
                host=f"{host}<port:port>",
            )
        )
    elif strategy == "domain":
        LOG.debug(f"Registering route from {host} to {endpoint.proxy.forward_base_url}")
        assert (
            not host == config.LOCALSTACK_HOSTNAME
        ), "trying to register an illegal catch all route"
        rules.append(
            ROUTER.add(
                "/",
                endpoint=endpoint,
                host=f"{host}<port:port>",
            )
        )
        rules.append(
            ROUTER.add(
                "/<path:path>",
                endpoint=endpoint,
                host=f"{host}<port:port>",
            )
        )
    elif strategy == "path":
        LOG.debug(f"Registering route from {path} to {endpoint.proxy.forward_base_url}")
        assert path and not path == "/", "trying to register an illegal catch all route"
        rules.append(ROUTER.add(path, endpoint=endpoint))
        rules.append(ROUTER.add(f"{path}/<path:path>", endpoint=endpoint))

    elif strategy != "port":
        LOG.warning(f"Attempted to register route for cluster with invalid strategy '{strategy}'")

    return rules


class OpensearchCluster(Server):
    """Manages an OpenSearch cluster which is installed and operated by LocalStack."""

    def __init__(
        self,
        port: int,
        arn: str,
        host: str = "localhost",
        version: str = None,
        security_options: SecurityOptions = None,
    ) -> None:
        super().__init__(port, host)
        self._version = version or self.default_version
        self.arn = arn
        self.security_options = security_options
        self.is_security_enabled = self.security_options and self.security_options.enabled
        self.auth = security_options.auth if self.is_security_enabled else None

    @property
    def default_version(self) -> str:
        return constants.OPENSEARCH_DEFAULT_VERSION

    @property
    def version(self) -> str:
        return self._version

    @property
    def install_version(self) -> str:
        _, install_version = versions.get_install_type_and_version(self._version)
        return install_version

    @property
    def protocol(self):
        # if the security plugin is enabled, the cluster rejects unencrypted requests
        return "https" if self.is_security_enabled else "http"

    @property
    def bin_name(self) -> str:
        return "opensearch"

    @property
    def os_user(self):
        return constants.OS_USER_OPENSEARCH

    def health(self) -> Optional[str]:
        return get_cluster_health_status(self.url, auth=self.auth)

    def do_start_thread(self) -> FuncThread:
        self._ensure_installed()
        directories = resolve_directories(version=self.version, cluster_path=self.arn)
        init_directories(directories)

        cmd = self._create_run_command(directories=directories)
        cmd = " ".join(cmd)

        if is_root() and self.os_user:
            # run the opensearch process as a non-root user (when running in docker)
            cmd = f"su {self.os_user} -c '{cmd}'"

        env_vars = self._create_env_vars(directories)

        LOG.info("starting %s: %s with env %s", self.bin_name, cmd, env_vars)
        t = ShellCommandThread(
            cmd,
            env_vars=env_vars,
            strip_color=True,
            log_listener=self._log_listener,
            name="opensearch-cluster",
        )
        t.start()

        # FIXME this approach should be handled differently
        #  - we need to perform some API requests after the server is up, but before the Server instance becomes healthy
        #  - this should be implemented in the Cluster or Server implementation
        # wait for the cluster to be up and running and perform the post-startup setup
        threading.Thread(
            target=self._post_start_setup,
            daemon=True,
        ).start()

        return t

    def _post_start_setup(self):
        if not self.is_security_enabled:
            # post start setup not necessary
            return

        # the health check for the cluster uses the master user auth (which will be created here).
        # check for the health using the startup internal user auth here.
        def wait_for_cluster_with_internal_creds() -> bool:
            try:
                return get_cluster_health_status(self.url, auth=INTERNAL_USER_AUTH) is not None
            except Exception:
                # we can get (raised) connection exceptions when the cluster is not yet accepting requests
                return False

        poll_condition(wait_for_cluster_with_internal_creds)

        # create the master user
        user = {
            "password": self.security_options.master_password,
            "opendistro_security_roles": ["all_access"],
        }
        response = requests.put(
            f"{self.url}/_plugins/_security/api/internalusers/{self.security_options.master_username}",
            json=user,
            auth=INTERNAL_USER_AUTH,
            verify=False,
        )
        # after it's created the actual domain check (using these credentials) will report healthy
        if not response.ok:
            LOG.error(
                "Setting up master user failed with status code %d! Shutting down!",
                response.status_code,
            )
            self.shutdown()

    def _ensure_installed(self):
        opensearch_package.install(self.version)

    def _base_settings(self, dirs) -> CommandSettings:
        settings = {
            "http.port": self.port,
            "http.publish_port": self.port,
            "transport.port": "0",
            "network.host": self.host,
            "http.compression": "false",
            "path.data": f'"{dirs.data}"',
            "path.repo": f'"{dirs.backup}"',
            "discovery.type": "single-node",
        }

        if os.path.exists(os.path.join(dirs.mods, "x-pack-ml")):
            settings["xpack.ml.enabled"] = "false"

        if not self.is_security_enabled:
            settings["plugins.security.disabled"] = "true"
        else:
            # enable the security plugin in the settings
            settings["plugins.security.disabled"] = "false"
            # certs are set up during the package installation
            settings["plugins.security.ssl.transport.pemkey_filepath"] = "cert.key"
            settings["plugins.security.ssl.transport.pemcert_filepath"] = "cert.crt"
            settings["plugins.security.ssl.transport.pemtrustedcas_filepath"] = "cert.crt"
            settings["plugins.security.ssl.transport.enforce_hostname_verification"] = "false"
            settings["plugins.security.ssl.http.enabled"] = "true"
            settings["plugins.security.ssl.http.pemkey_filepath"] = "cert.key"
            settings["plugins.security.ssl.http.pemcert_filepath"] = "cert.crt"
            settings["plugins.security.ssl.http.pemtrustedcas_filepath"] = "cert.crt"
            settings["plugins.security.allow_default_init_securityindex"] = "true"
            settings[
                "plugins.security.restapi.roles_enabled"
            ] = "all_access,security_rest_api_access"

        return settings

    def _create_run_command(
        self, directories: Directories, additional_settings: Optional[CommandSettings] = None
    ) -> List[str]:
        # delete opensearch data that may be cached locally from a previous test run
        bin_path = os.path.join(directories.install, "bin", self.bin_name)

        settings = self._base_settings(directories)

        if additional_settings:
            settings.update(additional_settings)

        cmd = build_cluster_run_command(bin_path, settings)
        return cmd

    def _create_env_vars(self, directories: Directories) -> Dict:
        return {
            "OPENSEARCH_JAVA_OPTS": os.environ.get("OPENSEARCH_JAVA_OPTS", "-Xms200m -Xmx600m"),
            "OPENSEARCH_TMPDIR": directories.tmp,
        }

    def _log_listener(self, line, **_kwargs):
        # logging the port before each line to be able to connect logs to specific instances
        LOG.info("[%s] %s", self.port, line.rstrip())


class EndpointProxy:
    def __init__(self, base_url: str, forward_url: str, custom_endpoint: CustomEndpoint) -> None:
        super().__init__()
        self.base_url = base_url
        self.forward_url = forward_url
        self.custom_endpoint = custom_endpoint
        self.routing_rules = None

    def register(self):
        _url = urlparse(self.base_url)
        self.routing_rules = register_cluster(
            host=_url.hostname,
            path=_url.path,
            forward_url=self.forward_url,
            custom_endpoint=self.custom_endpoint,
        )

    def unregister(self):
        for rule in self.routing_rules:
            ROUTER.remove_rule(rule)
        self.routing_rules.clear()


class FakeEndpointProxyServer(Server):
    """
    Makes an EndpointProxy behave like a Server. You can use this to create transparent
    multiplexing behavior.
    """

    endpoint: EndpointProxy

    def __init__(self, endpoint: EndpointProxy) -> None:
        self.endpoint = endpoint
        self._shutdown_event = threading.Event()

        self._url = urlparse(self.endpoint.base_url)
        super().__init__(self._url.port, self._url.hostname)

    @property
    def url(self):
        return self._url.geturl()

    def do_run(self):
        self.endpoint.register()
        try:
            self._shutdown_event.wait()
        finally:
            self.endpoint.unregister()

    def do_shutdown(self):
        self._shutdown_event.set()


class EdgeProxiedOpensearchCluster(Server):
    """
    Opensearch-backed Server that can be routed through the edge proxy using an UrlMatchingForwarder to forward
    requests to the backend cluster.
    """

    def __init__(
        self,
        url: str,
        arn: str,
        custom_endpoint: CustomEndpoint,
        version: str = None,
        security_options: SecurityOptions = None,
    ) -> None:
        self._url = urlparse(url)

        super().__init__(
            host=self._url.hostname,
            port=self._url.port,
        )
        self.custom_endpoint = custom_endpoint
        self._version = version or self.default_version
        self.security_options = security_options
        self.is_security_enabled = self.security_options and self.security_options.enabled
        self.auth = security_options.auth if self.is_security_enabled else None
        self.arn = arn

        self.cluster = None
        self.cluster_port = None
        self.proxy = None

    @property
    def version(self):
        return self._version

    @property
    def default_version(self):
        return constants.OPENSEARCH_DEFAULT_VERSION

    @property
    def url(self) -> str:
        return self._url.geturl()

    def is_up(self):
        # check service lifecycle
        if not self.cluster:
            return False

        if not self.cluster.is_up():
            return False

        return super().is_up()

    def health(self):
        """calls the health endpoint of cluster through the proxy, making sure implicitly that both are running"""
        return get_cluster_health_status(self.url, self.auth)

    def _backend_cluster(self) -> OpensearchCluster:
        return OpensearchCluster(
            port=self.cluster_port,
            host=DEFAULT_BACKEND_HOST,
            arn=self.arn,
            version=self.version,
            security_options=self.security_options,
        )

    def do_run(self):
        self.cluster_port = get_free_tcp_port()
        self.cluster = self._backend_cluster()
        self.cluster.start()

        self.proxy = EndpointProxy(self.url, self.cluster.url, self.custom_endpoint)
        LOG.info("registering an endpoint proxy for %s => %s", self.url, self.cluster.url)
        self.proxy.register()

        self.cluster.wait_is_up()
        LOG.info("cluster on %s is ready", self.cluster.url)

        return self.cluster.join()

    def do_shutdown(self):
        if self.proxy:
            self.proxy.unregister()
        if self.cluster:
            self.cluster.shutdown()


class ElasticsearchCluster(OpensearchCluster):
    def __init__(
        self,
        port: int,
        arn: str,
        host: str = "localhost",
        version: str = None,
        security_options: SecurityOptions = None,
    ) -> None:
        if security_options and security_options.enabled:
            LOG.warning(
                "Advanced security options are enabled, but are not supported for ElasticSearch."
            )
            security_options = None
        super().__init__(
            port=port, arn=arn, host=host, version=version, security_options=security_options
        )

    @property
    def default_version(self) -> str:
        return constants.ELASTICSEARCH_DEFAULT_VERSION

    @property
    def bin_name(self) -> str:
        return "elasticsearch"

    @property
    def os_user(self):
        return constants.OS_USER_OPENSEARCH

    def _ensure_installed(self):
        elasticsearch_package.install(self.version)

    def _base_settings(self, dirs) -> CommandSettings:
        settings = {
            "http.port": self.port,
            "http.publish_port": self.port,
            "transport.port": "0",
            "network.host": self.host,
            "http.compression": "false",
            "path.data": f'"{dirs.data}"',
            "path.repo": f'"{dirs.backup}"',
            "discovery.type": "single-node",
        }

        if os.path.exists(os.path.join(dirs.mods, "x-pack-ml")):
            settings["xpack.ml.enabled"] = "false"

        return settings

    def _create_env_vars(self, directories: Directories) -> Dict:
        return {
            "ES_JAVA_OPTS": os.environ.get("ES_JAVA_OPTS", "-Xms200m -Xmx600m"),
            "ES_TMPDIR": directories.tmp,
        }


class EdgeProxiedElasticsearchCluster(EdgeProxiedOpensearchCluster):
    @property
    def default_version(self):
        return constants.ELASTICSEARCH_DEFAULT_VERSION

    def _backend_cluster(self) -> OpensearchCluster:
        return ElasticsearchCluster(
            port=self.cluster_port,
            host=DEFAULT_BACKEND_HOST,
            arn=self.arn,
            version=self.version,
            security_options=self.security_options,
        )
