import dataclasses
import io
import ipaddress
import logging
import os
import re
import shlex
import sys
import tarfile
import tempfile
from abc import ABCMeta, abstractmethod
from enum import Enum, unique
from pathlib import Path
from typing import Dict, List, Literal, NamedTuple, Optional, Protocol, Tuple, Union, get_args

import dotenv

from localstack import config
from localstack.utils.collections import HashableList, ensure_list
from localstack.utils.files import TMP_FILES, rm_rf, save_file
from localstack.utils.no_exit_argument_parser import NoExitArgumentParser
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# list of well-known image repo prefixes that should be stripped off to canonicalize image names
WELL_KNOWN_IMAGE_REPO_PREFIXES = ("localhost/", "docker.io/library/")


@unique
class DockerContainerStatus(Enum):
    DOWN = -1
    NON_EXISTENT = 0
    UP = 1
    PAUSED = 2


class ContainerException(Exception):
    def __init__(self, message=None, stdout=None, stderr=None) -> None:
        self.message = message or "Error during the communication with the docker daemon"
        self.stdout = stdout
        self.stderr = stderr


class NoSuchObject(ContainerException):
    def __init__(self, object_id: str, message=None, stdout=None, stderr=None) -> None:
        message = message or f"Docker object {object_id} not found"
        super().__init__(message, stdout, stderr)
        self.object_id = object_id


class NoSuchContainer(ContainerException):
    def __init__(self, container_name_or_id: str, message=None, stdout=None, stderr=None) -> None:
        message = message or f"Docker container {container_name_or_id} not found"
        super().__init__(message, stdout, stderr)
        self.container_name_or_id = container_name_or_id


class NoSuchImage(ContainerException):
    def __init__(self, image_name: str, message=None, stdout=None, stderr=None) -> None:
        message = message or f"Docker image {image_name} not found"
        super().__init__(message, stdout, stderr)
        self.image_name = image_name


class NoSuchNetwork(ContainerException):
    def __init__(self, network_name: str, message=None, stdout=None, stderr=None) -> None:
        message = message or f"Docker network {network_name} not found"
        super().__init__(message, stdout, stderr)
        self.network_name = network_name


class RegistryConnectionError(ContainerException):
    def __init__(self, details: str, message=None, stdout=None, stderr=None) -> None:
        message = message or f"Connection error: {details}"
        super().__init__(message, stdout, stderr)
        self.details = details


class DockerNotAvailable(ContainerException):
    def __init__(self, message=None, stdout=None, stderr=None) -> None:
        message = message or "Docker not available"
        super().__init__(message, stdout, stderr)


class AccessDenied(ContainerException):
    def __init__(self, object_name: str, message=None, stdout=None, stderr=None) -> None:
        message = message or f"Access denied to {object_name}"
        super().__init__(message, stdout, stderr)
        self.object_name = object_name


class CancellableStream(Protocol):
    """Describes a generator that can be closed. Borrowed from ``docker.types.daemon``."""

    def __iter__(self):
        raise NotImplementedError

    def __next__(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class DockerPlatform(str):
    """Platform in the format ``os[/arch[/variant]]``"""

    linux_amd64 = "linux/amd64"
    linux_arm64 = "linux/arm64"


@dataclasses.dataclass
class Ulimit:
    """The ``ulimit`` settings for the container.
    See https://www.tutorialspoint.com/setting-ulimit-values-on-docker-containers
    """

    name: str
    soft_limit: int
    hard_limit: Optional[int] = None

    def __repr__(self):
        """Format: <type>=<soft limit>[:<hard limit>]"""
        ulimit_string = f"{self.name}={self.soft_limit}"
        if self.hard_limit:
            ulimit_string += f":{self.hard_limit}"
        return ulimit_string


# defines the type for port mappings (source->target port range)
PortRange = Union[List, HashableList]
# defines the protocol for a port range ("tcp" or "udp")
PortProtocol = str


def isinstance_union(obj, class_or_tuple):
    # that's some dirty hack
    if sys.version_info < (3, 10):
        return isinstance(obj, get_args(PortRange))
    else:
        return isinstance(obj, class_or_tuple)


class PortMappings:
    """Maps source to target port ranges for Docker port mappings."""

    # bind host to be used for defining port mappings
    bind_host: str
    # maps `from` port range to `to` port range for port mappings
    mappings: Dict[Tuple[PortRange, PortProtocol], List]

    def __init__(self, bind_host: str = None):
        self.bind_host = bind_host if bind_host else ""
        self.mappings = {}

    def add(
        self,
        port: Union[int, PortRange],
        mapped: Union[int, PortRange] = None,
        protocol: PortProtocol = "tcp",
    ):
        mapped = mapped or port
        if isinstance_union(port, PortRange):
            for i in range(port[1] - port[0] + 1):
                if isinstance_union(mapped, PortRange):
                    self.add(port[0] + i, mapped[0] + i, protocol)
                else:
                    self.add(port[0] + i, mapped, protocol)
            return
        if port is None or int(port) < 0:
            raise Exception(f"Unable to add mapping for invalid port: {port}")
        if self.contains(port, protocol):
            return
        bisected_host_port = None
        for (from_range, from_protocol), to_range in self.mappings.items():
            if not from_protocol == protocol:
                continue
            if not self.in_expanded_range(port, from_range):
                continue
            if not self.in_expanded_range(mapped, to_range):
                continue
            from_range_len = from_range[1] - from_range[0]
            to_range_len = to_range[1] - to_range[0]
            is_uniform = from_range_len == to_range_len
            if is_uniform:
                self.expand_range(port, from_range, protocol=protocol, remap=True)
                self.expand_range(mapped, to_range, protocol=protocol)
            else:
                if not self.in_range(mapped, to_range):
                    continue
                # extending a 1 to 1 mapping to be many to 1
                elif from_range_len == 1:
                    self.expand_range(port, from_range, protocol=protocol, remap=True)
                # splitting a uniform mapping
                else:
                    bisected_port_index = mapped - to_range[0]
                    bisected_host_port = from_range[0] + bisected_port_index
                    self.bisect_range(mapped, to_range, protocol=protocol)
                    self.bisect_range(bisected_host_port, from_range, protocol=protocol, remap=True)
                    break
            return
        if bisected_host_port is None:
            port_range = [port, port]
        elif bisected_host_port < port:
            port_range = [bisected_host_port, port]
        else:
            port_range = [port, bisected_host_port]
        protocol = str(protocol or "tcp").lower()
        self.mappings[(HashableList(port_range), protocol)] = [mapped, mapped]

    def to_str(self) -> str:
        bind_address = f"{self.bind_host}:" if self.bind_host else ""

        def entry(k, v):
            from_range, protocol = k
            to_range = v
            # use /<protocol> suffix if the protocol is not"tcp"
            protocol_suffix = f"/{protocol}" if protocol != "tcp" else ""
            if from_range[0] == from_range[1] and to_range[0] == to_range[1]:
                return f"-p {bind_address}{from_range[0]}:{to_range[0]}{protocol_suffix}"
            if from_range[0] != from_range[1] and to_range[0] == to_range[1]:
                return f"-p {bind_address}{from_range[0]}-{from_range[1]}:{to_range[0]}{protocol_suffix}"
            return f"-p {bind_address}{from_range[0]}-{from_range[1]}:{to_range[0]}-{to_range[1]}{protocol_suffix}"

        return " ".join([entry(k, v) for k, v in self.mappings.items()])

    def to_list(self) -> List[str]:  # TODO test
        bind_address = f"{self.bind_host}:" if self.bind_host else ""

        def entry(k, v):
            from_range, protocol = k
            to_range = v
            protocol_suffix = f"/{protocol}" if protocol != "tcp" else ""
            if from_range[0] == from_range[1] and to_range[0] == to_range[1]:
                return ["-p", f"{bind_address}{from_range[0]}:{to_range[0]}{protocol_suffix}"]
            return [
                "-p",
                f"{bind_address}{from_range[0]}-{from_range[1]}:{to_range[0]}-{to_range[1]}{protocol_suffix}",
            ]

        return [item for k, v in self.mappings.items() for item in entry(k, v)]

    def to_dict(self) -> Dict[str, Union[Tuple[str, Union[int, List[int]]], int]]:
        bind_address = self.bind_host or ""

        def bind_port(bind_address, host_port):
            if host_port == 0:
                return None
            elif bind_address:
                return (bind_address, host_port)
            else:
                return host_port

        def entry(k, v):
            from_range, protocol = k
            to_range = v
            protocol_suffix = f"/{protocol}"
            if from_range[0] != from_range[1] and to_range[0] == to_range[1]:
                container_port = to_range[0]
                host_ports = list(range(from_range[0], from_range[1] + 1))
                return [
                    (
                        f"{container_port}{protocol_suffix}",
                        (bind_address, host_ports) if bind_address else host_ports,
                    )
                ]
            return [
                (
                    f"{container_port}{protocol_suffix}",
                    bind_port(bind_address, host_port),
                )
                for container_port, host_port in zip(
                    range(to_range[0], to_range[1] + 1), range(from_range[0], from_range[1] + 1)
                )
            ]

        items = [item for k, v in self.mappings.items() for item in entry(k, v)]
        return dict(items)

    def contains(self, port: int, protocol: PortProtocol = "tcp") -> bool:
        for from_range_w_protocol, to_range in self.mappings.items():
            from_protocol = from_range_w_protocol[1]
            if from_protocol == protocol:
                from_range = from_range_w_protocol[0]
                if self.in_range(port, from_range):
                    return True

    def in_range(self, port: int, range: PortRange) -> bool:
        return port >= range[0] and port <= range[1]

    def in_expanded_range(self, port: int, range: PortRange):
        return port >= range[0] - 1 and port <= range[1] + 1

    def expand_range(
        self, port: int, range: PortRange, protocol: PortProtocol = "tcp", remap: bool = False
    ):
        """
        Expand the given port range by the given port. If remap==True, put the updated range into self.mappings
        """
        if self.in_range(port, range):
            return
        new_range = list(range) if remap else range
        if port == range[0] - 1:
            new_range[0] = port
        elif port == range[1] + 1:
            new_range[1] = port
        else:
            raise Exception(f"Unable to add port {port} to existing range {range}")
        if remap:
            self._remap_range(range, new_range, protocol=protocol)

    def bisect_range(
        self, port: int, range: PortRange, protocol: PortProtocol = "tcp", remap: bool = False
    ):
        """
        Bisect a port range, at the provided port. This is needed in some cases when adding a
        non-uniform host to port mapping adjacent to an existing port range.
        If remap==True, put the updated range into self.mappings
        """
        if not self.in_range(port, range):
            return
        new_range = list(range) if remap else range
        if port == range[0]:
            new_range[0] = port + 1
        else:
            new_range[1] = port - 1
        if remap:
            self._remap_range(range, new_range, protocol)

    def _remap_range(self, old_key: PortRange, new_key: PortRange, protocol: PortProtocol):
        self.mappings[(HashableList(new_key), protocol)] = self.mappings.pop(
            (HashableList(old_key), protocol)
        )

    def __repr__(self):
        return f"<PortMappings: {self.to_dict()}>"


SimpleVolumeBind = Tuple[str, str]
"""Type alias for a simple version of VolumeBind"""


@dataclasses.dataclass
class VolumeBind:
    """Represents a --volume argument run/create command. When using VolumeBind to bind-mount a file or directory
    that does not yet exist on the Docker host, -v creates the endpoint for you. It is always created as a directory.
    """

    host_dir: str
    container_dir: str
    read_only: bool = False

    def to_str(self) -> str:
        args = []

        if self.host_dir:
            args.append(self.host_dir)

        if not self.container_dir:
            raise ValueError("no container dir specified")

        args.append(self.container_dir)

        if self.read_only:
            args.append("ro")

        return ":".join(args)

    @classmethod
    def parse(cls, param: str) -> "VolumeBind":
        parts = param.split(":")
        if 1 > len(parts) > 3:
            raise ValueError(f"Cannot parse volume bind {param}")

        volume = cls(parts[0], parts[1])
        if len(parts) == 3:
            if "ro" in parts[2].split(","):
                volume.read_only = True
        return volume


class VolumeMappings:
    mappings: List[Union[SimpleVolumeBind, VolumeBind]]

    def __init__(self, mappings: List[Union[SimpleVolumeBind, VolumeBind]] = None):
        self.mappings = mappings if mappings is not None else []

    def add(self, mapping: Union[SimpleVolumeBind, VolumeBind]):
        self.append(mapping)

    def append(
        self,
        mapping: Union[
            SimpleVolumeBind,
            VolumeBind,
        ],
    ):
        self.mappings.append(mapping)

    def find_target_mapping(
        self, container_dir: str
    ) -> Optional[Union[SimpleVolumeBind, VolumeBind]]:
        """
        Looks through the volumes and returns the one where the container dir matches ``container_dir``.
        Returns None if there is no volume mapping to the given container directory.

        :param container_dir: the target of the volume mapping, i.e., the path in the container
        :return: the volume mapping or None
        """
        for volume in self.mappings:
            target_dir = volume[1] if isinstance(volume, tuple) else volume.container_dir
            if container_dir == target_dir:
                return volume
        return None

    def __iter__(self):
        return self.mappings.__iter__()

    def __repr__(self):
        return self.mappings.__repr__()


VolumeType = Literal["bind", "volume"]


class VolumeInfo(NamedTuple):
    """Container volume information."""

    type: VolumeType
    source: str
    destination: str
    mode: str
    rw: bool
    propagation: str
    name: Optional[str] = None
    driver: Optional[str] = None


@dataclasses.dataclass
class LogConfig:
    type: Literal["json-file", "syslog", "journald", "gelf", "fluentd", "none", "awslogs", "splunk"]
    config: Dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ContainerConfiguration:
    image_name: str
    name: Optional[str] = None
    volumes: VolumeMappings = dataclasses.field(default_factory=VolumeMappings)
    ports: PortMappings = dataclasses.field(default_factory=PortMappings)
    exposed_ports: List[str] = dataclasses.field(default_factory=list)
    entrypoint: Optional[str] = None
    additional_flags: Optional[str] = None
    command: Optional[List[str]] = None
    env_vars: Dict[str, str] = dataclasses.field(default_factory=dict)

    privileged: bool = False
    remove: bool = False
    interactive: bool = False
    tty: bool = False
    detach: bool = False

    stdin: Optional[str] = None
    user: Optional[str] = None
    cap_add: Optional[List[str]] = None
    cap_drop: Optional[List[str]] = None
    security_opt: Optional[List[str]] = None
    network: Optional[str] = None
    dns: Optional[str] = None
    workdir: Optional[str] = None
    platform: Optional[str] = None
    ulimits: Optional[List[Ulimit]] = None
    labels: Optional[Dict[str, str]] = None
    init: Optional[bool] = None
    log_config: Optional[LogConfig] = None


class ContainerConfigurator(Protocol):
    """Protocol for functional configurators. A ContainerConfigurator modifies, when called,
    a ContainerConfiguration in place."""

    def __call__(self, configuration: ContainerConfiguration):
        """
        Modify the given container configuration.

        :param configuration: the configuration to modify
        """
        ...


@dataclasses.dataclass
class DockerRunFlags:
    """Class to capture Docker run/create flags for a container.
    run: https://docs.docker.com/engine/reference/commandline/run/
    create: https://docs.docker.com/engine/reference/commandline/create/
    """

    env_vars: Optional[Dict[str, str]]
    extra_hosts: Optional[Dict[str, str]]
    labels: Optional[Dict[str, str]]
    mounts: Optional[List[SimpleVolumeBind]]
    network: Optional[str]
    platform: Optional[DockerPlatform]
    privileged: Optional[bool]
    ports: Optional[PortMappings]
    ulimits: Optional[List[Ulimit]]
    user: Optional[str]
    dns: Optional[List[str]]


# TODO: remove Docker/Podman compatibility switches (in particular strip_wellknown_repo_prefixes=...)
#  from the container client base interface and introduce derived Podman client implementations instead!
class ContainerClient(metaclass=ABCMeta):
    @abstractmethod
    def get_system_info(self) -> dict:
        """Returns the docker system-wide information as dictionary (``docker info``)."""

    def get_system_id(self) -> str:
        """Returns the unique and stable ID of the docker daemon."""
        return self.get_system_info()["ID"]

    @abstractmethod
    def get_container_status(self, container_name: str) -> DockerContainerStatus:
        """Returns the status of the container with the given name"""
        pass

    def get_networks(self, container_name: str) -> List[str]:
        LOG.debug("Getting networks for container: %s", container_name)
        container_attrs = self.inspect_container(container_name_or_id=container_name)
        return list(container_attrs["NetworkSettings"].get("Networks", {}).keys())

    def get_container_ipv4_for_network(
        self, container_name_or_id: str, container_network: str
    ) -> str:
        """
        Returns the IPv4 address for the container on the interface connected to the given network
        :param container_name_or_id: Container to inspect
        :param container_network: Network the IP address will belong to
        :return: IP address of the given container on the interface connected to the given network
        """
        LOG.debug(
            "Getting ipv4 address for container %s in network %s.",
            container_name_or_id,
            container_network,
        )
        # we always need the ID for this
        container_id = self.get_container_id(container_name=container_name_or_id)
        network_attrs = self.inspect_network(container_network)
        containers = network_attrs.get("Containers") or {}
        if container_id not in containers:
            LOG.debug("Network attributes: %s", network_attrs)
            try:
                inspection = self.inspect_container(container_name_or_id=container_name_or_id)
                LOG.debug("Container %s Attributes: %s", container_name_or_id, inspection)
                logs = self.get_container_logs(container_name_or_id=container_name_or_id)
                LOG.debug("Container %s Logs: %s", container_name_or_id, logs)
            except ContainerException as e:
                LOG.debug("Cannot inspect container %s: %s", container_name_or_id, e)
            raise ContainerException(
                "Container %s is not connected to target network %s",
                container_name_or_id,
                container_network,
            )
        try:
            ip = str(ipaddress.IPv4Interface(containers[container_id]["IPv4Address"]).ip)
        except Exception as e:
            raise ContainerException(
                f"Unable to detect IP address for container {container_name_or_id} in network {container_network}: {e}"
            )
        return ip

    @abstractmethod
    def stop_container(self, container_name: str, timeout: int = 10):
        """Stops container with given name
        :param container_name: Container identifier (name or id) of the container to be stopped
        :param timeout: Timeout after which SIGKILL is sent to the container.
        """

    @abstractmethod
    def restart_container(self, container_name: str, timeout: int = 10):
        """Restarts a container with the given name.
        :param container_name: Container identifier
        :param timeout: Seconds to wait for stop before killing the container
        """

    @abstractmethod
    def pause_container(self, container_name: str):
        """Pauses a container with the given name."""

    @abstractmethod
    def unpause_container(self, container_name: str):
        """Unpauses a container with the given name."""

    @abstractmethod
    def remove_container(self, container_name: str, force=True, check_existence=False) -> None:
        """Removes container with given name"""

    @abstractmethod
    def remove_image(self, image: str, force: bool = True) -> None:
        """Removes an image with given name

        :param image: Image name and tag
        :param force: Force removal
        """

    @abstractmethod
    def list_containers(self, filter: Union[List[str], str, None] = None, all=True) -> List[dict]:
        """List all containers matching the given filters

        :return: A list of dicts with keys id, image, name, labels, status
        """

    def get_running_container_names(self) -> List[str]:
        """Returns a list of the names of all running containers"""
        result = self.list_containers(all=False)
        result = [container["name"] for container in result]
        return result

    def is_container_running(self, container_name: str) -> bool:
        """Checks whether a container with a given name is currently running"""
        return container_name in self.get_running_container_names()

    @abstractmethod
    def copy_into_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        """Copy contents of the given local path into the container"""

    @abstractmethod
    def copy_from_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        """Copy contents of the given container to the host"""

    @abstractmethod
    def pull_image(self, docker_image: str, platform: Optional[DockerPlatform] = None) -> None:
        """Pulls an image with a given name from a Docker registry"""

    @abstractmethod
    def push_image(self, docker_image: str) -> None:
        """Pushes an image with a given name to a Docker registry"""

    @abstractmethod
    def build_image(
        self,
        dockerfile_path: str,
        image_name: str,
        context_path: str = None,
        platform: Optional[DockerPlatform] = None,
    ) -> None:
        """Builds an image from the given Dockerfile

        :param dockerfile_path: Path to Dockerfile, or a directory that contains a Dockerfile
        :param image_name: Name of the image to be built
        :param context_path: Path for build context (defaults to dirname of Dockerfile)
        :param platform: Target platform for build (defaults to platform of Docker host)
        """

    @abstractmethod
    def tag_image(self, source_ref: str, target_name: str) -> None:
        """Tags an image with a new name

        :param source_ref: Name or ID of the image to be tagged
        :param target_name: New name (tag) of the tagged image
        """

    @abstractmethod
    def get_docker_image_names(
        self,
        strip_latest: bool = True,
        include_tags: bool = True,
        strip_wellknown_repo_prefixes: bool = True,
    ) -> List[str]:
        """
        Get all names of docker images available to the container engine
        :param strip_latest: return images both with and without :latest tag
        :param include_tags: include tags of the images in the names
        :param strip_wellknown_repo_prefixes: whether to strip off well-known repo prefixes like
               "localhost/" or "docker.io/library/" which are added by the Podman API, but not by Docker
        :return: List of image names
        """

    @abstractmethod
    def get_container_logs(self, container_name_or_id: str, safe: bool = False) -> str:
        """Get all logs of a given container"""

    @abstractmethod
    def stream_container_logs(self, container_name_or_id: str) -> CancellableStream:
        """Returns a blocking generator you can iterate over to retrieve log output as it happens."""

    @abstractmethod
    def inspect_container(self, container_name_or_id: str) -> Dict[str, Union[Dict, str]]:
        """Get detailed attributes of a container.

        :return: Dict containing docker attributes as returned by the daemon
        """

    def inspect_container_volumes(self, container_name_or_id) -> List[VolumeInfo]:
        """Return information about the volumes mounted into the given container.

        :param container_name_or_id: the container name or id
        :return: a list of volumes
        """
        volumes = []
        for doc in self.inspect_container(container_name_or_id)["Mounts"]:
            volumes.append(VolumeInfo(**{k.lower(): v for k, v in doc.items()}))

        return volumes

    @abstractmethod
    def inspect_image(
        self, image_name: str, pull: bool = True, strip_wellknown_repo_prefixes: bool = True
    ) -> Dict[str, Union[dict, list, str]]:
        """Get detailed attributes of an image.

        :param image_name: Image name to inspect
        :param pull: Whether to pull image if not existent
        :param strip_wellknown_repo_prefixes: whether to strip off well-known repo prefixes like
               "localhost/" or "docker.io/library/" which are added by the Podman API, but not by Docker
        :return: Dict containing docker attributes as returned by the daemon
        """

    @abstractmethod
    def create_network(self, network_name: str) -> str:
        """
        Creates a network with the given name
        :param network_name: Name of the network
        :return Network ID
        """

    @abstractmethod
    def delete_network(self, network_name: str) -> None:
        """
        Delete a network with the given name
        :param network_name: Name of the network
        """

    @abstractmethod
    def inspect_network(self, network_name: str) -> Dict[str, Union[Dict, str]]:
        """Get detailed attributes of an network.

        :return: Dict containing docker attributes as returned by the daemon
        """

    @abstractmethod
    def connect_container_to_network(
        self,
        network_name: str,
        container_name_or_id: str,
        aliases: Optional[List] = None,
        link_local_ips: List[str] = None,
    ) -> None:
        """
        Connects a container to a given network
        :param network_name: Network to connect the container to
        :param container_name_or_id: Container to connect to the network
        :param aliases: List of dns names the container should be available under in the network
        :param link_local_ips: List of link-local (IPv4 or IPv6) addresses
        """

    @abstractmethod
    def disconnect_container_from_network(
        self, network_name: str, container_name_or_id: str
    ) -> None:
        """
        Disconnects a container from a given network
        :param network_name: Network to disconnect the container from
        :param container_name_or_id: Container to disconnect from the network
        """

    def get_container_name(self, container_id: str) -> str:
        """Get the name of a container by a given identifier"""
        return self.inspect_container(container_id)["Name"].lstrip("/")

    def get_container_id(self, container_name: str) -> str:
        """Get the id of a container by a given name"""
        return self.inspect_container(container_name)["Id"]

    @abstractmethod
    def get_container_ip(self, container_name_or_id: str) -> str:
        """Get the IP address of a given container

        If container has multiple networks, it will return the IP of the first
        """

    def get_image_cmd(self, docker_image: str, pull: bool = True) -> List[str]:
        """Get the command for the given image
        :param docker_image: Docker image to inspect
        :param pull: Whether to pull if image is not present
        :return: Image command in its array form
        """
        cmd_list = self.inspect_image(docker_image, pull)["Config"]["Cmd"] or []
        return cmd_list

    def get_image_entrypoint(self, docker_image: str, pull: bool = True) -> str:
        """Get the entry point for the given image
        :param docker_image: Docker image to inspect
        :param pull: Whether to pull if image is not present
        :return: Image entrypoint
        """
        LOG.debug("Getting the entrypoint for image: %s", docker_image)
        entrypoint_list = self.inspect_image(docker_image, pull)["Config"].get("Entrypoint") or []
        return shlex.join(entrypoint_list)

    @abstractmethod
    def has_docker(self) -> bool:
        """Check if system has docker available"""

    @abstractmethod
    def commit(
        self,
        container_name_or_id: str,
        image_name: str,
        image_tag: str,
    ):
        """Create an image from a running container.

        :param container_name_or_id: Source container
        :param image_name: Destination image name
        :param image_tag: Destination image tag
        """

    def create_container_from_config(self, container_config: ContainerConfiguration) -> str:
        """
        Similar to create_container, but allows passing the whole ContainerConfiguration
        :param container_config: ContainerConfiguration how to start the container
        :return: Container ID
        """
        return self.create_container(
            image_name=container_config.image_name,
            name=container_config.name,
            entrypoint=container_config.entrypoint,
            remove=container_config.remove,
            interactive=container_config.interactive,
            tty=container_config.tty,
            command=container_config.command,
            mount_volumes=container_config.volumes,
            ports=container_config.ports,
            exposed_ports=container_config.exposed_ports,
            env_vars=container_config.env_vars,
            user=container_config.user,
            cap_add=container_config.cap_add,
            cap_drop=container_config.cap_drop,
            security_opt=container_config.security_opt,
            network=container_config.network,
            dns=container_config.dns,
            additional_flags=container_config.additional_flags,
            workdir=container_config.workdir,
            privileged=container_config.privileged,
            platform=container_config.platform,
            labels=container_config.labels,
            ulimits=container_config.ulimits,
            init=container_config.init,
        )

    @abstractmethod
    def create_container(
        self,
        image_name: str,
        *,
        name: Optional[str] = None,
        entrypoint: Optional[str] = None,
        remove: bool = False,
        interactive: bool = False,
        tty: bool = False,
        detach: bool = False,
        command: Optional[Union[List[str], str]] = None,
        mount_volumes: Optional[Union[VolumeMappings, List[SimpleVolumeBind]]] = None,
        ports: Optional[PortMappings] = None,
        exposed_ports: Optional[List[str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
        user: Optional[str] = None,
        cap_add: Optional[List[str]] = None,
        cap_drop: Optional[List[str]] = None,
        security_opt: Optional[List[str]] = None,
        network: Optional[str] = None,
        dns: Optional[Union[str, List[str]]] = None,
        additional_flags: Optional[str] = None,
        workdir: Optional[str] = None,
        privileged: Optional[bool] = None,
        labels: Optional[Dict[str, str]] = None,
        platform: Optional[DockerPlatform] = None,
        ulimits: Optional[List[Ulimit]] = None,
        init: Optional[bool] = None,
        log_config: Optional[LogConfig] = None,
    ) -> str:
        """Creates a container with the given image

        :return: Container ID
        """

    @abstractmethod
    def run_container(
        self,
        image_name: str,
        stdin: bytes = None,
        *,
        name: Optional[str] = None,
        entrypoint: Optional[str] = None,
        remove: bool = False,
        interactive: bool = False,
        tty: bool = False,
        detach: bool = False,
        command: Optional[Union[List[str], str]] = None,
        mount_volumes: Optional[Union[VolumeMappings, List[SimpleVolumeBind]]] = None,
        ports: Optional[PortMappings] = None,
        exposed_ports: Optional[List[str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
        user: Optional[str] = None,
        cap_add: Optional[List[str]] = None,
        cap_drop: Optional[List[str]] = None,
        security_opt: Optional[List[str]] = None,
        network: Optional[str] = None,
        dns: Optional[str] = None,
        additional_flags: Optional[str] = None,
        workdir: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        platform: Optional[DockerPlatform] = None,
        privileged: Optional[bool] = None,
        ulimits: Optional[List[Ulimit]] = None,
        init: Optional[bool] = None,
        log_config: Optional[LogConfig] = None,
    ) -> Tuple[bytes, bytes]:
        """Creates and runs a given docker container

        :return: A tuple (stdout, stderr)
        """

    def run_container_from_config(
        self, container_config: ContainerConfiguration
    ) -> Tuple[bytes, bytes]:
        """Like ``run_container`` but uses the parameters from the configuration."""

        return self.run_container(
            image_name=container_config.image_name,
            stdin=container_config.stdin,
            name=container_config.name,
            entrypoint=container_config.entrypoint,
            remove=container_config.remove,
            interactive=container_config.interactive,
            tty=container_config.tty,
            detach=container_config.detach,
            command=container_config.command,
            mount_volumes=container_config.volumes,
            ports=container_config.ports,
            exposed_ports=container_config.exposed_ports,
            env_vars=container_config.env_vars,
            user=container_config.user,
            cap_add=container_config.cap_add,
            cap_drop=container_config.cap_drop,
            security_opt=container_config.security_opt,
            network=container_config.network,
            dns=container_config.dns,
            additional_flags=container_config.additional_flags,
            workdir=container_config.workdir,
            platform=container_config.platform,
            privileged=container_config.privileged,
            ulimits=container_config.ulimits,
            init=container_config.init,
            log_config=container_config.log_config,
        )

    @abstractmethod
    def exec_in_container(
        self,
        container_name_or_id: str,
        command: Union[List[str], str],
        interactive: bool = False,
        detach: bool = False,
        env_vars: Optional[Dict[str, Optional[str]]] = None,
        stdin: Optional[bytes] = None,
        user: Optional[str] = None,
        workdir: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        """Execute a given command in a container

        :return: A tuple (stdout, stderr)
        """

    @abstractmethod
    def start_container(
        self,
        container_name_or_id: str,
        stdin: bytes = None,
        interactive: bool = False,
        attach: bool = False,
        flags: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        """Start a given, already created container

        :return: A tuple (stdout, stderr) if attach or interactive is set, otherwise a tuple (b"container_name_or_id", b"")
        """

    @abstractmethod
    def attach_to_container(self, container_name_or_id: str):
        """
        Attach local standard input, output, and error streams to a running container
        """

    @abstractmethod
    def login(self, username: str, password: str, registry: Optional[str] = None) -> None:
        """
        Login into an OCI registry

        :param username: Username for the registry
        :param password: Password / token for the registry
        :param registry: Registry url
        """


class Util:
    MAX_ENV_ARGS_LENGTH = 20000

    @staticmethod
    def format_env_vars(key: str, value: Optional[str]):
        if value is None:
            return key
        return f"{key}={value}"

    @classmethod
    def create_env_vars_file_flag(cls, env_vars: Dict) -> Tuple[List[str], Optional[str]]:
        if not env_vars:
            return [], None
        result = []
        env_vars = dict(env_vars)
        env_file = None
        if len(str(env_vars)) > cls.MAX_ENV_ARGS_LENGTH:
            # default ARG_MAX=131072 in Docker - let's create an env var file if the string becomes too long...
            env_file = cls.mountable_tmp_file()
            env_content = ""
            for name, value in dict(env_vars).items():
                if len(value) > cls.MAX_ENV_ARGS_LENGTH:
                    # each line in the env file has a max size as well (error "bufio.Scanner: token too long")
                    continue
                env_vars.pop(name)
                value = value.replace("\n", "\\")
                env_content += f"{cls.format_env_vars(name, value)}\n"
            save_file(env_file, env_content)
            result += ["--env-file", env_file]

        env_vars_res = [
            item for k, v in env_vars.items() for item in ["-e", cls.format_env_vars(k, v)]
        ]
        result += env_vars_res
        return result, env_file

    @staticmethod
    def rm_env_vars_file(env_vars_file) -> None:
        if env_vars_file:
            return rm_rf(env_vars_file)

    @staticmethod
    def mountable_tmp_file():
        f = os.path.join(config.dirs.mounted_tmp, short_uid())
        TMP_FILES.append(f)
        return f

    @staticmethod
    def append_without_latest(image_names: List[str]):
        suffix = ":latest"
        for image in list(image_names):
            if image.endswith(suffix):
                image_names.append(image[: -len(suffix)])

    @staticmethod
    def strip_wellknown_repo_prefixes(image_names: List[str]) -> List[str]:
        """
        Remove well-known repo prefixes like `localhost/` or `docker.io/library/` from the list of given
        image names. This is mostly to ensure compatibility of our Docker client with Podman API responses.
        :return: a copy of the list of image names, with well-known repo prefixes removed
        """
        result = []
        for image in image_names:
            for prefix in WELL_KNOWN_IMAGE_REPO_PREFIXES:
                if image.startswith(prefix):
                    image = image.removeprefix(prefix)
                    # strip only one of the matching prefixes (avoid multi-stripping)
                    break
            result.append(image)
        return result

    @staticmethod
    def tar_path(path: str, target_path: str, is_dir: bool):
        f = tempfile.NamedTemporaryFile()
        with tarfile.open(mode="w", fileobj=f) as t:
            abs_path = os.path.abspath(path)
            arcname = (
                os.path.basename(path)
                if is_dir
                else (os.path.basename(target_path) or os.path.basename(path))
            )
            t.add(abs_path, arcname=arcname)

        f.seek(0)
        return f

    @staticmethod
    def untar_to_path(tardata, target_path):
        target_path = Path(target_path)
        with tarfile.open(mode="r", fileobj=io.BytesIO(b"".join(b for b in tardata))) as t:
            if target_path.is_dir():
                t.extractall(path=target_path)
            else:
                member = t.next()
                if member:
                    member.name = target_path.name
                    t.extract(member, target_path.parent)
                else:
                    LOG.debug("File to copy empty, ignoring...")

    @staticmethod
    def _read_docker_cli_env_file(env_file: str) -> Dict[str, str]:
        """
        Read an environment file in docker CLI format, specified here:
        https://docs.docker.com/reference/cli/docker/container/run/#env
        :param env_file: Path to the environment file
        :return: Read environment variables
        """
        env_vars = {}
        try:
            with open(env_file, mode="rt") as f:
                env_file_lines = f.readlines()
        except FileNotFoundError as e:
            LOG.error(
                "Specified env file '%s' not found. Please make sure the file is properly mounted into the LocalStack container. Error: %s",
                env_file,
                e,
            )
            raise
        except OSError as e:
            LOG.error(
                "Could not read env file '%s'. Please make sure the LocalStack container has the permissions to read it. Error: %s",
                env_file,
                e,
            )
            raise
        for idx, line in enumerate(env_file_lines):
            line = line.strip()
            if not line or line.startswith("#"):
                # skip comments or empty lines
                continue
            lhs, separator, rhs = line.partition("=")
            if rhs or separator:
                env_vars[lhs] = rhs
            else:
                # No "=" in the line, only the name => lookup in local env
                if env_value := os.environ.get(lhs):
                    env_vars[lhs] = env_value
        return env_vars

    @staticmethod
    def parse_additional_flags(
        additional_flags: str,
        env_vars: Optional[Dict[str, str]] = None,
        labels: Optional[Dict[str, str]] = None,
        mounts: Optional[List[SimpleVolumeBind]] = None,
        network: Optional[str] = None,
        platform: Optional[DockerPlatform] = None,
        ports: Optional[PortMappings] = None,
        privileged: Optional[bool] = None,
        user: Optional[str] = None,
        ulimits: Optional[List[Ulimit]] = None,
        dns: Optional[Union[str, List[str]]] = None,
    ) -> DockerRunFlags:
        """Parses additional CLI-formatted Docker flags, which could overwrite provided defaults.
        :param additional_flags: String which contains the flag definitions inspired by the Docker CLI reference:
                                 https://docs.docker.com/engine/reference/commandline/run/
        :param env_vars: Dict with env vars. Will be modified in place.
        :param labels: Dict with labels. Will be modified in place.
        :param mounts: List of mount tuples (host_path, container_path). Will be modified in place.
        :param network: Existing network name (optional). Warning will be printed if network is overwritten in flags.
        :param platform: Platform to execute container. Warning will be printed if platform is overwritten in flags.
        :param ports: PortMapping object. Will be modified in place.
        :param privileged: Run the container in privileged mode. Warning will be printed if overwritten in flags.
        :param ulimits: ulimit options in the format <type>=<soft limit>[:<hard limit>]
        :param user: User to run first process. Warning will be printed if user is overwritten in flags.
        :param dns: List of DNS servers to configure the container with.
        :return: A DockerRunFlags object that will return new objects if respective parameters were None and
                additional flags contained a flag for that object or the same which are passed otherwise.
        """
        # Argparse refactoring opportunity: custom argparse actions can be used to modularize parsing (e.g., key=value)
        # https://docs.python.org/3/library/argparse.html#action

        # Configure parser
        parser = NoExitArgumentParser(description="Docker run flags parser")
        parser.add_argument(
            "--add-host",
            help="Add a custom host-to-IP mapping (host:ip)",
            dest="add_hosts",
            action="append",
        )
        parser.add_argument(
            "--env", "-e", help="Set environment variables", dest="envs", action="append"
        )
        parser.add_argument(
            "--env-file",
            help="Set environment variables via a file",
            dest="env_files",
            action="append",
        )
        parser.add_argument(
            "--compose-env-file",
            help="Set environment variables via a file, with a docker-compose supported feature set.",
            dest="compose_env_files",
            action="append",
        )
        parser.add_argument(
            "--label", "-l", help="Add container meta data", dest="labels", action="append"
        )
        parser.add_argument("--network", help="Connect a container to a network")
        parser.add_argument(
            "--platform",
            type=DockerPlatform,
            help="Docker platform (e.g., linux/amd64 or linux/arm64)",
        )
        parser.add_argument(
            "--privileged",
            help="Give extended privileges to this container",
            action="store_true",
        )
        parser.add_argument(
            "--publish",
            "-p",
            help="Publish container port(s) to the host",
            dest="publish_ports",
            action="append",
        )
        parser.add_argument(
            "--ulimit", help="Container ulimit settings", dest="ulimits", action="append"
        )
        parser.add_argument("--user", "-u", help="Username or UID to execute first process")
        parser.add_argument(
            "--volume", "-v", help="Bind mount a volume", dest="volumes", action="append"
        )
        parser.add_argument("--dns", help="Set custom DNS servers", dest="dns", action="append")

        # Parse
        flags = shlex.split(additional_flags)
        args = parser.parse_args(flags)

        # Post-process parsed flags
        extra_hosts = None
        if args.add_hosts:
            for add_host in args.add_hosts:
                extra_hosts = extra_hosts if extra_hosts is not None else {}
                hosts_split = add_host.split(":")
                extra_hosts[hosts_split[0]] = hosts_split[1]

        # set env file values before env values, as the latter override the earlier
        if args.env_files:
            env_vars = env_vars if env_vars is not None else {}
            for env_file in args.env_files:
                env_vars.update(Util._read_docker_cli_env_file(env_file))

        if args.compose_env_files:
            env_vars = env_vars if env_vars is not None else {}
            for env_file in args.compose_env_files:
                env_vars.update(dotenv.dotenv_values(env_file))

        if args.envs:
            env_vars = env_vars if env_vars is not None else {}
            for env in args.envs:
                lhs, _, rhs = env.partition("=")
                env_vars[lhs] = rhs

        if args.labels:
            labels = labels if labels is not None else {}
            for label in args.labels:
                key, _, value = label.partition("=")
                # Only consider non-empty labels
                if key:
                    labels[key] = value

        if args.network:
            LOG.warning(
                "Overwriting Docker container network '%s' with new value '%s'",
                network,
                args.network,
            )
            network = args.network

        if args.platform:
            LOG.warning(
                "Overwriting Docker platform '%s' with new value '%s'",
                platform,
                args.platform,
            )
            platform = args.platform

        if args.privileged:
            LOG.warning(
                "Overwriting Docker container privileged flag %s with new value %s",
                privileged,
                args.privileged,
            )
            privileged = args.privileged

        if args.publish_ports:
            for port_mapping in args.publish_ports:
                port_split = port_mapping.split(":")
                protocol = "tcp"
                if len(port_split) == 2:
                    host_port, container_port = port_split
                elif len(port_split) == 3:
                    LOG.warning(
                        "Host part of port mappings are ignored currently in additional flags"
                    )
                    _, host_port, container_port = port_split
                else:
                    raise ValueError(f"Invalid port string provided: {port_mapping}")
                host_port_split = host_port.split("-")
                if len(host_port_split) == 2:
                    host_port = [int(host_port_split[0]), int(host_port_split[1])]
                elif len(host_port_split) == 1:
                    host_port = int(host_port)
                else:
                    raise ValueError(f"Invalid port string provided: {port_mapping}")
                if "/" in container_port:
                    container_port, protocol = container_port.split("/")
                ports = ports if ports is not None else PortMappings()
                ports.add(host_port, int(container_port), protocol)

        if args.ulimits:
            ulimits = ulimits if ulimits is not None else []
            ulimits_dict = {ul.name: ul for ul in ulimits}
            for ulimit in args.ulimits:
                name, _, rhs = ulimit.partition("=")
                soft, _, hard = rhs.partition(":")
                hard_limit = int(hard) if hard else int(soft)
                new_ulimit = Ulimit(name=name, soft_limit=int(soft), hard_limit=hard_limit)
                if ulimits_dict.get(name):
                    LOG.warning(f"Overwriting Docker ulimit {new_ulimit}")
                ulimits_dict[name] = new_ulimit
            ulimits = list(ulimits_dict.values())

        if args.user:
            LOG.warning(
                "Overwriting Docker user '%s' with new value '%s'",
                user,
                args.user,
            )
            user = args.user

        if args.volumes:
            mounts = mounts if mounts is not None else []
            for volume in args.volumes:
                match = re.match(
                    r"(?P<host>[\w\s\\\/:\-.]+?):(?P<container>[\w\s\/\-.]+)(?::(?P<arg>ro|rw|z|Z))?",
                    volume,
                )
                if not match:
                    LOG.warning("Unable to parse volume mount Docker flags: %s", volume)
                    continue
                host_path = match.group("host")
                container_path = match.group("container")
                rw_args = match.group("arg")
                if rw_args:
                    LOG.info("Volume options like :ro or :rw are currently ignored.")
                mounts.append((host_path, container_path))

        dns = ensure_list(dns or [])
        if args.dns:
            LOG.info(
                "Extending Docker container DNS servers %s with additional values %s", dns, args.dns
            )
            dns.extend(args.dns)

        return DockerRunFlags(
            env_vars=env_vars,
            extra_hosts=extra_hosts,
            labels=labels,
            mounts=mounts,
            ports=ports,
            network=network,
            platform=platform,
            privileged=privileged,
            ulimits=ulimits,
            user=user,
            dns=dns,
        )

    @staticmethod
    def convert_mount_list_to_dict(
        mount_volumes: Union[List[SimpleVolumeBind], VolumeMappings],
    ) -> Dict[str, Dict[str, str]]:
        """Converts a List of (host_path, container_path) tuples to a Dict suitable as volume argument for docker sdk"""

        def _map_to_dict(paths: SimpleVolumeBind | VolumeBind):
            if isinstance(paths, VolumeBind):
                return str(paths.host_dir), {
                    "bind": paths.container_dir,
                    "mode": "ro" if paths.read_only else "rw",
                }
            else:
                return str(paths[0]), {"bind": paths[1], "mode": "rw"}

        return dict(
            map(
                _map_to_dict,
                mount_volumes,
            )
        )

    @staticmethod
    def resolve_dockerfile_path(dockerfile_path: str) -> str:
        """If the given path is a directory that contains a Dockerfile, then return the file path to it."""
        rel_path = os.path.join(dockerfile_path, "Dockerfile")
        if os.path.isdir(dockerfile_path) and os.path.exists(rel_path):
            return rel_path
        return dockerfile_path
