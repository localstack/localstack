import dataclasses
import io
import ipaddress
import logging
import os
import re
import shlex
import tarfile
import tempfile
from abc import ABCMeta, abstractmethod
from enum import Enum, unique
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from localstack import config
from localstack.utils.common import TMP_FILES, HashableList, rm_rf, save_file, short_uid

LOG = logging.getLogger(__name__)


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


class PortMappings(object):
    """Maps source to target port ranges for Docker port mappings."""

    def __init__(self, bind_host=None):
        self.bind_host = bind_host if bind_host else ""
        self.mappings = {}

    def add(self, port, mapped=None, protocol="tcp"):
        mapped = mapped or port
        if isinstance(port, list):
            for i in range(port[1] - port[0] + 1):
                if isinstance(mapped, list):
                    self.add(port[0] + i, mapped[0] + i)
                else:
                    self.add(port[0] + i, mapped)
            return
        if port is None or int(port) <= 0:
            raise Exception("Unable to add mapping for invalid port: %s" % port)
        if self.contains(port):
            return
        bisected_host_port = None
        for from_range, to_range in self.mappings.items():
            if not self.in_expanded_range(port, from_range):
                continue
            if not self.in_expanded_range(mapped, to_range):
                continue
            from_range_len = from_range[1] - from_range[0]
            to_range_len = to_range[1] - to_range[0]
            is_uniform = from_range_len == to_range_len
            if is_uniform:
                self.expand_range(port, from_range)
                self.expand_range(mapped, to_range)
            else:
                if not self.in_range(mapped, to_range):
                    continue
                # extending a 1 to 1 mapping to be many to 1
                elif from_range_len == 1:
                    self.expand_range(port, from_range)
                # splitting a uniform mapping
                else:
                    bisected_port_index = mapped - to_range[0]
                    bisected_host_port = from_range[0] + bisected_port_index
                    self.bisect_range(mapped, to_range)
                    self.bisect_range(bisected_host_port, from_range)
                    break
            return
        protocol = str(protocol or "tcp").lower()
        if bisected_host_port is None:
            port_range = [port, port, protocol]
        elif bisected_host_port < port:
            port_range = [bisected_host_port, port, protocol]
        else:
            port_range = [port, bisected_host_port, protocol]
        self.mappings[HashableList(port_range)] = [mapped, mapped]

    def to_str(self) -> str:
        bind_address = f"{self.bind_host}:" if self.bind_host else ""

        def entry(k, v):
            protocol = "/%s" % k[2] if k[2] != "tcp" else ""
            if k[0] == k[1] and v[0] == v[1]:
                return "-p %s%s:%s%s" % (bind_address, k[0], v[0], protocol)
            if k[0] != k[1] and v[0] == v[1]:
                return "-p %s%s-%s:%s%s" % (bind_address, k[0], k[1], v[0], protocol)
            return "-p %s%s-%s:%s-%s%s" % (bind_address, k[0], k[1], v[0], v[1], protocol)

        return " ".join([entry(k, v) for k, v in self.mappings.items()])

    def to_list(self) -> List[str]:  # TODO test
        bind_address = f"{self.bind_host}:" if self.bind_host else ""

        def entry(k, v):
            protocol = "/%s" % k[2] if k[2] != "tcp" else ""
            if k[0] == k[1] and v[0] == v[1]:
                return ["-p", f"{bind_address}{k[0]}:{v[0]}{protocol}"]
            return ["-p", f"{bind_address}{k[0]}-{k[1]}:{v[0]}-{v[1]}{protocol}"]

        return [item for k, v in self.mappings.items() for item in entry(k, v)]

    def to_dict(self) -> Dict[str, Union[Tuple[str, Union[int, List[int]]], int]]:
        bind_address = self.bind_host or ""

        def entry(k, v):
            protocol = "/%s" % k[2]
            if k[0] != k[1] and v[0] == v[1]:
                container_port = v[0]
                host_ports = list(range(k[0], k[1] + 1))
                return [
                    (
                        f"{container_port}{protocol}",
                        (bind_address, host_ports) if bind_address else host_ports,
                    )
                ]
            return [
                (
                    f"{container_port}{protocol}",
                    (bind_address, host_port) if bind_address else host_port,
                )
                for container_port, host_port in zip(range(v[0], v[1] + 1), range(k[0], k[1] + 1))
            ]

        items = [item for k, v in self.mappings.items() for item in entry(k, v)]
        return dict(items)

    def contains(self, port):
        for from_range, to_range in self.mappings.items():
            if self.in_range(port, from_range):
                return True

    def in_range(self, port, range):
        return port >= range[0] and port <= range[1]

    def in_expanded_range(self, port, range):
        return port >= range[0] - 1 and port <= range[1] + 1

    def expand_range(self, port, range):
        if self.in_range(port, range):
            return
        if port == range[0] - 1:
            range[0] = port
        elif port == range[1] + 1:
            range[1] = port
        else:
            raise Exception("Unable to add port %s to existing range %s" % (port, range))

    """Bisect a port range, at the provided port
        This is needed in some cases when adding a non-uniform host to port mapping
        adjacent to an existing port range
    """

    def bisect_range(self, port, range):
        if not self.in_range(port, range):
            return
        if port == range[0]:
            range[0] = port + 1
        else:
            range[1] = port - 1

    def __repr__(self):
        return f"<PortMappings: {self.to_dict()}>"


SimpleVolumeBind = Tuple[str, str]


@dataclasses.dataclass
class VolumeBind:
    """Represents a --volume argument run/create command. When using VolumeBind to bind-mount a file or directory
    that does not yet exist on the Docker host, -v creates the endpoint for you. It is always created as a directory.
    """

    host_dir: str
    container_dir: str
    options: Optional[List[str]] = None

    def to_str(self) -> str:
        args = []

        if self.host_dir:
            args.append(self.host_dir)

        if not self.container_dir:
            raise ValueError("no container dir specified")

        args.append(self.container_dir)

        if self.options:
            args.append(self.options)

        return ":".join(args)


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

    def __iter__(self):
        return self.mappings.__iter__()


@dataclasses.dataclass
class ContainerConfiguration:
    image_name: str
    name: Optional[str] = None
    volumes: Optional[VolumeMappings] = None
    ports: Optional[PortMappings] = None
    entrypoint: Optional[str] = None
    additional_flags: Optional[List[str]] = None
    command: Optional[List[str]] = None
    env_vars: Dict[str, str] = dataclasses.field(default_factory=dict)

    privileged: Optional[bool] = None
    remove: Optional[bool] = None
    interactive: Optional[bool] = None
    tty: Optional[bool] = None
    detach: Optional[bool] = None

    stdin: Optional[str] = None
    user: Optional[str] = None
    cap_add: Optional[str] = None
    network: Optional[str] = None
    dns: Optional[str] = None
    workdir: Optional[str] = None


class ContainerClient(metaclass=ABCMeta):
    STOP_TIMEOUT = 0

    @abstractmethod
    def get_container_status(self, container_name: str) -> DockerContainerStatus:
        """Returns the status of the container with the given name"""
        pass

    def get_networks(self, container_name: str) -> List[str]:
        LOG.debug("Getting networks for container: %s", container_name)
        container_attrs = self.inspect_container(container_name_or_id=container_name)
        return list(container_attrs["NetworkSettings"]["Networks"].keys())

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
        containers = network_attrs["Containers"]
        if container_id not in containers:
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
    def stop_container(self, container_name: str, timeout: int = None):
        """Stops container with given name
        :param container_name: Container identifier (name or id) of the container to be stopped
        :param timeout: Timeout after which SIGKILL is sent to the container.
                        If not specified, defaults to `STOP_TIMEOUT`
        """
        pass

    @abstractmethod
    def pause_container(self, container_name: str):
        """Pauses a container with the given name."""

    @abstractmethod
    def remove_container(self, container_name: str, force=True, check_existence=False) -> None:
        """Removes container with given name"""
        pass

    @abstractmethod
    def remove_image(self, image: str, force: bool = True) -> None:
        """Removes an image with given name

        :param image: Image name and tag
        :param force: Force removal
        """
        pass

    @abstractmethod
    def list_containers(self, filter: Union[List[str], str, None] = None, all=True) -> List[dict]:
        """List all containers matching the given filters

        :return: A list of dicts with keys id, image, name, labels, status
        """
        pass

    def get_running_container_names(self) -> List[str]:
        """Returns a list of the names of all running containers"""
        result = self.list_containers(all=False)
        result = list(map(lambda container: container["name"], result))
        return result

    def is_container_running(self, container_name: str) -> bool:
        """Checks whether a container with a given name is currently running"""
        return container_name in self.get_running_container_names()

    @abstractmethod
    def copy_into_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        """Copy contents of the given local path into the container"""
        pass

    @abstractmethod
    def copy_from_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        """Copy contents of the given container to the host"""
        pass

    @abstractmethod
    def pull_image(self, docker_image: str) -> None:
        """Pulls a image with a given name from a docker registry"""
        pass

    @abstractmethod
    def build_image(self, dockerfile_path: str, image_name: str, context_path: str = None) -> None:
        """Builds an image from the given Dockerfile

        :param dockerfile_path: Path to Dockerfile, or a directory that contains a Dockerfile
        :param image_name: Name of the image to be built
        :param context_path: Path for build context (defaults to dirname of Dockerfile)
        """
        pass

    @abstractmethod
    def get_docker_image_names(self, strip_latest=True, include_tags=True) -> List[str]:
        """
        Get all names of docker images available to the container engine
        :param strip_latest: return images both with and without :latest tag
        :param include_tags: Include tags of the images in the names
        :return: List of image names
        """
        pass

    @abstractmethod
    def get_container_logs(self, container_name_or_id: str, safe=False) -> str:
        """Get all logs of a given container"""
        pass

    @abstractmethod
    def inspect_container(self, container_name_or_id: str) -> Dict[str, Union[Dict, str]]:
        """Get detailed attributes of an container.

        :return: Dict containing docker attributes as returned by the daemon
        """
        pass

    @abstractmethod
    def inspect_image(self, image_name: str, pull: bool = True) -> Dict[str, Union[Dict, str]]:
        """Get detailed attributes of an image.

        :param image_name: Image name to inspect
        :param pull: Whether to pull image if not existent
        :return: Dict containing docker attributes as returned by the daemon
        """
        pass

    @abstractmethod
    def inspect_network(self, network_name: str) -> Dict[str, Union[Dict, str]]:
        """Get detailed attributes of an network.

        :return: Dict containing docker attributes as returned by the daemon
        """
        pass

    @abstractmethod
    def connect_container_to_network(
        self, network_name: str, container_name_or_id: str, aliases: Optional[List] = None
    ) -> None:
        """
        Connects a container to a given network
        :param network_name: Network to connect the container to
        :param container_name_or_id: Container to connect to the network
        :param aliases: List of dns names the container should be available under in the network
        """
        pass

    @abstractmethod
    def disconnect_container_from_network(
        self, network_name: str, container_name_or_id: str
    ) -> None:
        """
        Disconnects a container from a given network
        :param network_name: Network to disconnect the container from
        :param container_name_or_id: Container to disconnect from the network
        """
        pass

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
        pass

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
        entrypoint_list = self.inspect_image(docker_image, pull)["Config"]["Entrypoint"] or []
        return shlex.join(entrypoint_list)

    @abstractmethod
    def has_docker(self) -> bool:
        """Check if system has docker available"""
        pass

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
        pass

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
        mount_volumes: Optional[List[SimpleVolumeBind]] = None,
        ports: Optional[PortMappings] = None,
        env_vars: Optional[Dict[str, str]] = None,
        user: Optional[str] = None,
        cap_add: Optional[str] = None,
        network: Optional[str] = None,
        dns: Optional[str] = None,
        additional_flags: Optional[str] = None,
        workdir: Optional[str] = None,
    ) -> str:
        """Creates a container with the given image

        :return: Container ID
        """
        pass

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
        mount_volumes: Optional[List[SimpleVolumeBind]] = None,
        ports: Optional[PortMappings] = None,
        env_vars: Optional[Dict[str, str]] = None,
        user: Optional[str] = None,
        cap_add: Optional[str] = None,
        network: Optional[str] = None,
        dns: Optional[str] = None,
        additional_flags: Optional[str] = None,
        workdir: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        """Creates and runs a given docker container

        :return: A tuple (stdout, stderr)
        """
        pass

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
    ) -> Tuple[bytes, bytes]:
        """Execute a given command in a container

        :return: A tuple (stdout, stderr)
        """
        pass

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
        pass


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
        f = os.path.join(config.dirs.tmp, short_uid())
        TMP_FILES.append(f)
        return f

    @staticmethod
    def append_without_latest(image_names):
        suffix = ":latest"
        for image in list(image_names):
            if image.endswith(suffix):
                image_names.append(image[: -len(suffix)])

    @staticmethod
    def tar_path(path, target_path, is_dir: bool):
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
    def parse_additional_flags(
        additional_flags: str,
        env_vars: Dict[str, str] = None,
        ports: PortMappings = None,
        mounts: List[SimpleVolumeBind] = None,
        network: Optional[str] = None,
    ) -> Tuple[
        Dict[str, str],
        PortMappings,
        List[SimpleVolumeBind],
        Optional[Dict[str, str]],
        Optional[str],
    ]:
        """Parses environment, volume and port flags passed as string
        :param additional_flags: String which contains the flag definitions
        :param env_vars: Dict with env vars. Will be modified in place.
        :param ports: PortMapping object. Will be modified in place.
        :param mounts: List of mount tuples (host_path, container_path). Will be modified in place.
        :param network: Existing network name (optional). Warning will be printed if network is overwritten in flags.
        :return: A tuple containing the env_vars, ports, mount, extra_hosts and network objects. Will return new objects
                if respective parameters were None and additional flags contained a flag for that object, the same which
                are passed otherwise.
        """
        cur_state = None
        extra_hosts = None
        # TODO Use argparse to simplify this logic
        for flag in shlex.split(additional_flags):
            if not cur_state:
                if flag in ["-v", "--volume"]:
                    cur_state = "volume"
                elif flag in ["-p", "--publish"]:
                    cur_state = "port"
                elif flag in ["-e", "--env"]:
                    cur_state = "env"
                elif flag == "--add-host":
                    cur_state = "add-host"
                elif flag == "--network":
                    cur_state = "set-network"
                else:
                    raise NotImplementedError(
                        f"Flag {flag} is currently not supported by this Docker client."
                    )
            else:
                if cur_state == "volume":
                    mounts = mounts if mounts is not None else []
                    match = re.match(
                        r"(?P<host>[\w\s\\\/:\-.]+?):(?P<container>[\w\s\/\-.]+)(?::(?P<arg>ro|rw|z|Z))?",
                        flag,
                    )
                    if not match:
                        LOG.warning("Unable to parse volume mount Docker flags: %s", flag)
                        continue
                    host_path = match.group("host")
                    container_path = match.group("container")
                    rw_args = match.group("arg")
                    if rw_args:
                        LOG.info("Volume options like :ro or :rw are currently ignored.")
                    mounts.append((host_path, container_path))
                elif cur_state == "port":
                    port_split = flag.split(":")
                    protocol = "tcp"
                    if len(port_split) == 2:
                        host_port, container_port = port_split
                    elif len(port_split) == 3:
                        LOG.warning(
                            "Host part of port mappings are ignored currently in additional flags"
                        )
                        _, host_port, container_port = port_split
                    else:
                        raise ValueError("Invalid port string provided: %s", flag)
                    host_port_split = host_port.split("-")
                    if len(host_port_split) == 2:
                        host_port = [int(host_port_split[0]), int(host_port_split[1])]
                    elif len(host_port_split) == 1:
                        host_port = int(host_port)
                    else:
                        raise ValueError("Invalid port string provided: %s", flag)
                    if "/" in container_port:
                        container_port, protocol = container_port.split("/")
                    ports = ports if ports is not None else PortMappings()
                    ports.add(host_port, int(container_port), protocol)
                elif cur_state == "env":
                    lhs, _, rhs = flag.partition("=")
                    env_vars = env_vars if env_vars is not None else {}
                    env_vars[lhs] = rhs
                elif cur_state == "add-host":
                    extra_hosts = extra_hosts if extra_hosts is not None else {}
                    hosts_split = flag.split(":")
                    extra_hosts[hosts_split[0]] = hosts_split[1]
                elif cur_state == "set-network":
                    if network:
                        LOG.warning(
                            "Overwriting Docker container network '%s' with new value '%s'",
                            network,
                            flag,
                        )
                    network = flag

                cur_state = None
        return env_vars, ports, mounts, extra_hosts, network

    @staticmethod
    def convert_mount_list_to_dict(
        mount_volumes: List[SimpleVolumeBind],
    ) -> Dict[str, Dict[str, str]]:
        """Converts a List of (host_path, container_path) tuples to a Dict suitable as volume argument for docker sdk"""
        return dict(
            map(
                lambda paths: (str(paths[0]), {"bind": paths[1], "mode": "rw"}),
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
