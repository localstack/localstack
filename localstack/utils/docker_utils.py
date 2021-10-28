import io
import json
import logging
import os
import queue
import re
import shlex
import socket
import subprocess
import tarfile
import tempfile
import threading
from abc import ABCMeta, abstractmethod
from enum import Enum, unique
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import docker
from docker import DockerClient
from docker.errors import APIError, ContainerError, DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from docker.utils.socket import STDERR, STDOUT, frames_iter

from localstack import config
from localstack.utils.common import (
    TMP_FILES,
    rm_rf,
    safe_run,
    save_file,
    short_uid,
    start_worker_thread,
    to_bytes,
)
from localstack.utils.run import to_str

LOG = logging.getLogger(__name__)

SDK_ISDIR = 1 << 31


@unique
class DockerContainerStatus(Enum):
    DOWN = -1
    NON_EXISTENT = 0
    UP = 1


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

    class HashableList(list):
        def __hash__(self):
            result = 0
            for i in self:
                result += hash(i)
            return result

    def __init__(self, bind_host=None):
        self.bind_host = bind_host if bind_host else ""
        self.mappings = {}

    def add(self, port, mapped=None, protocol="tcp"):
        mapped = mapped or port
        if isinstance(port, list):
            for i in range(port[1] - port[0] + 1):
                self.add(port[0] + i, mapped[0] + i)
            return
        if port is None or int(port) <= 0:
            raise Exception("Unable to add mapping for invalid port: %s" % port)
        if self.contains(port):
            return
        for from_range, to_range in self.mappings.items():
            if not self.in_expanded_range(port, from_range):
                continue
            if not self.in_expanded_range(mapped, to_range):
                continue
            self.expand_range(port, from_range)
            self.expand_range(mapped, to_range)
            return
        protocol = str(protocol or "tcp").lower()
        self.mappings[self.HashableList([port, port, protocol])] = [mapped, mapped]

    def to_str(self) -> str:
        bind_address = f"{self.bind_host}:" if self.bind_host else ""

        def entry(k, v):
            protocol = "/%s" % k[2] if k[2] != "tcp" else ""
            if k[0] == k[1] and v[0] == v[1]:
                return "-p %s%s:%s%s" % (bind_address, k[0], v[0], protocol)
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

    def to_dict(self) -> Dict[str, Union[Tuple[str, int], int]]:
        bind_address = self.bind_host or ""

        def entry(k, v):
            protocol = "/%s" % k[2]
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


class ContainerClient(metaclass=ABCMeta):
    @abstractmethod
    def get_container_status(self, container_name: str) -> DockerContainerStatus:
        """Returns the status of the container with the given name"""
        pass

    @abstractmethod
    def get_network(self, container_name: str) -> str:
        """Returns the network mode of the container with the given name"""
        pass

    @abstractmethod
    def stop_container(self, container_name: str):
        """Stops container with given name"""
        pass

    @abstractmethod
    def remove_container(self, container_name: str, force=True, check_existence=False) -> None:
        """Removes container with given name"""
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
    def inspect_image(self, image_name: str) -> Dict[str, Union[Dict, str]]:
        """Get detailed attributes of an image.

        :return: Dict containing docker attributes as returned by the daemon
        """
        pass

    @abstractmethod
    def inspect_network(self, network_name: str) -> Dict[str, Union[Dict, str]]:
        """Get detailed attributes of an network.

        :return: Dict containing docker attributes as returned by the daemon
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

    def get_image_cmd(self, docker_image: str) -> str:
        """Get the command for the given image"""
        cmd_list = self.inspect_image(docker_image)["Config"]["Cmd"] or []
        return " ".join(cmd_list)

    def get_image_entrypoint(self, docker_image: str) -> str:
        """Get the entry point for the given image"""
        LOG.debug("Getting the entrypoint for image: %s", docker_image)
        entrypoint_list = self.inspect_image(docker_image)["Config"]["Entrypoint"] or []
        return " ".join(entrypoint_list)

    @abstractmethod
    def has_docker(self) -> bool:
        """Check if system has docker available"""
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
        mount_volumes: Optional[List[Tuple[str, str]]] = None,
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
        mount_volumes: Optional[List[Tuple[str, str]]] = None,
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
        env_vars: Optional[Dict[str, str]] = None,
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


class CmdDockerClient(ContainerClient):
    """Class for managing docker containers using the command line executable"""

    def _docker_cmd(self) -> List[str]:
        """Return the string to be used for running Docker commands."""
        return config.DOCKER_CMD.split()

    def get_container_status(self, container_name: str) -> DockerContainerStatus:
        cmd = self._docker_cmd()
        cmd += [
            "ps",
            "-a",
            "--filter",
            f"name={container_name}",
            "--format",
            "{{ .Status }} - {{ .Names }}",
        ]
        cmd_result = safe_run(cmd)

        # filter empty / invalid lines from docker ps output
        cmd_result = next((line for line in cmd_result.splitlines() if container_name in line), "")
        container_status = cmd_result.strip().lower()
        if len(container_status) == 0:
            return DockerContainerStatus.NON_EXISTENT
        elif container_status.startswith("up "):
            return DockerContainerStatus.UP
        else:
            return DockerContainerStatus.DOWN

    def get_network(self, container_name: str) -> str:
        LOG.debug("Getting container network: %s", container_name)
        cmd = self._docker_cmd()
        cmd += [
            "inspect",
            container_name,
            "--format",
            "{{ .HostConfig.NetworkMode }}",
        ]

        try:
            cmd_result = safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such container" in to_str(e.stdout):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

        container_network = cmd_result.strip()
        return container_network

    def stop_container(self, container_name: str) -> None:
        cmd = self._docker_cmd()
        cmd += ["stop", "-t0", container_name]
        LOG.debug("Stopping container with cmd %s", cmd)
        try:
            safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such container" in to_str(e.stdout):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def remove_container(self, container_name: str, force=True, check_existence=False) -> None:
        if check_existence and container_name not in self.get_running_container_names():
            return
        cmd = self._docker_cmd() + ["rm"]
        if force:
            cmd.append("-f")
        cmd.append(container_name)
        LOG.debug("Removing container with cmd %s", cmd)
        try:
            safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such container" in to_str(e.stdout):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def list_containers(self, filter: Union[List[str], str, None] = None, all=True) -> List[dict]:
        filter = [filter] if isinstance(filter, str) else filter
        cmd = self._docker_cmd()
        cmd.append("ps")
        if all:
            cmd.append("-a")
        options = []
        if filter:
            options += [y for filter_item in filter for y in ["--filter", filter_item]]
        cmd += options
        cmd.append("--format")
        cmd.append(
            '{"id":"{{ .ID }}","image":"{{ .Image }}","name":"{{ .Names }}",'
            '"labels":"{{ .Labels }}","status":"{{ .State }}"}'
        )
        try:
            cmd_result = safe_run(cmd).strip()
        except subprocess.CalledProcessError as e:
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            )
        container_list = []
        if cmd_result:
            container_list = [json.loads(line) for line in cmd_result.splitlines()]
        return container_list

    def copy_into_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        cmd = self._docker_cmd()
        cmd += ["cp", local_path, f"{container_name}:{container_path}"]
        LOG.debug("Copying into container with cmd: %s", cmd)
        try:
            safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such container" in to_str(e.stdout):
                raise NoSuchContainer(container_name)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            )

    def copy_from_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        cmd = self._docker_cmd()
        cmd += ["cp", f"{container_name}:{container_path}", local_path]
        LOG.debug("Copying from container with cmd: %s", cmd)
        try:
            safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such container" in to_str(e.stdout):
                raise NoSuchContainer(container_name)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            )

    def pull_image(self, docker_image: str) -> None:
        cmd = self._docker_cmd()
        cmd += ["pull", docker_image]
        LOG.debug("Pulling image with cmd: %s", cmd)
        try:
            safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "pull access denied" in to_str(e.stdout):
                raise NoSuchImage(docker_image)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            )

    def get_docker_image_names(self, strip_latest=True, include_tags=True):
        format_string = "{{.Repository}}:{{.Tag}}" if include_tags else "{{.Repository}}"
        cmd = self._docker_cmd()
        cmd += ["images", "--format", format_string]
        try:
            output = safe_run(cmd)

            image_names = output.splitlines()
            if strip_latest:
                Util.append_without_latest(image_names)
            return image_names
        except Exception as e:
            LOG.info('Unable to list Docker images via "%s": %s' % (cmd, e))
            return []

    def get_container_logs(self, container_name_or_id: str, safe=False) -> str:
        cmd = self._docker_cmd()
        cmd += ["logs", container_name_or_id]
        try:
            return safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if safe:
                return ""
            if "No such container" in to_str(e.stdout):
                raise NoSuchContainer(container_name_or_id, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def _inspect_object(self, object_name_or_id: str) -> Dict[str, Union[Dict, str]]:
        cmd = self._docker_cmd()
        cmd += ["inspect", "--format", "{{json .}}", object_name_or_id]
        try:
            cmd_result = safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such object" in to_str(e.stdout):
                raise NoSuchObject(object_name_or_id, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )
        image_data = json.loads(cmd_result.strip())
        return image_data

    def inspect_container(self, container_name_or_id: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self._inspect_object(container_name_or_id)
        except NoSuchObject as e:
            raise NoSuchContainer(container_name_or_id=e.object_id)

    def inspect_image(self, image_name: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self._inspect_object(image_name)
        except NoSuchObject as e:
            raise NoSuchImage(image_name=e.object_id)

    def inspect_network(self, network_name: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self._inspect_object(network_name)
        except NoSuchObject as e:
            raise NoSuchNetwork(network_name=e.object_id)

    def get_container_ip(self, container_name_or_id: str) -> str:
        cmd = self._docker_cmd()
        cmd += [
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_name_or_id,
        ]
        try:
            return safe_run(cmd).strip()
        except subprocess.CalledProcessError as e:
            if "No such object" in to_str(e.stdout):
                raise NoSuchContainer(container_name_or_id, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def has_docker(self) -> bool:
        try:
            safe_run(self._docker_cmd() + ["ps"])
            return True
        except subprocess.CalledProcessError:
            return False

    def create_container(self, image_name: str, **kwargs) -> str:
        cmd, env_file = self._build_run_create_cmd("create", image_name, **kwargs)
        LOG.debug("Create container with cmd: %s", cmd)
        try:
            container_id = safe_run(cmd)
            # Note: strip off Docker warning messages like "DNS setting (--dns=127.0.0.1) may fail in containers"
            container_id = container_id.strip().split("\n")[-1]
            return container_id.strip()
        except subprocess.CalledProcessError as e:
            if "Unable to find image" in to_str(e.stdout):
                raise NoSuchImage(image_name, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            )
        finally:
            Util.rm_env_vars_file(env_file)

    def run_container(self, image_name: str, stdin=None, **kwargs) -> Tuple[bytes, bytes]:
        cmd, env_file = self._build_run_create_cmd("run", image_name, **kwargs)
        LOG.debug("Run container with cmd: %s", cmd)
        result = self._run_async_cmd(cmd, stdin, kwargs.get("name") or "", image_name)
        Util.rm_env_vars_file(env_file)
        return result

    def exec_in_container(
        self,
        container_name_or_id: str,
        command: Union[List[str], str],
        interactive=False,
        detach=False,
        env_vars: Optional[Dict[str, str]] = None,
        stdin: Optional[bytes] = None,
        user: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        env_file = None
        cmd = self._docker_cmd()
        cmd.append("exec")
        if interactive:
            cmd.append("--interactive")
        if detach:
            cmd.append("--detach")
        if user:
            cmd += ["--user", user]
        if env_vars:
            env_flag, env_file = Util.create_env_vars_file_flag(env_vars)
            cmd += env_flag
        cmd.append(container_name_or_id)
        cmd += command if isinstance(command, List) else [command]
        LOG.debug("Execute in container cmd: %s", cmd)
        result = self._run_async_cmd(cmd, stdin, container_name_or_id)
        Util.rm_env_vars_file(env_file)
        return result

    def start_container(
        self,
        container_name_or_id: str,
        stdin=None,
        interactive: bool = False,
        attach: bool = False,
        flags: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        cmd = self._docker_cmd() + ["start"]
        if flags:
            cmd.append(flags)
        if interactive:
            cmd.append("--interactive")
        if attach:
            cmd.append("--attach")
        cmd.append(container_name_or_id)
        LOG.debug("Start container with cmd: %s", cmd)
        return self._run_async_cmd(cmd, stdin, container_name_or_id)

    def _run_async_cmd(
        self, cmd: List[str], stdin: bytes, container_name: str, image_name=None
    ) -> Tuple[bytes, bytes]:
        kwargs = {
            "inherit_env": True,
            "asynchronous": True,
            "stderr": subprocess.PIPE,
            "outfile": subprocess.PIPE,
        }
        if stdin:
            kwargs["stdin"] = True
        try:
            process = safe_run(cmd, **kwargs)
            stdout, stderr = process.communicate(input=stdin)
            if process.returncode != 0:
                raise subprocess.CalledProcessError(
                    process.returncode,
                    cmd,
                    stdout,
                    stderr,
                )
            else:
                return stdout, stderr
        except subprocess.CalledProcessError as e:
            stderr_str = to_str(e.stderr)
            if "Unable to find image" in stderr_str:
                raise NoSuchImage(image_name or "", stdout=e.stdout, stderr=e.stderr)
            if "No such container" in stderr_str:
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            )

    def _build_run_create_cmd(
        self,
        action: str,
        image_name: str,
        *,
        name: Optional[str] = None,
        entrypoint: Optional[str] = None,
        remove: bool = False,
        interactive: bool = False,
        tty: bool = False,
        detach: bool = False,
        command: Optional[Union[List[str], str]] = None,
        mount_volumes: Optional[List[Tuple[str, str]]] = None,
        ports: Optional[PortMappings] = None,
        env_vars: Optional[Dict[str, str]] = None,
        user: Optional[str] = None,
        cap_add: Optional[str] = None,
        network: Optional[str] = None,
        dns: Optional[str] = None,
        additional_flags: Optional[str] = None,
        workdir: Optional[str] = None,
    ) -> Tuple[List[str], str]:
        env_file = None
        cmd = self._docker_cmd() + [action]
        if remove:
            cmd.append("--rm")
        if name:
            cmd += ["--name", name]
        if entrypoint is not None:  # empty string entrypoint can be intentional
            cmd += ["--entrypoint", entrypoint]
        if mount_volumes:
            cmd += [
                volume
                for host_path, docker_path in mount_volumes
                for volume in ["-v", f"{host_path}:{docker_path}"]
            ]
        if interactive:
            cmd.append("--interactive")
        if tty:
            cmd.append("--tty")
        if detach:
            cmd.append("--detach")
        if ports:
            cmd += ports.to_list()
        if env_vars:
            env_flags, env_file = Util.create_env_vars_file_flag(env_vars)
            cmd += env_flags
        if user:
            cmd += ["--user", user]
        if cap_add:
            cmd += ["--cap-add", cap_add]
        if network:
            cmd += ["--network", network]
        if dns:
            cmd += ["--dns", dns]
        if workdir:
            cmd += ["--workdir", workdir]
        if additional_flags:
            cmd += shlex.split(additional_flags)
        cmd.append(image_name)
        if command:
            cmd += command if isinstance(command, List) else [command]
        return cmd, env_file


class Util:
    MAX_ENV_ARGS_LENGTH = 20000

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
                env_content += "%s=%s\n" % (name, value)
            save_file(env_file, env_content)
            result += ["--env-file", env_file]

        env_vars_res = [item for k, v in env_vars.items() for item in ["-e", "{}={}".format(k, v)]]
        result += env_vars_res
        return result, env_file

    @staticmethod
    def rm_env_vars_file(env_vars_file) -> None:
        if env_vars_file:
            return rm_rf(env_vars_file)

    @staticmethod
    def mountable_tmp_file():
        f = os.path.join(config.TMP_FOLDER, short_uid())
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
        mounts: List[Tuple[str, str]] = None,
        network: Optional[str] = None,
    ) -> Tuple[
        Dict[str, str], PortMappings, List[Tuple[str, str]], Optional[Dict[str, str]], Optional[str]
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
                    if "/" in container_port:
                        container_port, protocol = container_port.split("/")
                    ports = ports if ports is not None else PortMappings()
                    ports.add(int(host_port), int(container_port), protocol)
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
        mount_volumes: List[Tuple[str, str]]
    ) -> Dict[str, Dict[str, str]]:
        """Converts a List of (host_path, container_path) tuples to a Dict suitable as volume argument for docker sdk"""
        return dict(
            map(
                lambda paths: (str(paths[0]), {"bind": paths[1], "mode": "rw"}),
                mount_volumes,
            )
        )


class SdkDockerClient(ContainerClient):
    """Class for managing docker using the python docker sdk"""

    docker_client: Optional[DockerClient]

    def __init__(self):
        try:
            self.docker_client = docker.from_env()
            logging.getLogger("urllib3").setLevel(logging.INFO)
        except DockerException:
            self.docker_client = None

    def client(self):
        if self.docker_client:
            return self.docker_client
        else:
            raise ContainerException("Docker not available")

    def _read_from_sock(self, sock: socket, tty: bool):
        """Reads multiplexed messages from a socket returned by attach_socket.

        Uses the protocol specified here: https://docs.docker.com/engine/api/v1.41/#operation/ContainerAttach
        """
        stdout = b""
        stderr = b""
        for frame_type, frame_data in frames_iter(sock, tty):
            if frame_type == STDOUT:
                stdout += frame_data
            elif frame_type == STDERR:
                stderr += frame_data
            else:
                raise ContainerException("Invalid frame type when reading from socket")
        return stdout, stderr

    def _container_path_info(self, container: Container, container_path: str):
        """
        Get information about a path in the given container
        :param container: Container to be inspected
        :param container_path: Path in container
        :return: Tuple (path_exists, path_is_directory)
        """
        # Docker CLI copy uses go FileMode to determine if target is a dict or not
        # https://github.com/docker/cli/blob/e3dfc2426e51776a3263cab67fbba753dd3adaa9/cli/command/container/cp.go#L260
        # The isDir Bit is the most significant bit in the 32bit struct:
        # https://golang.org/src/os/types.go?s=2650:2683
        stats = {}
        try:
            _, stats = container.get_archive(container_path)
            target_exists = True
        except APIError:
            target_exists = False
        target_is_dir = target_exists and bool(stats["mode"] & SDK_ISDIR)
        return target_exists, target_is_dir

    def get_container_status(self, container_name: str) -> DockerContainerStatus:
        # LOG.debug("Getting container status for container: %s", container_name) #  too verbose
        try:
            container = self.client().containers.get(container_name)
            if container.status == "running":
                return DockerContainerStatus.UP
            else:
                return DockerContainerStatus.DOWN
        except NotFound:
            return DockerContainerStatus.NON_EXISTENT
        except APIError:
            raise ContainerException()

    def get_network(self, container_name: str) -> str:
        LOG.debug("Getting network type for container: %s", container_name)
        try:
            container = self.client().containers.get(container_name)
            return container.attrs["HostConfig"]["NetworkMode"]
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError:
            raise ContainerException()

    def stop_container(self, container_name: str) -> None:
        LOG.debug("Stopping container: %s", container_name)
        try:
            container = self.client().containers.get(container_name)
            container.stop(timeout=0)
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError:
            raise ContainerException()

    def remove_container(self, container_name: str, force=True, check_existence=False) -> None:
        LOG.debug("Removing container: %s", container_name)
        if check_existence and container_name not in self.get_running_container_names():
            LOG.debug("Aborting removing due to check_existence check")
            return
        try:
            container = self.client().containers.get(container_name)
            container.remove(force=force)
        except NotFound:
            if not force:
                raise NoSuchContainer(container_name)
        except APIError:
            raise ContainerException()

    def list_containers(self, filter: Union[List[str], str, None] = None, all=True) -> List[dict]:
        if filter:
            filter = [filter] if isinstance(filter, str) else filter
            filter = dict([f.split("=", 1) for f in filter])
        LOG.debug("Listing containers with filters: %s", filter)
        try:
            container_list = self.client().containers.list(filters=filter, all=all)
            return list(
                map(
                    lambda container: {
                        "id": container.id,
                        "image": container.image,
                        "name": container.name,
                        "status": container.status,
                        "labels": container.labels,
                    },
                    container_list,
                )
            )
        except APIError:
            raise ContainerException()

    def copy_into_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:  # TODO behave like https://docs.docker.com/engine/reference/commandline/cp/
        LOG.debug("Copying file %s into %s:%s", local_path, container_name, container_path)
        try:
            container = self.client().containers.get(container_name)
            target_exists, target_isdir = self._container_path_info(container, container_path)
            target_path = container_path if target_isdir else os.path.dirname(container_path)
            with Util.tar_path(local_path, container_path, is_dir=target_isdir) as tar:
                container.put_archive(target_path, tar)
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError:
            raise ContainerException()

    def copy_from_container(
        self,
        container_name: str,
        local_path: str,
        container_path: str,
    ) -> None:
        LOG.debug("Copying file from %s:%s to %s", container_name, container_path, local_path)
        try:
            container = self.client().containers.get(container_name)
            bits, _ = container.get_archive(container_path)
            Util.untar_to_path(bits, local_path)
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError:
            raise ContainerException()

    def pull_image(self, docker_image: str) -> None:
        LOG.debug("Pulling image: %s", docker_image)
        # some path in the docker image string indicates a custom repository
        path_split = docker_image.rpartition("/")
        image_split = path_split[2].partition(":")
        repository = f"{path_split[0]}{path_split[1]}{image_split[0]}"
        tag = image_split[2]
        try:
            LOG.debug("Repository: %s Tag: %s", repository, tag)
            self.client().images.pull(repository, tag)
        except ImageNotFound:
            raise NoSuchImage(docker_image)
        except APIError:
            raise ContainerException()

    def get_docker_image_names(self, strip_latest=True, include_tags=True):
        try:
            images = self.client().images.list()
            image_names = [tag for image in images for tag in image.tags if image.tags]
            if not include_tags:
                image_names = list(map(lambda image_name: image_name.split(":")[0], image_names))
            if strip_latest:
                Util.append_without_latest(image_names)
            return image_names
        except APIError:
            raise ContainerException()

    def get_container_logs(self, container_name_or_id: str, safe=False) -> str:
        try:
            container = self.client().containers.get(container_name_or_id)
            return to_str(container.logs())
        except NotFound:
            if safe:
                return ""
            raise NoSuchContainer(container_name_or_id)
        except APIError:
            if safe:
                return ""
            raise ContainerException()

    def inspect_container(self, container_name_or_id: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self.client().containers.get(container_name_or_id).attrs
        except NotFound:
            raise NoSuchContainer(container_name_or_id)
        except APIError:
            raise ContainerException()

    def inspect_image(self, image_name: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self.client().images.get(image_name).attrs
        except NotFound:
            raise NoSuchImage(image_name)
        except APIError:
            raise ContainerException()

    def inspect_network(self, network_name: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self.client().networks.get(network_name).attrs
        except NotFound:
            raise NoSuchNetwork(network_name)
        except APIError:
            raise ContainerException()

    def get_container_ip(self, container_name_or_id: str) -> str:
        networks = self.inspect_container(container_name_or_id)["NetworkSettings"]["Networks"]
        network_names = list(networks)
        if len(network_names) > 1:
            LOG.info("Container has more than one assigned network. Picking the first one...")
        return networks[network_names[0]]["IPAddress"]

    def has_docker(self) -> bool:
        try:
            if not self.docker_client:
                return False
            self.client().ping()
            return True
        except APIError:
            return False

    def start_container(
        self,
        container_name_or_id: str,
        stdin=None,
        interactive: bool = False,
        attach: bool = False,
        flags: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        LOG.debug("Starting container %s", container_name_or_id)
        try:
            container = self.client().containers.get(container_name_or_id)
            stdout = to_bytes(container_name_or_id)
            stderr = b""
            if interactive or attach:
                params = {"stdout": 1, "stderr": 1, "stream": 1}
                if interactive:
                    params["stdin"] = 1
                sock = container.attach_socket(params=params)
                sock = sock._sock if hasattr(sock, "_sock") else sock
                result_queue = queue.Queue()
                thread_started = threading.Event()
                start_waiting = threading.Event()

                # Note: We need to be careful about potential race conditions here - .wait() should happen right
                #   after .start(). Hence starting a thread and asynchronously waiting for the container exit code
                def wait_for_result(*_):
                    _exit_code = -1
                    try:
                        thread_started.set()
                        start_waiting.wait()
                        _exit_code = container.wait()["StatusCode"]
                    except APIError as e:
                        _exit_code = 1
                        raise ContainerException(str(e))
                    finally:
                        result_queue.put(_exit_code)

                # start listener thread
                start_worker_thread(wait_for_result)
                thread_started.wait()
                # start container
                container.start()
                # start awaiting container result
                start_waiting.set()

                # handle container input/output
                with sock:
                    try:
                        if stdin:
                            sock.sendall(to_bytes(stdin))
                            sock.shutdown(socket.SHUT_WR)
                        stdout, stderr = self._read_from_sock(sock, False)
                    except socket.timeout:
                        LOG.debug(
                            f"Socket timeout when talking to the I/O streams of Docker container '{container_name_or_id}'"
                        )

                # get container exit code
                exit_code = result_queue.get()
                if exit_code:
                    raise ContainerException(
                        "Docker container returned with exit code %s" % exit_code,
                        stdout=stdout,
                        stderr=stderr,
                    )
            else:
                container.start()
            return stdout, stderr
        except NotFound:
            raise NoSuchContainer(container_name_or_id)
        except APIError:
            raise ContainerException()

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
        mount_volumes: Optional[List[Tuple[str, str]]] = None,
        ports: Optional[PortMappings] = None,
        env_vars: Optional[Dict[str, str]] = None,
        user: Optional[str] = None,
        cap_add: Optional[str] = None,
        network: Optional[str] = None,
        dns: Optional[str] = None,
        additional_flags: Optional[str] = None,
        workdir: Optional[str] = None,
    ) -> str:
        LOG.debug(
            "Creating container with image %s, command '%s', volumes %s, env vars %s",
            image_name,
            command,
            mount_volumes,
            env_vars,
        )
        extra_hosts = None
        if additional_flags:
            env_vars, ports, mount_volumes, extra_hosts, network = Util.parse_additional_flags(
                additional_flags, env_vars, ports, mount_volumes, network
            )
        try:
            kwargs = {}
            if cap_add:
                kwargs["cap_add"] = [cap_add]
            if dns:
                kwargs["dns"] = [dns]
            if ports:
                kwargs["ports"] = ports.to_dict()
            if workdir:
                kwargs["working_dir"] = workdir
            mounts = None
            if mount_volumes:
                mounts = Util.convert_mount_list_to_dict(mount_volumes)

            def create_container():
                return self.client().containers.create(
                    image=image_name,
                    command=command,
                    auto_remove=remove,
                    name=name,
                    stdin_open=interactive,
                    tty=tty,
                    entrypoint=entrypoint,
                    environment=env_vars,
                    detach=detach,
                    user=user,
                    network=network,
                    volumes=mounts,
                    extra_hosts=extra_hosts,
                    **kwargs,
                )

            try:
                container = create_container()
            except ImageNotFound:
                self.pull_image(image_name)
                container = create_container()
            return container.id
        except ImageNotFound:
            raise NoSuchImage(image_name)
        except APIError:
            raise ContainerException()

    def run_container(
        self,
        image_name: str,
        stdin=None,
        *,
        name: Optional[str] = None,
        entrypoint: Optional[str] = None,
        remove: bool = False,
        interactive: bool = False,
        tty: bool = False,
        detach: bool = False,
        command: Optional[Union[List[str], str]] = None,
        mount_volumes: Optional[List[Tuple[str, str]]] = None,
        ports: Optional[PortMappings] = None,
        env_vars: Optional[Dict[str, str]] = None,
        user: Optional[str] = None,
        cap_add: Optional[str] = None,
        network: Optional[str] = None,
        dns: Optional[str] = None,
        additional_flags: Optional[str] = None,
        workdir: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        LOG.debug("Running container with image: %s", image_name)
        container = None
        try:
            container = self.create_container(
                image_name,
                name=name,
                entrypoint=entrypoint,
                interactive=interactive,
                tty=tty,
                detach=detach,
                remove=remove and detach,
                command=command,
                mount_volumes=mount_volumes,
                ports=ports,
                env_vars=env_vars,
                user=user,
                cap_add=cap_add,
                network=network,
                dns=dns,
                additional_flags=additional_flags,
                workdir=workdir,
            )
            result = self.start_container(
                container_name_or_id=container,
                stdin=stdin,
                interactive=interactive,
                attach=not detach,
            )
        finally:
            if remove and container and not detach:
                self.remove_container(container)
        return result

    def exec_in_container(
        self,
        container_name_or_id: str,
        command: Union[List[str], str],
        interactive=False,
        detach=False,
        env_vars: Optional[Dict[str, str]] = None,
        stdin: Optional[bytes] = None,
        user: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        LOG.debug("Executing command in container %s: %s", container_name_or_id, command)
        try:
            container: Container = self.client().containers.get(container_name_or_id)
            result = container.exec_run(
                cmd=command,
                environment=env_vars,
                user=user,
                detach=detach,
                stdin=interactive and bool(stdin),
                socket=interactive and bool(stdin),
                stdout=True,
                stderr=True,
                demux=True,
            )
            tty = False
            if interactive and stdin:  # result is a socket
                sock = result[1]
                sock = sock._sock if hasattr(sock, "_sock") else sock
                with sock:
                    try:
                        sock.sendall(stdin)
                        sock.shutdown(socket.SHUT_WR)
                        stdout, stderr = self._read_from_sock(sock, tty)
                        return stdout, stderr
                    except socket.timeout:
                        pass
            else:
                if detach:
                    return b"", b""
                return_code = result[0]
                if isinstance(result[1], bytes):
                    stdout = result[1]
                    stderr = b""
                else:
                    stdout, stderr = result[1]
                if return_code != 0:
                    raise ContainerException(
                        "Exec command returned with exit code %s" % return_code, stdout, stderr
                    )
                return stdout, stderr
        except ContainerError:
            raise NoSuchContainer(container_name_or_id)
        except APIError:
            raise ContainerException()


DOCKER_CLIENT: ContainerClient = (
    CmdDockerClient() if config.LEGACY_DOCKER_CLIENT else SdkDockerClient()
)
