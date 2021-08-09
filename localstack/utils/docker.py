import json
import logging
import os
import shlex
import subprocess
from enum import Enum, unique
from typing import Dict, List, Optional, Tuple, Union

from localstack import config
from localstack.utils.common import TMP_FILES, rm_rf, safe_run, save_file, short_uid

LOG = logging.getLogger(__name__)


@unique
class DockerContainerStatus(Enum):
    DOWN = -1
    NON_EXISTENT = 0
    UP = 1


class ContainerException(Exception):
    def __init__(self, message, stdout, stderr) -> None:
        self.message = message
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

    def to_str(self) -> str:  # TODO test (and/or remove?)
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


class CmdDockerClient:
    """Class for managing docker containers using the command line executable"""

    def _docker_cmd(self) -> List[str]:
        """Return the string to be used for running Docker commands."""
        return config.DOCKER_CMD.split()

    def get_container_status(self, container_name: str) -> DockerContainerStatus:
        """Returns the status of the container with the given name"""
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
        """Returns the network mode of the container with the given name"""
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
            if "No such container" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

        container_network = cmd_result.strip()
        return container_network

    def stop_container(self, container_name: str) -> None:
        """Stops container with given name"""
        cmd = self._docker_cmd()
        cmd += ["stop", "-t0", container_name]
        LOG.debug("Stopping container with cmd %s", cmd)
        try:
            safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such container" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def remove_container(self, container_name: str, force=True, check_existence=False) -> None:
        """Removes container with given name"""
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
            if "No such container" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def list_containers(self, filter: Union[List[str], str, None] = None, all=True) -> List[dict]:
        """List all containers matching the given filters

        Returns a list of dicts with keys id, image, name, labels, status
        """
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

    def get_running_container_names(self):
        """Returns a list of the names of all running containers"""
        result = self.list_containers(all=False)
        result = list(map(lambda container: container["name"], result))
        return result

    def is_container_running(self, container_name: str):
        """Checks whether a container with a given name is currently running"""
        return container_name in self.get_running_container_names()

    def copy_into_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        """Copy contents of the given local path into the container"""
        cmd = self._docker_cmd()
        cmd += ["cp", local_path, f"{container_name}:{container_path}"]
        LOG.debug("Copying into container with cmd: %s", cmd)
        safe_run(cmd)

    def copy_from_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        cmd = self._docker_cmd()
        cmd += ["cp", f"{container_name}:{container_path}", local_path]
        LOG.debug("Copying from container with cmd: %s", cmd)
        safe_run(cmd)

    def pull_image(self, docker_image: str) -> None:
        """Pulls a image with a given name from a docker registry"""
        cmd = self._docker_cmd()
        cmd += ["pull", docker_image]
        LOG.debug("Pulling image with cmd: %s", cmd)
        try:
            safe_run(cmd)
        except subprocess.CalledProcessError as e:
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
                suffix = ":latest"
                for image in list(image_names):
                    if image.endswith(suffix):
                        image_names.append(image[: -len(suffix)])
            return image_names
        except Exception as e:
            LOG.info('Unable to list Docker images via "%s": %s' % (cmd, e))
            return []

    def get_container_logs(self, container_name_or_id: str, safe=False) -> str:
        """Get all logs of a given container"""
        cmd = self._docker_cmd()
        cmd += ["logs", container_name_or_id]
        try:
            return safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if safe:
                return ""
            if "No such container" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchContainer(container_name_or_id, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def inspect_object(self, object_name_or_id: str) -> Dict[str, Union[Dict, str]]:
        cmd = self._docker_cmd()
        cmd += ["inspect", "--format", "{{json .}}", object_name_or_id]
        try:
            cmd_result = safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such object" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchObject(object_name_or_id, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )
        image_data = json.loads(cmd_result.strip())
        return image_data

    def get_container_name(self, container_id: str) -> str:
        """Get the name of a container by a given identifier"""
        try:
            return self.inspect_object(container_id)["Name"].lstrip("/")
        except NoSuchObject as e:
            raise NoSuchContainer(e.object_id, stdout=e.stdout, stderr=e.stderr)

    def get_container_id(self, container_name: str) -> str:
        """Get the id of a container by a given name"""
        try:
            return self.inspect_object(container_name)["Id"]
        except NoSuchObject as e:
            raise NoSuchContainer(e.object_id, stdout=e.stdout, stderr=e.stderr)

    def get_container_ip(self, container_name_or_id: str) -> str:
        """Get the IP address of a given container"""
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
            if "No such object" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchContainer(container_name_or_id, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def get_image_cmd(self, docker_image: str) -> str:
        """Get the command for the given image"""
        try:
            cmd_list = self.inspect_object(docker_image)["Config"]["Cmd"] or []
            return " ".join(cmd_list)
        except NoSuchObject as e:
            raise NoSuchImage(e.object_id, stdout=e.stdout, stderr=e.stderr)

    def get_image_entrypoint(self, docker_image: str) -> str:
        """Get the entry point for the given image"""
        LOG.debug("Getting the entrypoint for image: %s", docker_image)
        try:
            entrypoint_list = self.inspect_object(docker_image)["Config"]["Entrypoint"] or []
            return " ".join(entrypoint_list)
        except NoSuchObject as e:
            raise NoSuchImage(e.object_id, stdout=e.stdout, stderr=e.stderr)

    def has_docker(self) -> bool:
        """Check if system has docker available"""
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
            if "Unable to find image" in e.stdout.decode(config.DEFAULT_ENCODING):
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
            stderr_str = e.stderr.decode(config.DEFAULT_ENCODING)
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


DOCKER_CLIENT = CmdDockerClient()
