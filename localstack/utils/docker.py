import json
import logging
import os
import subprocess
from enum import Enum, unique
from typing import Dict, List, Optional, Tuple, Union

from localstack import config
from localstack.utils.bootstrap import PortMappings
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

    def remove_container(self, container_name: str, force=True) -> None:
        """Removes container with given name"""
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

    def list_containers(self, filter: Union[List[str], str, None] = None) -> List[dict]:
        """List all containers matching the given filters

        Returns a list of dicts with keys id, image, name, labels, status
        """
        filter = [filter] if isinstance(filter, str) else filter
        cmd = self._docker_cmd()
        cmd += ["ps", "-a"]
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
        """Copy contents of the given local path into the container"""
        cmd = self._docker_cmd()
        cmd += ["cp", local_path, f"{container_name}:{container_path}"]
        LOG.debug("Copying into container with cmd: %s", cmd)
        safe_run(cmd)

    def get_image_entrypoint(self, docker_image: str) -> str:
        """Get the entry point for the given image"""
        LOG.debug("Getting the entrypoint for image: %s", docker_image)
        cmd = self._docker_cmd()
        cmd += [
            "image",
            "inspect",
            '--format="{{ .Config.Entrypoint }}"',
            docker_image,
        ]

        try:
            run_result = safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such image" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchImage(docker_image, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

        entry_point = run_result.strip('"[]\n\r ')
        return entry_point

    def get_image_cmd(self, docker_image: str) -> str:
        """Get the command for the given image"""
        cmd = self._docker_cmd()
        cmd += [
            "image",
            "inspect",
            '--format="{{ .Config.Cmd }}"',
            docker_image,
        ]

        try:
            run_result = safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if "No such image" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchImage(docker_image, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

        entry_point = run_result.strip('"[]\n\r ')
        return entry_point

    def pull_image(self, docker_image: str) -> None:
        cmd = self._docker_cmd()
        cmd += ["pull", docker_image]
        LOG.debug("Pulling image with cmd: %s", cmd)
        try:
            safe_run(cmd)
        except subprocess.CalledProcessError as e:
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            )

    def get_container_logs(self, container_name_or_id: str, safe=False) -> str:
        cmd = self._docker_cmd()
        cmd += ["logs", container_name_or_id]
        try:
            return safe_run(cmd)
        except subprocess.CalledProcessError as e:
            if not safe:
                return ""
            if "No such container" in e.stdout.decode(config.DEFAULT_ENCODING):
                raise NoSuchContainer(container_name_or_id, stdout=e.stdout, stderr=e.stderr)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                )

    def has_docker(self) -> bool:
        """Check if system has docker available"""
        try:
            safe_run(self._docker_cmd() + ["ps"])
            return True
        except Exception:
            return False

    def create_container(self, image_name: str, **kwargs) -> str:
        cmd = self._build_run_create_cmd("create", image_name, **kwargs)
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

    def run_container(self, image_name: str, stdin=None, **kwargs) -> Tuple[str, str]:
        cmd = self._build_run_create_cmd("run", image_name, **kwargs)
        LOG.debug("Run container with cmd: %s", cmd)
        return self._run_async_cmd(cmd, stdin, kwargs.get("name") or "", image_name)

    def exec_in_container(
        self,
        container_name_or_id: str,
        command: Union[List[str], str],
        interactive=False,
        detach=False,
        env_vars: Optional[List[Tuple[str, str]]] = None,
        stdin: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        cmd = self._docker_cmd()
        cmd.append("exec")
        if interactive:
            cmd.append("--interactive")
        if detach:
            cmd.append("--detach")
        if env_vars:
            cmd += Util.create_env_vars_file_flag(env_vars)
        cmd.append(container_name_or_id)
        cmd += command if isinstance(command, List) else [command]
        LOG.debug("Execute in container cmd: %s", cmd)
        return self._run_async_cmd(cmd, stdin, container_name_or_id)

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
    ) -> List[str]:

        cmd = self._docker_cmd() + [action]
        if remove:
            cmd.append("--rm")
        if name:
            cmd += ["--name", name]
        if entrypoint:
            cmd += ["--entrypoint", entrypoint]
        if mount_volumes:
            cmd += [
                volume
                for host_path, docker_path in mount_volumes
                for volume in ["-v", f"{host_path}:{docker_path}"]
            ]
        if interactive:
            cmd.append("--interactive")
        if detach:
            cmd.append("--detach")
        if ports:
            cmd += ports.to_list()
        if env_vars:
            cmd += Util.create_env_vars_file_flag(env_vars)
        if user:
            cmd += ["--user", user]
        if cap_add:
            cmd += ["--cap-add", cap_add]
        if network:
            cmd += ["--network", network]
        if dns:
            cmd += ["--dns", dns]
        if additional_flags:
            cmd += additional_flags.split()
        cmd.append(image_name)
        if command:
            cmd += command if isinstance(command, List) else [command]
        return cmd


class Util:
    MAX_ENV_ARGS_LENGTH = 20000

    @classmethod
    def create_env_vars_file_flag(cls, env_vars):
        if not env_vars:
            return []
        result = []
        env_vars = dict(env_vars)
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
        return result

    @staticmethod
    def rm_env_vars_file(env_vars_file_flag):
        if not env_vars_file_flag or "--env-file" not in env_vars_file_flag:
            return
        if isinstance(env_vars_file_flag, list):
            env_vars_file = env_vars_file_flag[env_vars_file_flag.index("--env-file") + 1]
        else:
            env_vars_file = env_vars_file_flag.replace("--env-file", "").strip()
        return rm_rf(env_vars_file)

    @staticmethod
    def mountable_tmp_file():
        f = os.path.join(config.TMP_FOLDER, short_uid())
        TMP_FILES.append(f)
        return f


DOCKER_CLIENT = CmdDockerClient()
