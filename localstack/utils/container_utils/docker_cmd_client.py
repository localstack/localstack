import functools
import itertools
import json
import logging
import os
import re
import shlex
import subprocess
from typing import Dict, List, Optional, Tuple, Union

from localstack import config
from localstack.utils.collections import ensure_list
from localstack.utils.container_utils.container_client import (
    AccessDenied,
    CancellableStream,
    ContainerClient,
    ContainerException,
    DockerContainerStatus,
    DockerNotAvailable,
    DockerPlatform,
    NoSuchContainer,
    NoSuchImage,
    NoSuchNetwork,
    NoSuchObject,
    PortMappings,
    RegistryConnectionError,
    SimpleVolumeBind,
    Ulimit,
    Util,
    VolumeBind,
)
from localstack.utils.run import run
from localstack.utils.strings import first_char_to_upper, to_str

LOG = logging.getLogger(__name__)


class CancellableProcessStream(CancellableStream):
    process: subprocess.Popen

    def __init__(self, process: subprocess.Popen) -> None:
        super().__init__()
        self.process = process

    def __iter__(self):
        return self

    def __next__(self):
        line = self.process.stdout.readline()
        if not line:
            raise StopIteration
        return line

    def close(self):
        return self.process.terminate()


class CmdDockerClient(ContainerClient):
    """
    Class for managing Docker (or Podman) containers using the command line executable.

    The client also supports targeting Podman engines, as Podman is almost a drop-in replacement
    for Docker these days. The majority of compatibility switches in this class is to handle slightly
    different response payloads or error messages returned by the `docker` vs `podman` commands.
    """

    default_run_outfile: Optional[str] = None

    def _docker_cmd(self) -> List[str]:
        """
        Get the configured, tested Docker CMD.
        :return: string to be used for running Docker commands
        :raises: DockerNotAvailable exception if the Docker command or the socker is not available
        """
        if not self.has_docker():
            raise DockerNotAvailable()
        return shlex.split(config.DOCKER_CMD)

    def get_system_info(self) -> dict:
        cmd = [
            *self._docker_cmd(),
            "info",
            "--format",
            "{{json .}}",
        ]
        cmd_result = run(cmd)

        return json.loads(cmd_result)

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
        cmd_result = run(cmd)

        # filter empty / invalid lines from docker ps output
        cmd_result = next((line for line in cmd_result.splitlines() if container_name in line), "")
        container_status = cmd_result.strip().lower()
        if len(container_status) == 0:
            return DockerContainerStatus.NON_EXISTENT
        elif "(paused)" in container_status:
            return DockerContainerStatus.PAUSED
        elif container_status.startswith("up "):
            return DockerContainerStatus.UP
        else:
            return DockerContainerStatus.DOWN

    def stop_container(self, container_name: str, timeout: int = None) -> None:
        if timeout is None:
            timeout = self.STOP_TIMEOUT
        cmd = self._docker_cmd()
        cmd += ["stop", "--time", str(timeout), container_name]
        LOG.debug("Stopping container with cmd %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name, error=e)
            raise ContainerException(
                f"Docker process returned with errorcode {e.returncode}", e.stdout, e.stderr
            ) from e

    def restart_container(self, container_name: str, timeout: int = 10) -> None:
        cmd = self._docker_cmd()
        cmd += ["restart", "--time", str(timeout), container_name]
        LOG.debug("Restarting container with cmd %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name, error=e)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def pause_container(self, container_name: str) -> None:
        cmd = self._docker_cmd()
        cmd += ["pause", container_name]
        LOG.debug("Pausing container with cmd %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name, error=e)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def unpause_container(self, container_name: str) -> None:
        cmd = self._docker_cmd()
        cmd += ["unpause", container_name]
        LOG.debug("Unpausing container with cmd %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name, error=e)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def remove_image(self, image: str, force: bool = True) -> None:
        cmd = self._docker_cmd()
        cmd += ["rmi", image]
        if force:
            cmd += ["--force"]
        LOG.debug("Removing image %s %s", image, "(forced)" if force else "")
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            # handle different error messages for Docker and podman
            error_messages = ["No such image", "image not known"]
            if any(msg in to_str(e.stdout) for msg in error_messages):
                raise NoSuchImage(image, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def commit(
        self,
        container_name_or_id: str,
        image_name: str,
        image_tag: str,
    ):
        cmd = self._docker_cmd()
        cmd += ["commit", container_name_or_id, f"{image_name}:{image_tag}"]
        LOG.debug(
            "Creating image from container %s as %s:%s", container_name_or_id, image_name, image_tag
        )
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name_or_id, error=e)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def remove_container(self, container_name: str, force=True, check_existence=False) -> None:
        if check_existence and container_name not in self.get_running_container_names():
            return
        cmd = self._docker_cmd() + ["rm"]
        if force:
            cmd.append("-f")
        cmd.append(container_name)
        LOG.debug("Removing container with cmd %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name, error=e)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

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
        cmd.append("{{json . }}")
        try:
            cmd_result = run(cmd).strip()
        except subprocess.CalledProcessError as e:
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e
        container_list = []
        if cmd_result:
            if cmd_result[0] == "[":
                container_list = json.loads(cmd_result)
            else:
                container_list = [json.loads(line) for line in cmd_result.splitlines()]
        result = []
        for container in container_list:
            result.append(
                {
                    # support both, Docker and podman API response formats (`ID` vs `Id`)
                    "id": container.get("ID") or container["Id"],
                    "image": container["Image"],
                    # Docker returns a single string for `Names`, whereas podman returns a list of names
                    "name": ensure_list(container["Names"])[0],
                    "status": container["State"],
                    "labels": container["Labels"],
                }
            )
        return result

    def copy_into_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        cmd = self._docker_cmd()
        cmd += ["cp", local_path, f"{container_name}:{container_path}"]
        LOG.debug("Copying into container with cmd: %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name, error=e)
            if "does not exist" in to_str(e.stdout):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                f"Docker process returned with errorcode {e.returncode}", e.stdout, e.stderr
            ) from e

    def copy_from_container(
        self, container_name: str, local_path: str, container_path: str
    ) -> None:
        cmd = self._docker_cmd()
        cmd += ["cp", f"{container_name}:{container_path}", local_path]
        LOG.debug("Copying from container with cmd: %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name, error=e)
            # additional check to support Podman CLI output
            if re.match(".*container .+ does not exist", to_str(e.stdout)):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def pull_image(self, docker_image: str, platform: Optional[DockerPlatform] = None) -> None:
        cmd = self._docker_cmd()
        cmd += ["pull", docker_image]
        if platform:
            cmd += ["--platform", platform]
        LOG.debug("Pulling image with cmd: %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            stdout_str = to_str(e.stdout)
            if "pull access denied" in stdout_str:
                raise NoSuchImage(docker_image, stdout=e.stdout, stderr=e.stderr)
            # note: error message 'access to the resource is denied' raised by Podman client
            if "Trying to pull" in stdout_str and "access to the resource is denied" in stdout_str:
                raise NoSuchImage(docker_image, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def push_image(self, docker_image: str) -> None:
        cmd = self._docker_cmd()
        cmd += ["push", docker_image]
        LOG.debug("Pushing image with cmd: %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            if "is denied" in to_str(e.stdout):
                raise AccessDenied(docker_image)
            if "requesting higher privileges than access token allows" in to_str(e.stdout):
                raise AccessDenied(docker_image)
            if "access token has insufficient scopes" in to_str(e.stdout):
                raise AccessDenied(docker_image)
            if "does not exist" in to_str(e.stdout):
                raise NoSuchImage(docker_image)
            if "connection refused" in to_str(e.stdout):
                raise RegistryConnectionError(e.stdout)
            # note: error message 'image not known' raised by Podman client
            if "image not known" in to_str(e.stdout):
                raise NoSuchImage(docker_image)
            raise ContainerException(
                f"Docker process returned with errorcode {e.returncode}", e.stdout, e.stderr
            ) from e

    def build_image(
        self,
        dockerfile_path: str,
        image_name: str,
        context_path: str = None,
        platform: Optional[DockerPlatform] = None,
    ):
        cmd = self._docker_cmd()
        dockerfile_path = Util.resolve_dockerfile_path(dockerfile_path)
        context_path = context_path or os.path.dirname(dockerfile_path)
        cmd += ["build", "-t", image_name, "-f", dockerfile_path]
        if platform:
            cmd += ["--platform", platform]
        cmd += [context_path]
        LOG.debug("Building Docker image: %s", cmd)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            raise ContainerException(
                f"Docker build process returned with error code {e.returncode}", e.stdout, e.stderr
            ) from e

    def tag_image(self, source_ref: str, target_name: str) -> None:
        cmd = self._docker_cmd()
        cmd += ["tag", source_ref, target_name]
        LOG.debug("Tagging Docker image %s as %s", source_ref, target_name)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            # handle different error messages for Docker and podman
            error_messages = ["No such image", "image not known"]
            if any(msg in to_str(e.stdout) for msg in error_messages):
                raise NoSuchImage(source_ref)
            raise ContainerException(
                f"Docker process returned with error code {e.returncode}", e.stdout, e.stderr
            ) from e

    def get_docker_image_names(
        self, strip_latest=True, include_tags=True, strip_wellknown_repo_prefixes: bool = True
    ):
        format_string = "{{.Repository}}:{{.Tag}}" if include_tags else "{{.Repository}}"
        cmd = self._docker_cmd()
        cmd += ["images", "--format", format_string]
        try:
            output = run(cmd)

            image_names = output.splitlines()
            if strip_wellknown_repo_prefixes:
                image_names = Util.strip_wellknown_repo_prefixes(image_names)
            if strip_latest:
                Util.append_without_latest(image_names)

            return image_names
        except Exception as e:
            LOG.info('Unable to list Docker images via "%s": %s', cmd, e)
            return []

    def get_container_logs(self, container_name_or_id: str, safe=False) -> str:
        cmd = self._docker_cmd()
        cmd += ["logs", container_name_or_id]
        try:
            return run(cmd)
        except subprocess.CalledProcessError as e:
            if safe:
                return ""
            self._check_and_raise_no_such_container_error(container_name_or_id, error=e)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def stream_container_logs(self, container_name_or_id: str) -> CancellableStream:
        self.inspect_container(container_name_or_id)  # guard to check whether container is there

        cmd = self._docker_cmd()
        cmd += ["logs", container_name_or_id, "--follow"]

        process: subprocess.Popen = run(
            cmd, asynchronous=True, outfile=subprocess.PIPE, stderr=subprocess.PIPE
        )

        return CancellableProcessStream(process)

    def _inspect_object(self, object_name_or_id: str) -> Dict[str, Union[dict, list, str]]:
        cmd = self._docker_cmd()
        cmd += ["inspect", "--format", "{{json .}}", object_name_or_id]
        try:
            cmd_result = run(cmd)
        except subprocess.CalledProcessError as e:
            # note: case-insensitive comparison, to support Docker and Podman output formats
            if "no such object" in to_str(e.stdout).lower():
                raise NoSuchObject(object_name_or_id, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e
        object_data = json.loads(cmd_result.strip())
        if isinstance(object_data, list):
            # return first list item, for compatibility with Podman API
            if len(object_data) == 1:
                result = object_data[0]
                # convert first character to uppercase (e.g., `name` -> `Name`), for Podman/Docker compatibility
                result = {first_char_to_upper(k): v for k, v in result.items()}
                return result
            LOG.info(
                "Expected a single object for `inspect` on ID %s, got %s",
                object_name_or_id,
                len(object_data),
            )
        return object_data

    def inspect_container(self, container_name_or_id: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self._inspect_object(container_name_or_id)
        except NoSuchObject as e:
            raise NoSuchContainer(container_name_or_id=e.object_id)

    def inspect_image(
        self,
        image_name: str,
        pull: bool = True,
        strip_wellknown_repo_prefixes: bool = True,
    ) -> Dict[str, Union[dict, list, str]]:
        try:
            result = self._inspect_object(image_name)
            if strip_wellknown_repo_prefixes:
                if result.get("RepoDigests"):
                    result["RepoDigests"] = Util.strip_wellknown_repo_prefixes(
                        result["RepoDigests"]
                    )
                if result.get("RepoTags"):
                    result["RepoTags"] = Util.strip_wellknown_repo_prefixes(result["RepoTags"])
            return result
        except NoSuchObject as e:
            if pull:
                self.pull_image(image_name)
                return self.inspect_image(image_name, pull=False)
            raise NoSuchImage(image_name=e.object_id)

    def create_network(self, network_name: str) -> str:
        cmd = self._docker_cmd()
        cmd += ["network", "create", network_name]
        try:
            return run(cmd).strip()
        except subprocess.CalledProcessError as e:
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def delete_network(self, network_name: str) -> None:
        cmd = self._docker_cmd()
        cmd += ["network", "rm", network_name]
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            stdout_str = to_str(e.stdout)
            if re.match(r".*network (.*) not found.*", stdout_str):
                raise NoSuchNetwork(network_name=network_name)
            else:
                raise ContainerException(
                    "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
                ) from e

    def inspect_network(self, network_name: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self._inspect_object(network_name)
        except NoSuchObject as e:
            raise NoSuchNetwork(network_name=e.object_id)

    def connect_container_to_network(
        self, network_name: str, container_name_or_id: str, aliases: Optional[List] = None
    ) -> None:
        LOG.debug(
            "Connecting container '%s' to network '%s' with aliases '%s'",
            container_name_or_id,
            network_name,
            aliases,
        )
        cmd = self._docker_cmd()
        cmd += ["network", "connect"]
        if aliases:
            cmd += ["--alias", ",".join(aliases)]
        cmd += [network_name, container_name_or_id]
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            stdout_str = to_str(e.stdout)
            if re.match(r".*network (.*) not found.*", stdout_str):
                raise NoSuchNetwork(network_name=network_name)
            self._check_and_raise_no_such_container_error(container_name_or_id, error=e)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def disconnect_container_from_network(
        self, network_name: str, container_name_or_id: str
    ) -> None:
        LOG.debug(
            "Disconnecting container '%s' from network '%s'", container_name_or_id, network_name
        )
        cmd = self._docker_cmd() + ["network", "disconnect", network_name, container_name_or_id]
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            stdout_str = to_str(e.stdout)
            if re.match(r".*network (.*) not found.*", stdout_str):
                raise NoSuchNetwork(network_name=network_name)
            self._check_and_raise_no_such_container_error(container_name_or_id, error=e)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def get_container_ip(self, container_name_or_id: str) -> str:
        cmd = self._docker_cmd()
        cmd += [
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            container_name_or_id,
        ]
        try:
            result = run(cmd).strip()
            return result.split(" ")[0] if result else ""
        except subprocess.CalledProcessError as e:
            self._check_and_raise_no_such_container_error(container_name_or_id, error=e)
            # consider different error messages for Podman
            if "no such object" in to_str(e.stdout).lower():
                raise NoSuchContainer(container_name_or_id, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    def login(self, username: str, password: str, registry: Optional[str] = None) -> None:
        cmd = self._docker_cmd()
        # TODO specify password via stdin
        cmd += ["login", "-u", username, "-p", password]
        if registry:
            cmd.append(registry)
        try:
            run(cmd)
        except subprocess.CalledProcessError as e:
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

    @functools.lru_cache(maxsize=None)
    def has_docker(self) -> bool:
        try:
            # do not use self._docker_cmd here (would result in a loop)
            run(shlex.split(config.DOCKER_CMD) + ["ps"])
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def create_container(self, image_name: str, **kwargs) -> str:
        cmd, env_file = self._build_run_create_cmd("create", image_name, **kwargs)
        LOG.debug("Create container with cmd: %s", cmd)
        try:
            container_id = run(cmd)
            # Note: strip off Docker warning messages like "DNS setting (--dns=127.0.0.1) may fail in containers"
            container_id = container_id.strip().split("\n")[-1]
            return container_id.strip()
        except subprocess.CalledProcessError as e:
            error_messages = ["Unable to find image", "Trying to pull"]
            if any(msg in to_str(e.stdout) for msg in error_messages):
                raise NoSuchImage(image_name, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e
        finally:
            Util.rm_env_vars_file(env_file)

    def run_container(self, image_name: str, stdin=None, **kwargs) -> Tuple[bytes, bytes]:
        cmd, env_file = self._build_run_create_cmd("run", image_name, **kwargs)
        LOG.debug("Run container with cmd: %s", cmd)
        try:
            return self._run_async_cmd(cmd, stdin, kwargs.get("name") or "", image_name)
        except ContainerException as e:
            if "Trying to pull" in str(e) and "access to the resource is denied" in str(e):
                raise NoSuchImage(image_name, stdout=e.stdout, stderr=e.stderr) from e
            raise
        finally:
            Util.rm_env_vars_file(env_file)

    def exec_in_container(
        self,
        container_name_or_id: str,
        command: Union[List[str], str],
        interactive=False,
        detach=False,
        env_vars: Optional[Dict[str, Optional[str]]] = None,
        stdin: Optional[bytes] = None,
        user: Optional[str] = None,
        workdir: Optional[str] = None,
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
        if workdir:
            cmd += ["--workdir", workdir]
        if env_vars:
            env_flag, env_file = Util.create_env_vars_file_flag(env_vars)
            cmd += env_flag
        cmd.append(container_name_or_id)
        cmd += command if isinstance(command, List) else [command]
        LOG.debug("Execute command in container: %s", cmd)
        try:
            return self._run_async_cmd(cmd, stdin, container_name_or_id)
        finally:
            Util.rm_env_vars_file(env_file)

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
            "outfile": self.default_run_outfile or subprocess.PIPE,
        }
        if stdin:
            kwargs["stdin"] = True
        try:
            process = run(cmd, **kwargs)
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
            # consider different error messages for Docker/Podman
            error_messages = ("No such container", "no container with name or ID")
            if any(msg.lower() in to_str(e.stderr).lower() for msg in error_messages):
                raise NoSuchContainer(container_name, stdout=e.stdout, stderr=e.stderr)
            raise ContainerException(
                "Docker process returned with errorcode %s" % e.returncode, e.stdout, e.stderr
            ) from e

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
        mount_volumes: Optional[List[SimpleVolumeBind]] = None,
        ports: Optional[PortMappings] = None,
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
    ) -> Tuple[List[str], str]:
        env_file = None
        cmd = self._docker_cmd() + [action]
        if remove:
            cmd.append("--rm")
        if name:
            cmd += ["--name", name]
        if entrypoint is not None:  # empty string entrypoint can be intentional
            cmd += ["--entrypoint", entrypoint]
        if privileged:
            cmd += ["--privileged"]
        if mount_volumes:
            cmd += [
                volume
                for mount_volume in mount_volumes
                for volume in ["-v", self._map_to_volume_param(mount_volume)]
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
            cmd += list(itertools.chain.from_iterable(["--cap-add", cap] for cap in cap_add))
        if cap_drop:
            cmd += list(itertools.chain.from_iterable(["--cap-drop", cap] for cap in cap_drop))
        if security_opt:
            cmd += list(
                itertools.chain.from_iterable(["--security-opt", opt] for opt in security_opt)
            )
        if network:
            cmd += ["--network", network]
        if dns:
            for dns_server in ensure_list(dns):
                cmd += ["--dns", dns_server]
        if workdir:
            cmd += ["--workdir", workdir]
        if labels:
            for key, value in labels.items():
                cmd += ["--label", f"{key}={value}"]
        if platform:
            cmd += ["--platform", platform]
        if ulimits:
            cmd += list(
                itertools.chain.from_iterable(["--ulimits", str(ulimit)] for ulimit in ulimits)
            )

        if additional_flags:
            cmd += shlex.split(additional_flags)
        cmd.append(image_name)
        if command:
            cmd += command if isinstance(command, List) else [command]
        return cmd, env_file

    @staticmethod
    def _map_to_volume_param(mount_volume: Union[SimpleVolumeBind, VolumeBind]) -> str:
        """
        Maps the mount volume, to a parameter for the -v docker cli argument.

        Examples:
        (host_path, container_path) -> host_path:container_path
        VolumeBind(host_dir=host_path, container_dir=container_path, read_only=True) -> host_path:container_path:ro

        :param mount_volume: Either a SimpleVolumeBind, in essence a tuple (host_dir, container_dir), or a VolumeBind object
        :return: String which is passable as parameter to the docker cli -v option
        """
        if isinstance(mount_volume, VolumeBind):
            return mount_volume.to_str()
        else:
            return f"{mount_volume[0]}:{mount_volume[1]}"

    def _check_and_raise_no_such_container_error(
        self, container_name_or_id: str, error: subprocess.CalledProcessError
    ):
        """
        Check the given client invocation error and raise a `NoSuchContainer` exception if it
        represents a `no such container` exception from Docker or Podman.
        """

        # consider different error messages for Docker/Podman
        error_messages = ("No such container", "no container with name or ID")
        process_stdout_lower = to_str(error.stdout).lower()
        if any(msg.lower() in process_stdout_lower for msg in error_messages):
            raise NoSuchContainer(container_name_or_id, stdout=error.stdout, stderr=error.stderr)
