import base64
import json
import logging
import os
import queue
import re
import socket
import threading
from time import sleep
from typing import Dict, List, Optional, Tuple, Union, cast
from urllib.parse import quote

import docker
from docker import DockerClient
from docker.errors import APIError, ContainerError, DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from docker.utils.socket import STDERR, STDOUT, frames_iter

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
    PortMappings,
    RegistryConnectionError,
    SimpleVolumeBind,
    Ulimit,
    Util,
)
from localstack.utils.strings import to_bytes, to_str
from localstack.utils.threads import start_worker_thread

LOG = logging.getLogger(__name__)
SDK_ISDIR = 1 << 31


class SdkDockerClient(ContainerClient):
    """
    Class for managing Docker (or Podman) using the Python Docker SDK.

    The client also supports targeting Podman engines, as Podman is almost a drop-in replacement
    for Docker these days (with ongoing efforts to further streamline the two), and the Docker SDK
    is doing some of the heavy lifting for us to support both target platforms.
    """

    docker_client: Optional[DockerClient]

    def __init__(self):
        try:
            self.docker_client = self._create_client()
            logging.getLogger("urllib3").setLevel(logging.INFO)
        except DockerNotAvailable:
            self.docker_client = None

    def client(self):
        if self.docker_client:
            return self.docker_client
        # if the initialization failed before, try to initialize on-demand
        self.docker_client = self._create_client()
        return self.docker_client

    @staticmethod
    def _create_client():
        from localstack.config import DOCKER_SDK_DEFAULT_RETRIES, DOCKER_SDK_DEFAULT_TIMEOUT_SECONDS

        for attempt in range(0, DOCKER_SDK_DEFAULT_RETRIES + 1):
            try:
                return docker.from_env(timeout=DOCKER_SDK_DEFAULT_TIMEOUT_SECONDS)
            except DockerException as e:
                LOG.debug("Creating Docker SDK client failed: %s", e, exc_info=e)
                if attempt < DOCKER_SDK_DEFAULT_RETRIES:
                    # wait for a second before retrying
                    sleep(1)
                else:
                    # we are out of attempts
                    raise DockerNotAvailable("Docker not available") from e

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
        api_client = self.client().api

        def _head(path_suffix, **kwargs):
            return api_client.head(
                api_client.base_url + path_suffix, **api_client._set_request_timeout(kwargs)
            )

        escaped_id = quote(container.id, safe="/:")
        result = _head(f"/containers/{escaped_id}/archive", params={"path": container_path})
        stats = result.headers.get("X-Docker-Container-Path-Stat")
        target_exists = result.ok

        if target_exists:
            stats = json.loads(base64.b64decode(stats).decode("utf-8"))
        target_is_dir = target_exists and bool(stats["mode"] & SDK_ISDIR)
        return target_exists, target_is_dir

    def get_system_info(self) -> dict:
        return self.client().info()

    def get_container_status(self, container_name: str) -> DockerContainerStatus:
        # LOG.debug("Getting container status for container: %s", container_name) #  too verbose
        try:
            container = self.client().containers.get(container_name)
            if container.status == "running":
                return DockerContainerStatus.UP
            elif container.status == "paused":
                return DockerContainerStatus.PAUSED
            else:
                return DockerContainerStatus.DOWN
        except NotFound:
            return DockerContainerStatus.NON_EXISTENT
        except APIError as e:
            raise ContainerException() from e

    def stop_container(self, container_name: str, timeout: int = 10) -> None:
        LOG.debug("Stopping container: %s", container_name)
        try:
            container = self.client().containers.get(container_name)
            container.stop(timeout=timeout)
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError as e:
            raise ContainerException() from e

    def restart_container(self, container_name: str, timeout: int = 10) -> None:
        LOG.debug("Restarting container: %s", container_name)
        try:
            container = self.client().containers.get(container_name)
            container.restart(timeout=timeout)
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError as e:
            raise ContainerException() from e

    def pause_container(self, container_name: str) -> None:
        LOG.debug("Pausing container: %s", container_name)
        try:
            container = self.client().containers.get(container_name)
            container.pause()
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError as e:
            raise ContainerException() from e

    def unpause_container(self, container_name: str) -> None:
        LOG.debug("Unpausing container: %s", container_name)
        try:
            container = self.client().containers.get(container_name)
            container.unpause()
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError as e:
            raise ContainerException() from e

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
        except APIError as e:
            raise ContainerException() from e

    def list_containers(self, filter: Union[List[str], str, None] = None, all=True) -> List[dict]:
        if filter:
            filter = [filter] if isinstance(filter, str) else filter
            filter = dict([f.split("=", 1) for f in filter])
        LOG.debug("Listing containers with filters: %s", filter)
        try:
            container_list = self.client().containers.list(filters=filter, all=all)
            result = []
            for container in container_list:
                try:
                    result.append(
                        {
                            "id": container.id,
                            "image": container.image,
                            "name": container.name,
                            "status": container.status,
                            "labels": container.labels,
                        }
                    )
                except Exception as e:
                    LOG.error(f"Error checking container {container}: {e}")
            return result
        except APIError as e:
            raise ContainerException() from e

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
        except APIError as e:
            raise ContainerException() from e

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
        except APIError as e:
            raise ContainerException() from e

    def pull_image(self, docker_image: str, platform: Optional[DockerPlatform] = None) -> None:
        LOG.debug("Pulling Docker image: %s", docker_image)
        # some path in the docker image string indicates a custom repository
        try:
            self.client().images.pull(docker_image, platform=platform)
        except ImageNotFound:
            raise NoSuchImage(docker_image)
        except APIError as e:
            raise ContainerException() from e

    def push_image(self, docker_image: str) -> None:
        LOG.debug("Pushing Docker image: %s", docker_image)
        try:
            result = self.client().images.push(docker_image)
            # some SDK clients (e.g., 5.0.0) seem to return an error string, instead of raising
            if isinstance(result, (str, bytes)) and '"errorDetail"' in to_str(result):
                if "image does not exist locally" in to_str(result):
                    raise NoSuchImage(docker_image)
                if "is denied" in to_str(result):
                    raise AccessDenied(docker_image)
                if "requesting higher privileges than access token allows" in to_str(result):
                    raise AccessDenied(docker_image)
                if "access token has insufficient scopes" in to_str(result):
                    raise AccessDenied(docker_image)
                if "connection refused" in to_str(result):
                    raise RegistryConnectionError(result)
                raise ContainerException(result)
        except ImageNotFound:
            raise NoSuchImage(docker_image)
        except APIError as e:
            # note: error message 'image not known' raised by Podman API
            if "image not known" in str(e):
                raise NoSuchImage(docker_image)
            raise ContainerException() from e

    def build_image(
        self,
        dockerfile_path: str,
        image_name: str,
        context_path: str = None,
        platform: Optional[DockerPlatform] = None,
    ):
        try:
            dockerfile_path = Util.resolve_dockerfile_path(dockerfile_path)
            context_path = context_path or os.path.dirname(dockerfile_path)
            LOG.debug("Building Docker image %s from %s", image_name, dockerfile_path)
            self.client().images.build(
                path=context_path,
                dockerfile=dockerfile_path,
                tag=image_name,
                rm=True,
                platform=platform,
            )
        except APIError as e:
            raise ContainerException("Unable to build Docker image") from e

    def tag_image(self, source_ref: str, target_name: str) -> None:
        try:
            LOG.debug("Tagging Docker image '%s' as '%s'", source_ref, target_name)
            image = self.client().images.get(source_ref)
            image.tag(target_name)
        except APIError as e:
            if e.status_code == 404:
                raise NoSuchImage(source_ref)
            raise ContainerException("Unable to tag Docker image") from e

    def get_docker_image_names(
        self,
        strip_latest: bool = True,
        include_tags: bool = True,
        strip_wellknown_repo_prefixes: bool = True,
    ):
        try:
            images = self.client().images.list()
            image_names = [tag for image in images for tag in image.tags if image.tags]
            if not include_tags:
                image_names = [image_name.rpartition(":")[0] for image_name in image_names]
            if strip_wellknown_repo_prefixes:
                image_names = Util.strip_wellknown_repo_prefixes(image_names)
            if strip_latest:
                Util.append_without_latest(image_names)
            return image_names
        except APIError as e:
            raise ContainerException() from e

    def get_container_logs(self, container_name_or_id: str, safe: bool = False) -> str:
        try:
            container = self.client().containers.get(container_name_or_id)
            return to_str(container.logs())
        except NotFound:
            if safe:
                return ""
            raise NoSuchContainer(container_name_or_id)
        except APIError as e:
            if safe:
                return ""
            raise ContainerException() from e

    def stream_container_logs(self, container_name_or_id: str) -> CancellableStream:
        try:
            container = self.client().containers.get(container_name_or_id)
            return container.logs(stream=True, follow=True)
        except NotFound:
            raise NoSuchContainer(container_name_or_id)
        except APIError as e:
            raise ContainerException() from e

    def inspect_container(self, container_name_or_id: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self.client().containers.get(container_name_or_id).attrs
        except NotFound:
            raise NoSuchContainer(container_name_or_id)
        except APIError as e:
            raise ContainerException() from e

    def inspect_image(
        self,
        image_name: str,
        pull: bool = True,
        strip_wellknown_repo_prefixes: bool = True,
    ) -> Dict[str, Union[dict, list, str]]:
        try:
            result = self.client().images.get(image_name).attrs
            if strip_wellknown_repo_prefixes:
                if result.get("RepoDigests"):
                    result["RepoDigests"] = Util.strip_wellknown_repo_prefixes(
                        result["RepoDigests"]
                    )
                if result.get("RepoTags"):
                    result["RepoTags"] = Util.strip_wellknown_repo_prefixes(result["RepoTags"])
            return result
        except NotFound:
            if pull:
                self.pull_image(image_name)
                return self.inspect_image(image_name, pull=False)
            raise NoSuchImage(image_name)
        except APIError as e:
            raise ContainerException() from e

    def create_network(self, network_name: str) -> None:
        try:
            return self.client().networks.create(name=network_name).id
        except APIError as e:
            raise ContainerException() from e

    def delete_network(self, network_name: str) -> None:
        try:
            return self.client().networks.get(network_name).remove()
        except NotFound:
            raise NoSuchNetwork(network_name)
        except APIError as e:
            raise ContainerException() from e

    def inspect_network(self, network_name: str) -> Dict[str, Union[Dict, str]]:
        try:
            return self.client().networks.get(network_name).attrs
        except NotFound:
            raise NoSuchNetwork(network_name)
        except APIError as e:
            raise ContainerException() from e

    def connect_container_to_network(
        self, network_name: str, container_name_or_id: str, aliases: Optional[List] = None
    ) -> None:
        LOG.debug(
            "Connecting container '%s' to network '%s' with aliases '%s'",
            container_name_or_id,
            network_name,
            aliases,
        )
        try:
            network = self.client().networks.get(network_name)
        except NotFound:
            raise NoSuchNetwork(network_name)
        try:
            network.connect(container=container_name_or_id, aliases=aliases)
        except NotFound:
            raise NoSuchContainer(container_name_or_id)
        except APIError as e:
            raise ContainerException() from e

    def disconnect_container_from_network(
        self, network_name: str, container_name_or_id: str
    ) -> None:
        LOG.debug(
            "Disconnecting container '%s' from network '%s'", container_name_or_id, network_name
        )
        try:
            try:
                network = self.client().networks.get(network_name)
            except NotFound:
                raise NoSuchNetwork(network_name)
            try:
                network.disconnect(container_name_or_id)
            except NotFound:
                raise NoSuchContainer(container_name_or_id)
        except APIError as e:
            raise ContainerException() from e

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

    def remove_image(self, image: str, force: bool = True):
        LOG.debug("Removing image %s %s", image, "(forced)" if force else "")
        try:
            self.client().images.remove(image=image, force=force)
        except ImageNotFound:
            if not force:
                raise NoSuchImage(image)
        except APIError as e:
            if "image not known" in str(e):
                raise NoSuchImage(image)
            raise ContainerException() from e

    def commit(
        self,
        container_name_or_id: str,
        image_name: str,
        image_tag: str,
    ):
        LOG.debug(
            "Creating image from container %s as %s:%s", container_name_or_id, image_name, image_tag
        )
        try:
            container = self.client().containers.get(container_name_or_id)
            container.commit(repository=image_name, tag=image_tag)
        except NotFound:
            raise NoSuchContainer(container_name_or_id)
        except APIError as e:
            raise ContainerException() from e

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
                # under windows, the socket has no __enter__ / cannot be used as context manager
                # therefore try/finally instead of with here
                try:
                    if stdin:
                        sock.sendall(to_bytes(stdin))
                        sock.shutdown(socket.SHUT_WR)
                    stdout, stderr = self._read_from_sock(sock, False)
                except socket.timeout:
                    LOG.debug(
                        f"Socket timeout when talking to the I/O streams of Docker container '{container_name_or_id}'"
                    )
                finally:
                    sock.close()

                # get container exit code
                exit_code = result_queue.get()
                if exit_code:
                    raise ContainerException(
                        f"Docker container returned with exit code {exit_code}",
                        stdout=stdout,
                        stderr=stderr,
                    )
            else:
                container.start()
            return stdout, stderr
        except NotFound:
            raise NoSuchContainer(container_name_or_id)
        except APIError as e:
            raise ContainerException() from e

    def attach_to_container(self, container_name_or_id: str):
        client: DockerClient = self.client()
        container = cast(Container, client.containers.get(container_name_or_id))
        container.attach()

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
    ) -> str:
        LOG.debug("Creating container with attributes: %s", locals())
        extra_hosts = None
        if additional_flags:
            parsed_flags = Util.parse_additional_flags(
                additional_flags,
                env_vars=env_vars,
                mounts=mount_volumes,
                network=network,
                platform=platform,
                privileged=privileged,
                ports=ports,
                ulimits=ulimits,
                user=user,
                dns=dns,
            )
            env_vars = parsed_flags.env_vars
            extra_hosts = parsed_flags.extra_hosts
            mount_volumes = parsed_flags.mounts
            labels = parsed_flags.labels
            network = parsed_flags.network
            platform = parsed_flags.platform
            privileged = parsed_flags.privileged
            ports = parsed_flags.ports
            ulimits = parsed_flags.ulimits
            user = parsed_flags.user
            dns = parsed_flags.dns

        try:
            kwargs = {}
            if cap_add:
                kwargs["cap_add"] = cap_add
            if cap_drop:
                kwargs["cap_drop"] = cap_drop
            if security_opt:
                kwargs["security_opt"] = security_opt
            if dns:
                kwargs["dns"] = ensure_list(dns)
            if exposed_ports:
                # This is not exactly identical to --expose, as they are listed in the "HostConfig" on docker inspect
                # but the behavior should be identical
                kwargs["ports"] = {port: [] for port in exposed_ports}
            if ports:
                kwargs.setdefault("ports", {})
                kwargs["ports"].update(ports.to_dict())
            if workdir:
                kwargs["working_dir"] = workdir
            if privileged:
                kwargs["privileged"] = True
            if labels:
                kwargs["labels"] = labels
            if ulimits:
                kwargs["ulimits"] = [
                    docker.types.Ulimit(
                        name=ulimit.name, soft=ulimit.soft_limit, hard=ulimit.hard_limit
                    )
                    for ulimit in ulimits
                ]
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
                    platform=platform,
                    **kwargs,
                )

            try:
                container = create_container()
            except ImageNotFound:
                LOG.debug("Image not found. Pulling image %s", image_name)
                self.pull_image(image_name, platform)
                container = create_container()
            return container.id
        except ImageNotFound:
            raise NoSuchImage(image_name)
        except APIError as e:
            raise ContainerException() from e

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
        mount_volumes: Optional[List[SimpleVolumeBind]] = None,
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
        platform: Optional[DockerPlatform] = None,
        privileged: Optional[bool] = None,
        ulimits: Optional[List[Ulimit]] = None,
    ) -> Tuple[bytes, bytes]:
        LOG.debug("Running container with image: %s", image_name)
        container = None
        try:
            kwargs = {}
            if ulimits:
                kwargs["ulimits"] = [
                    docker.types.Ulimit(
                        name=ulimit.name, soft=ulimit.soft_limit, hard=ulimit.hard_limit
                    )
                    for ulimit in ulimits
                ]
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
                exposed_ports=exposed_ports,
                env_vars=env_vars,
                user=user,
                cap_add=cap_add,
                cap_drop=cap_drop,
                security_opt=security_opt,
                network=network,
                dns=dns,
                additional_flags=additional_flags,
                workdir=workdir,
                privileged=privileged,
                platform=platform,
                **kwargs,
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
        env_vars: Optional[Dict[str, Optional[str]]] = None,
        stdin: Optional[bytes] = None,
        user: Optional[str] = None,
        workdir: Optional[str] = None,
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
                workdir=workdir,
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
                        f"Exec command returned with exit code {return_code}", stdout, stderr
                    )
                return stdout, stderr
        except ContainerError:
            raise NoSuchContainer(container_name_or_id)
        except APIError as e:
            raise ContainerException() from e

    def login(self, username: str, password: str, registry: Optional[str] = None) -> None:
        LOG.debug("Docker login for %s", username)
        try:
            self.client().login(username, password=password, registry=registry, reauth=True)
        except APIError as e:
            raise ContainerException() from e


# apply patches required for podman API compatibility


@property
def _container_image(self):
    image_id = self.attrs.get("ImageID", self.attrs["Image"])
    if image_id is None:
        return None
    image_ref = image_id
    # Fix for podman API response: Docker returns "sha:..." for `Image`, podman returns "<image-name>:<tag>".
    # See https://github.com/containers/podman/issues/8329 . Without this check, the Docker client would
    # blindly strip off the suffix after the colon `:` (which is the `<tag>` in podman's case) which would
    # then lead to "no such image" errors.
    if re.match("sha256:[0-9a-f]{64}", image_id, flags=re.IGNORECASE):
        image_ref = image_id.split(":")[1]
    return self.client.images.get(image_ref)


Container.image = _container_image
