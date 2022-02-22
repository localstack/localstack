import logging
import os
import queue
import socket
import threading
from typing import Dict, List, Optional, Tuple, Union

import docker
from docker import DockerClient
from docker.errors import APIError, ContainerError, DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from docker.utils.socket import STDERR, STDOUT, frames_iter

from localstack.utils.common import start_worker_thread, to_bytes
from localstack.utils.container_utils.container_client import (
    ContainerClient,
    ContainerException,
    DockerContainerStatus,
    NoSuchContainer,
    NoSuchImage,
    NoSuchNetwork,
    PortMappings,
    SimpleVolumeBind,
    Util,
)
from localstack.utils.run import to_str

LOG = logging.getLogger(__name__)
SDK_ISDIR = 1 << 31


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
            elif container.status == "paused":
                return DockerContainerStatus.PAUSED
            else:
                return DockerContainerStatus.DOWN
        except NotFound:
            return DockerContainerStatus.NON_EXISTENT
        except APIError:
            raise ContainerException()

    def stop_container(self, container_name: str, timeout: int = None) -> None:
        if timeout is None:
            timeout = self.STOP_TIMEOUT
        LOG.debug("Stopping container: %s", container_name)
        try:
            container = self.client().containers.get(container_name)
            container.stop(timeout=timeout)
        except NotFound:
            raise NoSuchContainer(container_name)
        except APIError:
            raise ContainerException()

    def pause_container(self, container_name: str) -> None:
        LOG.debug("Pausing container: %s", container_name)
        try:
            container = self.client().containers.get(container_name)
            container.pause()
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
        try:
            LOG.debug("Repository: %s", docker_image)
            self.client().images.pull(docker_image)
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

    def inspect_image(self, image_name: str, pull: bool = True) -> Dict[str, Union[Dict, str]]:
        try:
            return self.client().images.get(image_name).attrs
        except NotFound:
            if pull:
                self.pull_image(image_name)
                return self.inspect_image(image_name, pull=False)
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
        except APIError:
            raise ContainerException()

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

    def remove_image(self, image: str, force: bool = True):
        LOG.debug("Removing image %s %s", image, "(forced)" if force else "")
        try:
            self.client().images.remove(image=image, force=force)
        except ImageNotFound:
            if not force:
                raise NoSuchImage(image)

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
        except APIError:
            raise ContainerException()

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
        LOG.debug("Creating container with attributes: %s", locals())
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
        env_vars: Optional[Dict[str, Optional[str]]] = None,
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
