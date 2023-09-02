import gzip
import os
from pathlib import Path, PurePosixPath
from tempfile import gettempdir
from typing import Iterable, List

from localstack import config, constants
from localstack.utils.container_utils.container_client import (
    ContainerClient,
    ContainerConfiguration,
    VolumeBind,
    VolumeMappings,
)
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.files import get_user_cache_dir
from localstack.utils.net import get_free_tcp_port
from localstack.utils.run import run
from localstack.utils.strings import md5

from .paths import CommunityContainerPaths, ContainerPaths, HostPaths, ProContainerPaths


class VolumeFromParameters:
    def __init__(self, params: List[str]):
        self.params = params

    def __call__(self, cfg: ContainerConfiguration):
        for param in self.params:
            cfg.volumes.append(self._parse(param))

    def _parse(self, param: str) -> VolumeBind:
        parts = param.split(":")
        if 1 > len(parts) > 3:
            raise ValueError(f"Cannot parse volume bind {param}")

        volume = VolumeBind(parts[0], parts[1])
        if len(parts) == 3:
            if parts[3] == "ro":
                volume.read_only = True
        return volume


class EnvironmentVariablesFromParameters:
    """Configures the environment variables from additional CLI input through the ``-e`` options."""

    def __init__(self, env_args: Iterable[str]):
        self.env_args = env_args or ()

    def __call__(self, cfg: ContainerConfiguration):
        for kv in self.env_args:
            kv = kv.split("=", maxsplit=1)
            k = kv[0]
            v = kv[1] if len(kv) == 2 else os.environ.get(k)
            if v is not None:
                cfg.env_vars[k] = v


class ConfigEnvironmentConfigurator:
    """Configures the environment variables from the localstack and localstack_ext config."""

    def __init__(self, pro: bool):
        self.pro = pro

    def __call__(self, cfg: ContainerConfiguration):
        if cfg.env_vars is None:
            cfg.env_vars = {}

        if self.pro:
            from localstack_ext import config as config_ext  # noqa

        # set env vars from config
        for env_var in config.CONFIG_ENV_VARS:
            value = os.environ.get(env_var, None)
            if value is not None:
                cfg.env_vars[env_var] = value


class PortConfigurator:
    """
    Configures the port mappings. Can be randomized to run multiple localstack instances.
    """

    def __init__(self, randomize: bool = True):
        self.randomize = randomize

    def __call__(self, cfg: ContainerConfiguration):
        cfg.ports.bind_host = config.EDGE_BIND_HOST

        if self.randomize:
            # TODO: randomize ports and set config accordingly (also set GATEWAY_LISTEN)
            cfg.ports.add(get_free_tcp_port(), constants.DEFAULT_PORT_EDGE)
        else:
            cfg.ports.add(constants.DEFAULT_PORT_EDGE)
            cfg.ports.add([config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END])


class ImageConfigurator:
    """
    Sets the container image to use for the container (by default either localstack/localstack or
    localstack/localstack-pro)
    """

    def __init__(self, pro: bool, image_name: str | None):
        self.pro = pro
        self.image_name = image_name

    def __call__(self, cfg: ContainerConfiguration):
        if self.image_name:
            cfg.image_name = self.image_name
        else:
            if self.pro:
                cfg.image_name = constants.DOCKER_IMAGE_NAME_PRO
            else:
                cfg.image_name = constants.DOCKER_IMAGE_NAME


class SourceVolumeMountConfigurator:
    site_packages_target_dir = "/opt/code/localstack/.venv/lib/python3.10/site-packages"
    """Constant for the site-packages dir path within the container."""

    localstack_project_dir: str
    localstack_ext_project_dir: str
    venv_path: str
    pro: bool
    mount_source: bool
    mount_dependencies: bool
    mount_entrypoints: bool

    def __init__(
        self,
        *,
        host_paths: HostPaths = None,
        pro: bool = False,
    ):
        self.host_paths = host_paths or HostPaths()
        self.container_paths = ProContainerPaths() if pro else CommunityContainerPaths()
        self.pro = pro

    def __call__(self, cfg: ContainerConfiguration):
        # localstack source code if available
        source = self.host_paths.localstack_project_dir / "localstack"
        if source.exists():
            cfg.volumes.add(
                VolumeBind(str(source), self.container_paths.localstack_source_dir, read_only=True)
            )

        # ext source code if available
        if self.pro:
            source = self.host_paths.localstack_ext_project_dir / "localstack_ext"
            if source.exists():
                cfg.volumes.add(
                    VolumeBind(
                        str(source), self.container_paths.localstack_ext_source_dir, read_only=True
                    )
                )

        # moto code if available
        source = self.host_paths.moto_project_dir / "moto"
        if source.exists():
            cfg.volumes.add(
                VolumeBind(
                    str(source), self.container_paths.dependency_source("moto"), read_only=True
                )
            )

        # docker entrypoint
        if self.pro:
            source = self.host_paths.localstack_ext_project_dir / "bin" / "docker-entrypoint.sh"
        else:
            source = self.host_paths.localstack_project_dir / "bin" / "docker-entrypoint.sh"
        if source.exists():
            cfg.volumes.add(
                VolumeBind(str(source), self.container_paths.docker_entrypoint, read_only=True)
            )


class CoverageRunScriptConfigurator:
    """
    Adds the coverage-run.py script as read-only volume mount into /opt/code/localstack/bin/coverage-run.py
    """

    def __init__(self, *, host_paths: HostPaths = None):
        self.host_paths = host_paths or HostPaths()
        self.container_paths = ProContainerPaths()

    def __call__(self, cfg: ContainerConfiguration):
        # coverage script
        source = self.host_paths.localstack_ext_project_dir / "bin" / "coverage-run.py"
        target = f"{self.container_paths.project_dir}/bin/coverage-run.py"
        if source.exists():
            cfg.volumes.add(VolumeBind(str(source), target, read_only=True))

        # and add the pyproject toml since it contains the coverage config
        source = self.host_paths.localstack_ext_project_dir / "pyproject.toml"
        target = f"{self.container_paths.project_dir}/pyproject.toml"
        if source.exists():
            cfg.volumes.add(VolumeBind(str(source), target, read_only=True))


class CustomEntryPointConfigurator:
    def __init__(self, script: str, tmp_dir: str = None):
        self.script = script.lstrip(os.linesep)
        self.container_paths = ProContainerPaths()
        self.tmp_dir = tmp_dir

    def __call__(self, cfg: ContainerConfiguration):
        h = md5(self.script)
        tempdir = gettempdir() if not self.tmp_dir else self.tmp_dir
        file_name = f"docker-entrypoint-{h}.sh"

        file = Path(tempdir, file_name)
        if not file.exists():
            file.write_text(self.script)
            file.chmod(0o777)
        cfg.volumes.add(VolumeBind(str(file), f"/tmp/{file.name}"))
        cfg.entrypoint = f"/tmp/{file.name}"


class EntryPointMountConfigurator:
    """
    Mounts ``entry_points.txt`` files of localstack and dependencies into the venv in the container.

    For example, when starting the pro container, the entrypoints of localstack-ext on the host would be in
    ``~/workspace/localstack-ext/localstack_ext.egg-info/entry_points.txt``
    which needs to be mounted into the distribution info of the installed dependency within the container:
    ``/opt/code/localstack/.venv/.../site-packages/localstack_ext-2.1.0.dev0.dist-info/entry_points.txt``.
    """

    entry_point_glob = (
        "/opt/code/localstack/.venv/lib/python3.*/site-packages/*.dist-info/entry_points.txt"
    )
    localstack_community_entry_points = (
        "/opt/code/localstack/localstack_core.egg-info/entry_points.txt"
    )

    def __init__(
        self,
        *,
        host_paths: HostPaths = None,
        container_paths: ContainerPaths = None,
        venv_path: Path = None,
        pro: bool = False,
    ):
        self.host_paths = host_paths or HostPaths()
        self.pro = pro
        self.venv_path = venv_path or Path(os.path.join(os.getcwd(), ".venv"))  # FIXME
        self.container_paths = container_paths or None

    def __call__(self, cfg: ContainerConfiguration):
        # special case for community code
        if not self.pro:
            host_path = (
                self.host_paths.localstack_project_dir
                / "localstack_core.egg-info"
                / "entry_points.txt"
            )
            if host_path.exists():
                cfg.volumes.append(
                    VolumeBind(
                        str(host_path), self.localstack_community_entry_points, read_only=True
                    )
                )

        # locate all relevant entry_point.txt files within the container
        pattern = self.entry_point_glob
        files = _list_files_in_container_image(DOCKER_CLIENT, cfg.image_name)
        paths = [PurePosixPath(f) for f in files]
        paths = [p for p in paths if p.match(pattern)]

        # then, check whether they exist in some form on the host within the workspace directory
        for container_path in paths:
            dep_path = container_path.parent.name.removesuffix(".dist-info")
            dep, ver = dep_path.split("-")

            for host_path in self.host_paths.workspace_dir.glob(
                f"*/{dep}.egg-info/entry_points.txt"
            ):
                cfg.volumes.add(VolumeBind(str(host_path), str(container_path), read_only=True))
                break


class DependencyMountConfigurator:
    """
    Mounts source folders from your host's .venv directory into the container's .venv.
    """

    dependency_glob = "/opt/code/localstack/.venv/lib/python3.*/site-packages/*"

    def __init__(
        self,
        *,
        host_paths: HostPaths = None,
        container_paths: ContainerPaths = None,
        venv_path: Path = None,
        pro: bool = False,
    ):
        self.host_paths = host_paths
        self.pro = pro
        self.venv_path = venv_path or Path(os.path.join(os.getcwd(), ".venv"))  # FIXME
        self.container_paths = container_paths or None

    def __call__(self, cfg: ContainerConfiguration):
        # locate all relevant dependency directories
        pattern = self.dependency_glob
        files = _list_files_in_container_image(DOCKER_CLIENT, cfg.image_name)
        paths = [PurePosixPath(f) for f in files]
        # builds an index of "jinja2: /opt/code/.../site-packages/jinja2"
        container_path_index = {p.name: p for p in paths if p.match(pattern)}

        # find dependencies from the host
        for dep_path in self.venv_path.glob("lib/python3.*/site-packages/*"):
            # filter out everything that heuristically cannot be a source directory
            if not dep_path.is_dir():
                continue
            if dep_path.name.endswith(".dist-info"):
                continue
            if dep_path.name == "__pycache__":
                continue

            # if the dependency is not in the container, then don't mount it
            # TODO: this could be useful though, but in that case i would just explicitly mount it using `-v`
            if dep_path.name not in container_path_index:
                continue

            # find the target path in the index
            target_path = str(container_path_index[dep_path.name])

            if self._has_mount(cfg.volumes, target_path):
                continue

            cfg.volumes.append(VolumeBind(str(dep_path), str(container_path_index[dep_path.name])))

    def _has_mount(self, volumes: VolumeMappings, target_path: str) -> bool:
        for volume in volumes:
            # don't overwrite volumes that were already done via SourceVolumeMountConfigurator
            if volume.container_dir == target_path:
                return True

        return False


def _list_files_in_container_image(container_client: ContainerClient, image_name: str) -> list[str]:
    """
    Uses ``docker export | tar -t`` to list all files in a given docker image. It caches the result based on
    the image ID into a gziped file into ``~/.cache/localstack-dev-cli`` to (significantly) speed up
    subsequent calls.

    :param container_client: the container client to use
    :param image_name: the container image to analyze
    :return: a list of file paths
    """
    if not image_name:
        raise ValueError("missing image name")

    image_id = container_client.inspect_image(image_name)["Id"]

    cache_dir = get_user_cache_dir() / "localstack-dev-cli"
    cache_dir.mkdir(exist_ok=True, parents=True)
    cache_file = cache_dir / f"{image_id}.files.txt.gz"

    if not cache_file.exists():
        container_id = container_client.create_container(image_name=image_name)
        try:
            # docker export yields paths without prefixed slashes, so we add them here
            # since the file is pretty big (~4MB for community, ~7MB for pro) we gzip it
            cmd = "docker export %s | tar -t | awk '{ print \"/\" $0 }' | gzip > %s" % (
                container_id,
                cache_file,
            )
            run(cmd, shell=True)
        finally:
            container_client.remove_container(container_id)

    with gzip.open(cache_file, mode="rt") as fd:
        return fd.read().splitlines(keepends=False)
