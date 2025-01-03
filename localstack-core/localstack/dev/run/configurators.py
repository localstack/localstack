"""
Several ContainerConfigurator implementations to set up a development version of a localstack container.
"""

import gzip
import os
from pathlib import Path, PurePosixPath
from tempfile import gettempdir

from localstack import config, constants
from localstack.utils.bootstrap import ContainerConfigurators
from localstack.utils.container_utils.container_client import (
    ContainerClient,
    ContainerConfiguration,
    VolumeBind,
    VolumeMappings,
)
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.files import get_user_cache_dir
from localstack.utils.run import run
from localstack.utils.strings import md5

from .paths import (
    HOST_PATH_MAPPINGS,
    CommunityContainerPaths,
    ContainerPaths,
    HostPaths,
    ProContainerPaths,
)


class ConfigEnvironmentConfigurator:
    """Configures the environment variables from the localstack and localstack-pro config."""

    def __init__(self, pro: bool):
        self.pro = pro

    def __call__(self, cfg: ContainerConfiguration):
        if cfg.env_vars is None:
            cfg.env_vars = {}

        if self.pro:
            # import localstack.pro.core.config extends the list of config vars
            from localstack.pro.core import config as config_pro  # noqa

        ContainerConfigurators.config_env_vars(cfg)


class PortConfigurator:
    """
    Configures the port mappings. Can be randomized to run multiple localstack instances.
    """

    def __init__(self, randomize: bool = True):
        self.randomize = randomize

    def __call__(self, cfg: ContainerConfiguration):
        cfg.ports.bind_host = config.GATEWAY_LISTEN[0].host

        if self.randomize:
            ContainerConfigurators.random_gateway_port(cfg)
            ContainerConfigurators.random_service_port_range()(cfg)
        else:
            ContainerConfigurators.gateway_listen(config.GATEWAY_LISTEN)(cfg)
            ContainerConfigurators.service_port_range(cfg)


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


class CustomEntryPointConfigurator:
    """
    Creates a ``docker-entrypoint-<hash>.sh`` script from the given source and mounts it into the container.
    It also configures the container to then use that entrypoint.
    """

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
            # newline separator should be '\n' independent of the os, since the entrypoint is executed in the container
            # encoding needs to be "utf-8" since scripts could include emojis
            file.write_text(self.script, newline="\n", encoding="utf-8")
            file.chmod(0o777)
        cfg.volumes.add(VolumeBind(str(file), f"/tmp/{file.name}"))
        cfg.entrypoint = f"/tmp/{file.name}"


class SourceVolumeMountConfigurator:
    """
    Mounts source code of localstack, localstack_ext, and moto into the container. It does this by assuming
    that there is a "workspace" directory in which the source repositories are checked out into.
    Depending on whether we want to start the pro container, the source paths for localstack are different.
    """

    def __init__(
        self,
        *,
        host_paths: HostPaths = None,
        pro: bool = False,
        chosen_packages: list[str] | None = None,
    ):
        self.host_paths = host_paths or HostPaths()
        self.container_paths = ProContainerPaths() if pro else CommunityContainerPaths()
        self.pro = pro
        self.chosen_packages = chosen_packages or []

    def __call__(self, cfg: ContainerConfiguration):
        # localstack source code if available
        source = self.host_paths.aws_community_package_dir
        if source.exists():
            cfg.volumes.add(
                # read_only=False is a temporary workaround to make the mounting of the pro source work
                # this can be reverted once we don't need the nested mounting anymore
                VolumeBind(str(source), self.container_paths.localstack_source_dir, read_only=False)
            )

        # ext source code if available
        if self.pro:
            source = self.host_paths.aws_pro_package_dir
            if source.exists():
                cfg.volumes.add(
                    VolumeBind(
                        str(source), self.container_paths.localstack_pro_source_dir, read_only=True
                    )
                )

        # mount local code checkouts if possible
        for package_name in self.chosen_packages:
            # Unconditional lookup because the CLI rejects incorect items
            extractor = HOST_PATH_MAPPINGS[package_name]
            self.try_mount_to_site_packages(cfg, extractor(self.host_paths))

        # docker entrypoint
        if self.pro:
            source = self.host_paths.localstack_pro_project_dir / "bin" / "docker-entrypoint.sh"
        else:
            source = self.host_paths.localstack_project_dir / "bin" / "docker-entrypoint.sh"
        if source.exists():
            cfg.volumes.add(
                VolumeBind(str(source), self.container_paths.docker_entrypoint, read_only=True)
            )

    def try_mount_to_site_packages(self, cfg: ContainerConfiguration, sources_path: Path):
        """
        Attempts to mount something like `~/workspace/plux/plugin` on the host into
        ``.venv/.../site-packages/plugin``.

        :param cfg:
        :param sources_path:
        :return:
        """
        if sources_path.exists():
            cfg.volumes.add(
                VolumeBind(
                    str(sources_path),
                    self.container_paths.dependency_source(sources_path.name),
                    read_only=True,
                )
            )


class EntryPointMountConfigurator:
    """
    Mounts ``entry_points.txt`` files of localstack and dependencies into the venv in the container.

    For example, when starting the pro container, the entrypoints of localstack-ext on the host would be in
    ``~/workspace/localstack-ext/localstack-pro-core/localstack_ext.egg-info/entry_points.txt``
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
        pro: bool = False,
    ):
        self.host_paths = host_paths or HostPaths()
        self.pro = pro
        self.container_paths = container_paths or None

    def __call__(self, cfg: ContainerConfiguration):
        # special case for community code
        if not self.pro:
            host_path = self.host_paths.aws_community_package_dir
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

            if dep == "localstack_core":
                host_path = (
                    self.host_paths.localstack_project_dir
                    / "localstack-core"
                    / "localstack_core.egg-info"
                    / "entry_points.txt"
                )
                if host_path.is_file():
                    cfg.volumes.add(
                        VolumeBind(
                            str(host_path),
                            str(container_path),
                            read_only=True,
                        )
                    )
                    continue
            elif dep == "localstack_ext":
                host_path = (
                    self.host_paths.localstack_pro_project_dir
                    / "localstack-pro-core"
                    / "localstack_ext.egg-info"
                    / "entry_points.txt"
                )
                if host_path.is_file():
                    cfg.volumes.add(
                        VolumeBind(
                            str(host_path),
                            str(container_path),
                            read_only=True,
                        )
                    )
                    continue
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

    # skip mounting dependencies with incompatible binaries (e.g., on macOS)
    skipped_dependencies = ["cryptography", "psutil", "rpds"]

    def __init__(
        self,
        *,
        host_paths: HostPaths = None,
        container_paths: ContainerPaths = None,
        pro: bool = False,
    ):
        self.host_paths = host_paths or HostPaths()
        self.pro = pro
        self.container_paths = container_paths or (
            ProContainerPaths() if pro else CommunityContainerPaths()
        )

    def __call__(self, cfg: ContainerConfiguration):
        # locate all relevant dependency directories
        pattern = self.dependency_glob
        files = _list_files_in_container_image(DOCKER_CLIENT, cfg.image_name)
        paths = [PurePosixPath(f) for f in files]
        # builds an index of "jinja2: /opt/code/.../site-packages/jinja2"
        container_path_index = {p.name: p for p in paths if p.match(pattern)}

        # find dependencies from the host
        for dep_path in self.host_paths.venv_dir.glob("lib/python3.*/site-packages/*"):
            # filter out everything that heuristically cannot be a source path
            if not self._can_be_source_path(dep_path):
                continue
            if dep_path.name.endswith(".dist-info"):
                continue
            if dep_path.name == "__pycache__":
                continue

            if dep_path.name in self.skipped_dependencies:
                continue

            if dep_path.name in container_path_index:
                # find the target path in the index if it exists
                target_path = str(container_path_index[dep_path.name])
            else:
                # if the given dependency is not in the container, then we mount it anyway
                # FIXME: we should also mount the dist-info directory. perhaps this method should be
                #  re-written completely
                target_path = self.container_paths.dependency_source(dep_path.name)

            if self._has_mount(cfg.volumes, target_path):
                continue

            cfg.volumes.append(VolumeBind(str(dep_path), target_path))

    def _can_be_source_path(self, path: Path) -> bool:
        return path.is_dir() or (path.name.endswith(".py") and not path.name.startswith("__"))

    def _has_mount(self, volumes: VolumeMappings, target_path: str) -> bool:
        return True if volumes.find_target_mapping(target_path) else False


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
