import dataclasses
import os
from typing import Tuple

import click
from rich.rule import Rule

from localstack import config
from localstack.cli import console
from localstack.utils.bootstrap import ContainerConfigurators
from localstack.utils.container_utils.container_client import (
    ContainerConfiguration,
    PortMappings,
    VolumeMappings,
)
from localstack.utils.container_utils.docker_cmd_client import CmdDockerClient
from localstack.utils.files import cache_dir
from localstack.utils.run import run_interactive
from localstack.utils.strings import short_uid

from .configurators import (
    ConfigEnvironmentConfigurator,
    CoverageRunScriptConfigurator,
    DependencyMountConfigurator,
    EntryPointMountConfigurator,
    ImageConfigurator,
    PortConfigurator,
    SourceVolumeMountConfigurator,
)
from .paths import HostPaths


@click.command("run")
@click.option(
    "--image",
    type=str,
    required=False,
    help="Overwrite the container image to be used (defaults to localstack/localstack or "
    "localstack/localstack-pro.",
)
@click.option(
    "--volume-dir",
    type=click.Path(file_okay=False, dir_okay=True),
    required=False,
    help="The localstack volume on the host, default: ~/.cache/localstack/volume",
)
@click.option(
    "--pro/--community",
    is_flag=True,
    default=None,
    help="Whether to start localstack pro or community. If not set, it will guess from the current directory",
)
@click.option(
    "--develop/--no-develop",
    is_flag=True,
    default=False,
    help="Install debugpy and expose port 5678",
)
@click.option(
    "--randomize",
    is_flag=True,
    default=False,
    help="Randomize container name and ports to start multiple instances",
)
@click.option(
    "--mount-source/--no-mount-source",
    is_flag=True,
    default=True,
    help="Mount source files from localstack, localstack-ext, and moto into the container.",
)
@click.option(
    "--mount-dependencies/--no-mount-dependencies",
    is_flag=True,
    default=False,
    help="Whether to mount the dependencies of the current .venv directory into the container. Note this only works if the dependencies are compatible with the python and platform version from the venv and the container.",
)
@click.option(
    "--mount-entrypoints/--no-mount-entrypoints",
    is_flag=True,
    default=False,
    help="Mount entrypoints",
)
@click.option("--mount-docker-socket/--no-docker-socket", is_flag=True, default=True)
@click.option(
    "--env",
    "-e",
    help="Additional environment variables that are passed to the LocalStack container",
    multiple=True,
    required=False,
)
@click.option(
    "--volume",
    "-v",
    help="Additional volume mounts that are passed to the LocalStack container",
    multiple=True,
    required=False,
)
@click.option(
    "--publish",
    "-p",
    help="Additional ports that are published to the host",
    multiple=True,
    required=False,
)
@click.option(
    "--entrypoint",
    type=str,
    required=False,
    help="Additional entrypoint flag passed to docker",
)
@click.option(
    "--network",
    type=str,
    required=False,
    help="Docker network to start the container in",
)
@click.argument("command", nargs=-1, required=False)
def run(
    image: str = None,
    volume_dir: str = None,
    pro: bool = None,
    develop: bool = False,
    randomize: bool = False,
    mount_source: bool = True,
    mount_dependencies: bool = False,
    mount_entrypoints: bool = False,
    mount_docker_socket: bool = True,
    env: Tuple = (),
    volume: Tuple = (),
    publish: Tuple = (),
    entrypoint: str = None,
    network: str = None,
    command: str = None,
):
    """
    A tool for localstack developers to start localstack containers. Run this in your localstack or
    localstack-ext source tree to mount local source files or dependencies into the container.
    Here are some examples::

    \b
        python -m localstack.dev.run
        python -m localstack.dev.run -e DEBUG=1 -e LOCALSTACK_API_KEY=test
        python -m localstack.dev.run -- bash -c 'echo "hello"'

    Explanations and more examples:

    Start a normal container localstack container. If you run this from the localstack-ext repo,
    it will start localstack-pro::

        python -m localstack.dev.run

    If you start localstack-pro, you might also want to add the API KEY as environment variable::

        python -m localstack.dev.run -e DEBUG=1 -e LOCALSTACK_API_KEY=test

    If your local changes are making modifications to plux plugins (e.g., adding new providers or hooks),
    then you also want to mount the newly generated entry_point.txt files into the container::

        python -m localstack.dev.run --mount-entrypoints

    Start a new container with randomized gateway and service ports, and randomized container name::

        python -m localstack.dev.run --randomize

    You can also run custom commands:

        python -m localstack.dev.run bash -c 'echo "hello"'

    Or use custom entrypoints:

        python -m localstack.dev.run --entrypoint /bin/bash -- echo "hello"

    You can import and expose debugpy:

        python -m localstack.dev.run --develop

    You can also mount local dependencies (e.g., pytest and other test dependencies, and then use that
    in the container)::

    \b
        python -m localstack.dev.run --mount-dependencies \\
            -v $PWD/tests:/opt/code/localstack/tests \\
            -- .venv/bin/python -m pytest tests/unit/http_/

    The script generally assumes that you are executing in either localstack or localstack-ext source
    repositories that are organized like this::

    \b
        somedir                              <- your workspace directory
        ├── localstack                       <- execute script in here
        │   ├── ...
        │   ├── localstack                   <- will be mounted into the container
        │   ├── localstack_core.egg-info
        │   ├── setup.cfg
        │   ├── tests
        │   └── ...
        ├── localstack-ext                   <- or execute script in here
        │   ├── ...
        │   ├── localstack_ext               <- will be mounted into the container
        │   ├── localstack_ext.egg-info
        │   ├── setup.cfg
        │   ├── tests
        │   └── ...
        ├── moto
        │   ├── AUTHORS.md
        │   ├── ...
        │   ├── moto                         <- will be mounted into the container
        │   ├── moto_ext.egg-info
        │   ├── setup.cfg
        │   ├── tests
        │   └── ...

    """
    status = console.status("Configuring")
    status.start()

    # set the VOLUME_DIR config variable like in the CLI
    if not os.environ.get("LOCALSTACK_VOLUME_DIR", "").strip():
        config.VOLUME_DIR = str(cache_dir() / "volume")

    # setup important paths on the host
    host_paths = HostPaths(
        # we assume that python -m localstack.dev.run is always executed in the repo source
        workspace_dir=os.path.abspath(os.path.join(os.getcwd(), "..")),
        volume_dir=volume_dir or config.VOLUME_DIR,
    )

    # auto-set pro flag
    if pro is None:
        if os.getcwd().endswith("localstack-ext"):
            pro = True
        else:
            pro = False

    # setup base configuration
    container_config = ContainerConfiguration(
        image_name=image,
        name=config.MAIN_CONTAINER_NAME if not randomize else f"localstack-{short_uid()}",
        remove=True,
        interactive=True,
        tty=True,
        env_vars=dict(),
        volumes=VolumeMappings(),
        ports=PortMappings(),
        network=network,
    )

    # replicate pro startup
    if pro:
        try:
            from localstack_ext.plugins import modify_edge_port_config

            modify_edge_port_config(config)
        except ImportError:
            pass

    # setup configurators
    configurators = [
        ImageConfigurator(pro, image),
        PortConfigurator(randomize),
        ConfigEnvironmentConfigurator(pro),
        ContainerConfigurators.mount_localstack_volume(host_paths.volume_dir),
        CoverageRunScriptConfigurator(host_paths=host_paths),
    ]
    if command:
        configurators.append(ContainerConfigurators.custom_command(list(command)))
    if entrypoint:
        container_config.entrypoint = entrypoint
    if mount_docker_socket:
        configurators.append(ContainerConfigurators.mount_docker_socket)
    if mount_source:
        configurators.append(
            SourceVolumeMountConfigurator(
                host_paths=host_paths,
                pro=pro,
            )
        )
    if mount_entrypoints:
        configurators.append(EntryPointMountConfigurator(host_paths=host_paths, pro=pro))
    if mount_dependencies:
        configurators.append(DependencyMountConfigurator(host_paths=host_paths))
    if develop:
        configurators.append(ContainerConfigurators.develop)

    # make sure anything coming from CLI arguments has priority
    configurators.extend(
        [
            ContainerConfigurators.volume_cli_params(volume),
            ContainerConfigurators.port_cli_params(publish),
            ContainerConfigurators.env_cli_params(env),
        ]
    )

    # run configurators
    for configurator in configurators:
        configurator(container_config)
    # print the config
    print_config(container_config)

    # run the container
    docker = CmdDockerClient()
    status.update("Creating container")
    try:
        container_id = docker.create_container_from_config(container_config)
    finally:
        status.stop()

    rule = Rule(f"Interactive session with {container_id[:12]} 💻")
    console.print(rule)
    try:
        cmd = [*docker._docker_cmd(), "start", "--interactive", "--attach", container_id]
        run_interactive(cmd)
    finally:
        if container_config.remove:
            try:
                if docker.is_container_running(container_id):
                    docker.stop_container(container_id)
                docker.remove_container(container_id)
            except Exception:
                pass


def print_config(cfg: ContainerConfiguration):
    d = dataclasses.asdict(cfg)

    d["volumes"] = [v.to_str() for v in d["volumes"].mappings]
    d["ports"] = [p for p in d["ports"].to_list() if p != "-p"]

    for k in list(d.keys()):
        if d[k] is None:
            d.pop(k)

    console.print(d)


def main():
    run()


if __name__ == "__main__":
    main()
