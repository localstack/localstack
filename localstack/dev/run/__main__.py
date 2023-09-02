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
from localstack.utils.run import run_interactive
from localstack.utils.strings import short_uid

from .configurators import (
    ConfigEnvironmentConfigurator,
    DependencyMountConfigurator,
    EntryPointMountConfigurator,
    EnvironmentVariablesFromParameters,
    ImageConfigurator,
    PortConfigurator,
    SourceVolumeMountConfigurator,
    VolumeFromParameters,
)
from .paths import HostPaths


@click.command("run")
@click.option("--image", type=str, required=False)
@click.option("--volume-dir", type=click.Path(file_okay=False, dir_okay=True), required=False)
@click.option("--pro", is_flag=True, default=False)
@click.option("--randomize", is_flag=True, default=False)
@click.option("--mount-source/--no-mount-source", is_flag=True, default=True)
@click.option("--mount-dependencies/--no-mount-dependencies", is_flag=True, default=False)
@click.option("--mount-entrypoints/--no-mount-entrypoints", is_flag=True, default=False)
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
@click.argument("command", nargs=-1, required=False)
def run(
    image: str = None,
    volume_dir: str = None,
    pro: bool = False,
    randomize: bool = False,
    mount_source: bool = True,
    mount_dependencies: bool = False,
    mount_entrypoints: bool = False,
    mount_docker_socket: bool = True,
    env: Tuple = (),
    volume: Tuple = (),
    command: str = None,
):
    console.print(locals())

    if command:
        entrypoint = ""
        command = list(command)
    else:
        entrypoint = None
        command = None

    status = console.status("Configuring")
    status.start()

    # setup important paths on the host
    host_paths = HostPaths(volume_dir=volume_dir)

    # setup base configuration
    container_config = ContainerConfiguration(
        image_name=image,
        name=config.MAIN_CONTAINER_NAME if not randomize else f"localstack-{short_uid()}",
        remove=True,
        entrypoint=entrypoint,
        interactive=True,
        tty=True,
        env_vars=dict(),
        volumes=VolumeMappings(),
        ports=PortMappings(),
        command=command,
    )

    # setup configurators
    configurators = [
        ImageConfigurator(pro, image),
        PortConfigurator(randomize),
        ConfigEnvironmentConfigurator(pro),
        ContainerConfigurators.mount_localstack_volume(host_paths.volume_dir),
    ]
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

    # make sure anything coming from CLI arguments has priority
    configurators.extend(
        [
            VolumeFromParameters(list(volume)),
            EnvironmentVariablesFromParameters(env),
        ]
    )

    # run configurators
    for configurator in configurators:
        configurator(container_config)
    # print the config
    console.print(container_config.__dict__)

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


def main():
    run()


if __name__ == "__main__":
    main()
