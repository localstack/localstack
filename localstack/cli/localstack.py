import os
import sys
from typing import Dict

import click

from localstack import __version__

from .console import BANNER, console
from .plugin import LocalstackCli, load_cli_plugins


def create_with_plugins() -> LocalstackCli:
    """
    Creates a LocalstackCli instance with all cli plugins loaded.
    :return: a LocalstackCli instance
    """
    cli = LocalstackCli()
    cli.group = localstack
    load_cli_plugins(cli)
    return cli


def _setup_cli_debug():
    from localstack import config
    from localstack.utils.bootstrap import setup_logging

    config.DEBUG = True
    os.environ["DEBUG"] = "1"

    setup_logging()


@click.group(name="localstack", help="The LocalStack Command Line Interface (CLI)")
@click.version_option(version=__version__, message="%(version)s")
@click.option("--debug", is_flag=True, help="Enable CLI debugging mode")
def localstack(debug):
    if debug:
        _setup_cli_debug()


@localstack.group(name="config", help="Inspect your LocalStack configuration")
def localstack_config():
    pass


@localstack.group(
    name="status",
    help="Print status information about the LocalStack runtime",
    invoke_without_command=True,
)
@click.pass_context
def localstack_status(ctx):
    if ctx.invoked_subcommand is None:
        ctx.invoke(localstack_status.get_command(ctx, "docker"))


@localstack_status.command(
    name="docker", help="Query information about the LocalStack Docker image and runtime"
)
def cmd_status_docker():
    with console.status("Querying Docker status"):
        print_docker_status()


@localstack_status.command(name="services", help="Query information about running services")
def cmd_status_services():
    import requests

    from localstack import config

    url = config.get_edge_url()

    try:
        health = requests.get(f"{url}/health")
        doc = health.json()
        services = doc.get("services", [])
        print_service_table(services)
    except requests.ConnectionError:
        err = "[bold][red]:heavy_multiplication_x: ERROR[/red][/bold]"
        console.print(f"{err}: could not connect to LocalStack health endpoint at {url}")
        if config.DEBUG:
            console.print_exception()
        sys.exit(1)


@localstack.command(name="start", help="Start LocalStack")
@click.option("--docker", is_flag=True, help="Start LocalStack in a docker container (default)")
@click.option("--host", is_flag=True, help="Start LocalStack directly on the host")
@click.option("--no-banner", is_flag=True, help="Disable LocalStack banner", default=False)
def cmd_start(docker: bool, host: bool, no_banner: bool):
    if docker and host:
        raise click.ClickException("Please specify either --docker or --host")

    if not no_banner:
        print_banner()
        print_version()
        console.line()

    from localstack.utils import bootstrap

    if not no_banner:
        if host:
            console.log("starting LocalStack in host mode :laptop_computer:")
        else:
            console.log("starting LocalStack in Docker mode :whale:")

        console.rule("LocalStack Runtime Log (press [bold][yellow]CTRL-C[/yellow][/bold] to quit)")

    if host:
        bootstrap.start_infra_locally()
    else:
        bootstrap.start_infra_in_docker()


@localstack_config.command(
    name="validate", help="Validate your LocalStack configuration (e.g., your docker-compose.yml)"
)
@click.option(
    "--file",
    default="docker-compose.yml",
    type=click.Path(exists=True, file_okay=True, readable=True),
)
def cmd_config_validate(file):
    from rich.panel import Panel

    from localstack.utils import bootstrap

    try:
        if bootstrap.validate_localstack_config(file):
            console.print("[green]:heavy_check_mark:[/green] config valid")
            sys.exit(0)
        else:
            console.print("[red]:heavy_multiplication_x:[/red] validation error")
            sys.exit(1)
    except Exception as e:
        console.print(Panel(str(e), title="[red]Error[/red]", expand=False))
        console.print("[red]:heavy_multiplication_x:[/red] validation error")
        sys.exit(1)


@localstack.command(name="ssh", help="Obtain a shell in the running LocalStack container")
def cmd_ssh():
    from localstack import config
    from localstack.utils.docker_utils import DOCKER_CLIENT
    from localstack.utils.run import run

    if not DOCKER_CLIENT.is_container_running(config.MAIN_CONTAINER_NAME):
        raise click.ClickException(
            'Expected a running container named "%s", but found none' % config.MAIN_CONTAINER_NAME
        )
    try:
        process = run("docker exec -it %s bash" % config.MAIN_CONTAINER_NAME, tty=True)
        process.wait()
    except KeyboardInterrupt:
        pass


# legacy support
@localstack.group(
    name="infra",
    help="Manipulate LocalStack infrastructure (legacy)",
)
def infra():
    pass


@infra.command("start")
@click.pass_context
@click.option("--docker", is_flag=True, help="Start LocalStack in a docker container (default)")
@click.option("--host", is_flag=True, help="Start LocalStack directly on the host")
def cmd_infra_start(ctx, *args, **kwargs):
    ctx.invoke(cmd_start, *args, **kwargs)


def print_docker_status():
    from rich.table import Table

    from localstack import config
    from localstack.utils import docker
    from localstack.utils.bootstrap import (
        get_docker_image_details,
        get_main_container_ip,
        get_main_container_name,
        get_server_version,
    )

    grid = Table(show_header=False)
    grid.add_column()
    grid.add_column()

    # version
    grid.add_row("Runtime version", "[bold]%s[/bold]" % get_server_version())

    # image
    img = get_docker_image_details()
    grid.add_row(
        "Docker image", "tag: %s, id: %s, :calendar: %s" % (img["tag"], img["id"], img["created"])
    )

    # container
    cont_name = config.MAIN_CONTAINER_NAME
    running = docker.DOCKER_CLIENT.is_container_running(cont_name)
    cont_status = "[bold][red]:heavy_multiplication_x: stopped"
    if running:
        cont_status = '[bold][green]:heavy_check_mark: running[/green][/bold] (name: "[italic]%s[/italic]", IP: %s)' % (
            get_main_container_name(),
            get_main_container_ip(),
        )
    grid.add_row("Runtime status", cont_status)

    console.print(grid)


def print_service_table(services: Dict[str, str]):
    from rich.table import Table

    status_display = {
        "running": "[green]:heavy_check_mark:[/green] running",
        "starting": ":hourglass_flowing_sand: starting",
        "available": "[grey]:heavy_check_mark:[/grey] available",
        "error": "[red]:heavy_multiplication_x:[/red] error",
    }

    table = Table()
    table.add_column("Service")
    table.add_column("Status")

    services = [(k, v) for k, v in services.items()]
    services.sort(key=lambda item: item[0])

    for service, status in services:
        if status in status_display:
            status = status_display[status]

        table.add_row(service, status)

    console.print(table)


def print_version():
    console.print(" :laptop_computer: [bold]LocalStack CLI[/bold] [blue]%s[/blue]" % __version__)


def print_banner():
    print(BANNER)
