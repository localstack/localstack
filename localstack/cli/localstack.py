import json
import os
import sys
from typing import Dict, Optional, TypedDict

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
@click.option("--profile", type=str, help="Set the configuration profile")
def localstack(debug, profile):
    if profile:
        os.environ["CONFIG_PROFILE"] = profile

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
@click.option("--format", type=click.Choice(["table", "plain", "dict", "json"]), default="table")
def cmd_status_docker(format):
    with console.status("Querying Docker status"):
        print_docker_status(format)


@localstack_status.command(name="services", help="Query information about running services")
@click.option("--format", type=click.Choice(["table", "plain", "dict", "json"]), default="table")
def cmd_status_services(format):
    import requests

    from localstack import config

    url = config.get_edge_url()

    try:
        health = requests.get(f"{url}/health")
        doc = health.json()
        services = doc.get("services", [])
        if format == "table":
            print_service_table(services)
        if format == "plain":
            for service, status in services.items():
                console.print(f"{service}={status}")
        if format == "dict":
            console.print(services)
        if format == "json":
            console.print(json.dumps(services))
    except requests.ConnectionError:
        error = f"could not connect to LocalStack health endpoint at {url}"
        print_error(format, error)
        if config.DEBUG:
            console.print_exception()
        sys.exit(1)


@localstack.command(name="start", help="Start LocalStack")
@click.option("--docker", is_flag=True, help="Start LocalStack in a docker container (default)")
@click.option("--host", is_flag=True, help="Start LocalStack directly on the host")
@click.option("--no-banner", is_flag=True, help="Disable LocalStack banner", default=False)
@click.option(
    "-d", "--detached", is_flag=True, help="Start LocalStack in the background", default=False
)
def cmd_start(docker: bool, host: bool, no_banner: bool, detached: bool):
    if docker and host:
        raise click.ClickException("Please specify either --docker or --host")
    if host and detached:
        raise click.ClickException("Cannot start detached in host mode")

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

    bootstrap.prepare_host()

    if not no_banner and not detached:
        console.rule("LocalStack Runtime Log (press [bold][yellow]CTRL-C[/yellow][/bold] to quit)")

    if host:
        bootstrap.start_infra_locally()
    else:
        if detached:
            bootstrap.start_infra_in_docker_detached(console)
        else:
            bootstrap.start_infra_in_docker()


@localstack.command(name="stop", help="Stop the running LocalStack container")
def cmd_stop():
    from localstack import config
    from localstack.utils.docker_utils import DOCKER_CLIENT

    from ..utils.container_utils.container_client import NoSuchContainer

    container_name = config.MAIN_CONTAINER_NAME

    try:
        DOCKER_CLIENT.stop_container(container_name)
        console.print("container stopped: %s" % container_name)
    except NoSuchContainer:
        console.print("no such container: %s" % container_name)
        sys.exit(1)


@localstack.command(name="logs", help="Show the logs of the LocalStack container")
@click.option(
    "-f",
    "--follow",
    is_flag=True,
    help="Block the terminal and follow the log output",
    default=False,
)
def cmd_logs(follow: bool):
    from localstack import config
    from localstack.utils.bootstrap import LocalstackContainer
    from localstack.utils.common import FileListener
    from localstack.utils.docker_utils import DOCKER_CLIENT

    container_name = config.MAIN_CONTAINER_NAME
    logfile = LocalstackContainer(container_name).logfile

    if not DOCKER_CLIENT.is_container_running(container_name):
        console.print("localstack container not running")
        sys.exit(1)

    if not os.path.exists(logfile):
        console.print("localstack container logfile not found at %s" % logfile)
        sys.exit(1)

    if follow:
        listener = FileListener(logfile, print)
        listener.start()
        try:
            listener.join()
        except KeyboardInterrupt:
            pass
        finally:
            listener.close()
    else:
        with open(logfile) as fd:
            for line in fd:
                print(line.rstrip("\n\r"))


@localstack.command(name="wait", help="Wait on the LocalStack container to start")
@click.option(
    "-t",
    "--timeout",
    type=float,
    help="The amount of time in seconds to wait before raising a timeout error",
    default=None,
)
def cmd_wait(timeout: Optional[float] = None):
    from localstack.utils.bootstrap import wait_container_is_ready

    if not wait_container_is_ready(timeout=timeout):
        raise click.ClickException("timeout")


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


@localstack_config.command(name="show", help="Print the current LocalStack config values")
@click.option("--format", type=click.Choice(["table", "plain", "dict", "json"]), default="table")
def cmd_config_show(format):
    # TODO: parse values from potential docker-compose file?

    from localstack_ext import config as ext_config

    from localstack import config

    assert config
    assert ext_config

    if format == "table":
        print_config_table()
    elif format == "plain":
        print_config_pairs()
    elif format == "dict":
        print_config_dict()
    elif format == "json":
        print_config_json()
    else:
        print_config_pairs()  # fall back to plain


def print_config_json():
    import json

    from localstack import config

    console.print(json.dumps(dict(config.collect_config_items())))


def print_config_pairs():
    from localstack import config

    for key, value in config.collect_config_items():
        console.print(f"{key}={value}")


def print_config_dict():
    from localstack import config

    console.print(dict(config.collect_config_items()))


def print_config_table():
    from rich.table import Table

    from localstack import config

    grid = Table(show_header=True)
    grid.add_column("Key")
    grid.add_column("Value")

    for key, value in config.collect_config_items():
        grid.add_row(key, str(value))

    console.print(grid)


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


class DockerStatus(TypedDict, total=False):
    running: bool
    runtime_version: str
    image_tag: str
    image_id: str
    image_created: str
    container_name: Optional[str]
    container_ip: Optional[str]


def print_docker_status(format):
    from localstack import config
    from localstack.utils import docker_utils
    from localstack.utils.bootstrap import (
        get_docker_image_details,
        get_main_container_ip,
        get_main_container_name,
        get_server_version,
    )

    img = get_docker_image_details()
    cont_name = config.MAIN_CONTAINER_NAME
    running = docker_utils.DOCKER_CLIENT.is_container_running(cont_name)
    status = DockerStatus(
        runtime_version=get_server_version(),
        image_tag=img["tag"],
        image_id=img["id"],
        image_created=img["created"],
        running=running,
    )
    if running:
        status["container_name"] = get_main_container_name()
        status["container_ip"] = get_main_container_ip()

    if format == "dict":
        console.print(status)
    if format == "table":
        print_docker_status_table(status)
    if format == "json":
        console.print(json.dumps(status))
    if format == "plain":
        for key, value in status.items():
            console.print(f"{key}={value}")


def print_docker_status_table(status: DockerStatus):
    from rich.table import Table

    grid = Table(show_header=False)
    grid.add_column()
    grid.add_column()

    grid.add_row("Runtime version", f'[bold]{status["runtime_version"]}[/bold]')
    grid.add_row(
        "Docker image",
        f"tag: {status['image_tag']}, "
        f"id: {status['image_id']}, "
        f":calendar: {status['image_created']}",
    )
    cont_status = "[bold][red]:heavy_multiplication_x: stopped"
    if status["running"]:
        cont_status = (
            f"[bold][green]:heavy_check_mark: running[/green][/bold] "
            f'(name: "[italic]{status["container_name"]}[/italic]", IP: {status["container_ip"]})'
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

    services = list(services.items())
    services.sort(key=lambda item: item[0])

    for service, status in services:
        if status in status_display:
            status = status_display[status]

        table.add_row(service, status)

    console.print(table)


def print_version():
    console.print(" :laptop_computer: [bold]LocalStack CLI[/bold] [blue]%s[/blue]" % __version__)


def print_error(format, error):
    if format == "table":
        symbol = "[bold][red]:heavy_multiplication_x: ERROR[/red][/bold]"
        console.print(f"{symbol}: {error}")
    if format == "plain":
        console.print(f"error={error}")
    if format == "dict":
        console.print({"error": error})
    if format == "json":
        console.print(json.dumps({"error": error}))


def print_banner():
    print(BANNER)
