import json
import logging
import os
import sys
import traceback
from typing import Dict, List, Optional, Tuple, TypedDict

import click
import requests

from localstack import config
from localstack.cli.exceptions import CLIError
from localstack.constants import VERSION
from localstack.utils.analytics.cli import publish_invocation
from localstack.utils.bootstrap import get_container_default_logfile_location
from localstack.utils.json import CustomEncoder

from .console import BANNER, console
from .plugin import LocalstackCli, load_cli_plugins


class LocalStackCliGroup(click.Group):
    """
    A Click group used for the top-level ``localstack`` command group. It implements global exception handling
    by:

    - Ignoring click exceptions (already handled)
    - Handling common exceptions (like DockerNotAvailable)
    - Wrapping all unexpected exceptions in a ClickException (for a unified error message)

    It also implements a custom help formatter to build more fine-grained groups.
    """

    # FIXME: find a way to communicate this from the actual command
    advanced_commands = [
        "aws",
        "dns",
        "extensions",
        "license",
        "login",
        "logout",
        "pod",
        "state",
        "ephemeral",
        "replicator",
    ]

    def invoke(self, ctx: click.Context):
        try:
            return super(LocalStackCliGroup, self).invoke(ctx)
        except click.exceptions.Exit:
            # raise Exit exceptions unmodified (e.g., raised on --help)
            raise
        except click.ClickException:
            # don't handle ClickExceptions, just reraise
            if ctx and ctx.params.get("debug"):
                click.echo(traceback.format_exc())
            raise
        except Exception as e:
            if ctx and ctx.params.get("debug"):
                click.echo(traceback.format_exc())
            from localstack.utils.container_utils.container_client import (
                ContainerException,
                DockerNotAvailable,
            )

            if isinstance(e, DockerNotAvailable):
                raise CLIError(
                    "Docker could not be found on the system.\n"
                    "Please make sure that you have a working docker environment on your machine."
                )
            elif isinstance(e, ContainerException):
                raise CLIError(e.message)
            else:
                # If we have a generic exception, we wrap it in a ClickException
                raise CLIError(str(e)) from e

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """Extra format methods for multi methods that adds all the commands after the options. It also
        groups commands into command categories."""
        categories = {"Commands": [], "Advanced": [], "Deprecated": []}

        commands = []
        for subcommand in self.list_commands(ctx):
            cmd = self.get_command(ctx, subcommand)
            # What is this, the tool lied about a command.  Ignore it
            if cmd is None:
                continue
            if cmd.hidden:
                continue

            commands.append((subcommand, cmd))

        # allow for 3 times the default spacing
        if len(commands):
            limit = formatter.width - 6 - max(len(cmd[0]) for cmd in commands)

            for subcommand, cmd in commands:
                help = cmd.get_short_help_str(limit)
                categories[self._get_category(cmd)].append((subcommand, help))

        for category, rows in categories.items():
            if rows:
                with formatter.section(category):
                    formatter.write_dl(rows)

    def _get_category(self, cmd) -> str:
        if cmd.deprecated:
            return "Deprecated"

        if cmd.name in self.advanced_commands:
            return "Advanced"

        return "Commands"


def create_with_plugins() -> LocalstackCli:
    """
    Creates a LocalstackCli instance with all cli plugins loaded.
    :return: a LocalstackCli instance
    """
    cli = LocalstackCli()
    cli.group = localstack
    load_cli_plugins(cli)
    return cli


def _setup_cli_debug() -> None:
    from localstack.logging.setup import setup_logging_for_cli

    config.DEBUG = True
    os.environ["DEBUG"] = "1"

    setup_logging_for_cli(logging.DEBUG if config.DEBUG else logging.INFO)


# Re-usable format option decorator which can be used across multiple commands
_click_format_option = click.option(
    "-f",
    "--format",
    "format_",
    type=click.Choice(["table", "plain", "dict", "json"]),
    default="table",
    help="The formatting style for the command output.",
)


@click.group(
    name="localstack",
    help="The LocalStack Command Line Interface (CLI)",
    cls=LocalStackCliGroup,
    context_settings={
        # add "-h" as a synonym for "--help"
        # https://click.palletsprojects.com/en/8.1.x/documentation/#help-parameter-customization
        "help_option_names": ["-h", "--help"],
        # show default values for options by default - https://github.com/pallets/click/pull/1225
        "show_default": True,
    },
)
@click.version_option(
    VERSION,
    "--version",
    "-v",
    message="LocalStack CLI %(version)s",
    help="Show the version of the LocalStack CLI and exit",
)
@click.option("-d", "--debug", is_flag=True, help="Enable CLI debugging mode")
@click.option("-p", "--profile", type=str, help="Set the configuration profile")
def localstack(debug, profile) -> None:
    # --profile is read manually in localstack.cli.main because it needs to be read before localstack.config is read

    if debug:
        _setup_cli_debug()

    from localstack.utils.files import cache_dir

    # overwrite the config variable here to defer import of cache_dir
    if not os.environ.get("LOCALSTACK_VOLUME_DIR", "").strip():
        config.VOLUME_DIR = str(cache_dir() / "volume")

    # FIXME: at some point we should remove the use of `config.dirs` for the CLI,
    #  see https://github.com/localstack/localstack/pull/7906
    config.dirs.for_cli().mkdirs()


@localstack.group(
    name="config",
    short_help="Manage your LocalStack config",
)
def localstack_config() -> None:
    """
    Inspect and validate your LocalStack configuration.
    """
    pass


@localstack_config.command(name="show", short_help="Show your config")
@_click_format_option
@publish_invocation
def cmd_config_show(format_: str) -> None:
    """
    Print the current LocalStack config values.

    This command prints the LocalStack configuration values from your environment.
    It analyzes the environment variables as well as the LocalStack CLI profile.
    It does _not_ analyze a specific file (like a docker-compose-yml).
    """
    # TODO: parse values from potential docker-compose file?
    assert config

    try:
        # only load the ext config if it's available
        from localstack.pro.core import config as ext_config

        assert ext_config
    except ImportError:
        # the ext package is not available
        return None

    if format_ == "table":
        _print_config_table()
    elif format_ == "plain":
        _print_config_pairs()
    elif format_ == "dict":
        _print_config_dict()
    elif format_ == "json":
        _print_config_json()
    else:
        _print_config_pairs()  # fall back to plain


@localstack_config.command(name="validate", short_help="Validate your config")
@click.option(
    "-f",
    "--file",
    help="Path to compose file",
    default="docker-compose.yml",
    type=click.Path(exists=True, file_okay=True, readable=True),
)
@publish_invocation
def cmd_config_validate(file: str) -> None:
    """
    Validate your LocalStack configuration (docker compose).

    This command inspects the given docker-compose file (by default docker-compose.yml in the current working
    directory) and validates if the configuration is valid.

    \b
    It will show an error and return a non-zero exit code if:
    - The docker-compose file is syntactically incorrect.
    - If the file contains common issues when configuring LocalStack.
    """

    from localstack.utils import bootstrap

    if bootstrap.validate_localstack_config(file):
        console.print("[green]:heavy_check_mark:[/green] config valid")
        sys.exit(0)
    else:
        console.print("[red]:heavy_multiplication_x:[/red] validation error")
        sys.exit(1)


def _print_config_json() -> None:
    import json

    console.print(json.dumps(dict(config.collect_config_items()), cls=CustomEncoder))


def _print_config_pairs() -> None:
    for key, value in config.collect_config_items():
        console.print(f"{key}={value}")


def _print_config_dict() -> None:
    console.print(dict(config.collect_config_items()))


def _print_config_table() -> None:
    from rich.table import Table

    grid = Table(show_header=True)
    grid.add_column("Key")
    grid.add_column("Value")

    for key, value in config.collect_config_items():
        grid.add_row(key, str(value))

    console.print(grid)


@localstack.group(
    name="status",
    short_help="Query status info",
    invoke_without_command=True,
)
@click.pass_context
def localstack_status(ctx: click.Context) -> None:
    """
    Query status information about the currently running LocalStack instance.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(localstack_status.get_command(ctx, "docker"))


@localstack_status.command(name="docker", short_help="Query LocalStack Docker status")
@_click_format_option
def cmd_status_docker(format_: str) -> None:
    """
    Query information about the currently running LocalStack Docker image, its container,
    and the LocalStack runtime.
    """
    with console.status("Querying Docker status"):
        _print_docker_status(format_)


class DockerStatus(TypedDict, total=False):
    running: bool
    runtime_version: str
    image_tag: str
    image_id: str
    image_created: str
    container_name: Optional[str]
    container_ip: Optional[str]


def _print_docker_status(format_: str) -> None:
    from localstack.utils import docker_utils
    from localstack.utils.bootstrap import get_docker_image_details, get_server_version
    from localstack.utils.container_networking import get_main_container_ip, get_main_container_name

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

    if format_ == "dict":
        console.print(status)
    if format_ == "table":
        _print_docker_status_table(status)
    if format_ == "json":
        console.print(json.dumps(status))
    if format_ == "plain":
        for key, value in status.items():
            console.print(f"{key}={value}")


def _print_docker_status_table(status: DockerStatus) -> None:
    from rich.table import Table

    grid = Table(show_header=False)
    grid.add_column()
    grid.add_column()

    grid.add_row("Runtime version", f"[bold]{status['runtime_version']}[/bold]")
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


@localstack_status.command(name="services", short_help="Query LocalStack services status")
@_click_format_option
def cmd_status_services(format_: str) -> None:
    """
    Query information about the services of the currently running LocalStack instance.
    """
    url = config.external_service_url()

    try:
        health = requests.get(f"{url}/_localstack/health", timeout=2)
        doc = health.json()
        services = doc.get("services", [])
        if format_ == "table":
            _print_service_table(services)
        if format_ == "plain":
            for service, status in services.items():
                console.print(f"{service}={status}")
        if format_ == "dict":
            console.print(services)
        if format_ == "json":
            console.print(json.dumps(services))
    except requests.ConnectionError:
        if config.DEBUG:
            console.print_exception()
        raise CLIError(f"could not connect to LocalStack health endpoint at {url}")


def _print_service_table(services: Dict[str, str]) -> None:
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


@localstack.command(name="start", short_help="Start LocalStack")
@click.option("--docker", is_flag=True, help="Start LocalStack in a docker container [default]")
@click.option("--host", is_flag=True, help="Start LocalStack directly on the host")
@click.option("--no-banner", is_flag=True, help="Disable LocalStack banner", default=False)
@click.option(
    "-d", "--detached", is_flag=True, help="Start LocalStack in the background", default=False
)
@click.option(
    "--network",
    type=str,
    help="The container network the LocalStack container should be started in. By default, the default docker bridge network is used.",
    required=False,
)
@click.option(
    "--env",
    "-e",
    help="Additional environment variables that are passed to the LocalStack container",
    multiple=True,
    required=False,
)
@click.option(
    "--publish",
    "-p",
    help="Additional port mappings that are passed to the LocalStack container",
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
    "--host-dns",
    help="Expose the LocalStack DNS server to the host using port bindings.",
    required=False,
    is_flag=True,
    default=False,
)
@publish_invocation
def cmd_start(
    docker: bool,
    host: bool,
    no_banner: bool,
    detached: bool,
    network: str = None,
    env: Tuple = (),
    publish: Tuple = (),
    volume: Tuple = (),
    host_dns: bool = False,
) -> None:
    """
    Start the LocalStack runtime.

    This command starts the LocalStack runtime with your current configuration.
    By default, it will start a new Docker container from the latest LocalStack(-Pro) Docker image
    with best-practice volume mounts and port mappings.
    """
    if docker and host:
        raise CLIError("Please specify either --docker or --host")
    if host and detached:
        raise CLIError("Cannot start detached in host mode")

    if not no_banner:
        print_banner()
        print_version()
        print_profile()
        print_app()
        console.line()

    from localstack.utils import bootstrap

    if not no_banner:
        if host:
            console.log("starting LocalStack in host mode :laptop_computer:")
        else:
            console.log("starting LocalStack in Docker mode :whale:")

    if host:
        # call hooks to prepare host
        bootstrap.prepare_host(console)

        # from here we abandon the regular CLI control path and start treating the process like a localstack
        # runtime process
        os.environ["LOCALSTACK_CLI"] = "0"
        config.dirs = config.init_directories()

        try:
            bootstrap.start_infra_locally()
        except ImportError:
            if config.DEBUG:
                console.print_exception()
            raise CLIError(
                "It appears you have a light install of localstack which only supports running in docker.\n"
                "If you would like to use --host, please install localstack with Python using "
                "`pip install localstack[runtime]` instead."
            )
    else:
        # make sure to initialize the bootstrap environment and directories for the host (even if we're executing
        # in Docker), to allow starting the container from within other containers (e.g., Github Codespaces).
        config.OVERRIDE_IN_DOCKER = False
        config.is_in_docker = False
        config.dirs = config.init_directories()

        # call hooks to prepare host (note that this call should stay below the config overrides above)
        bootstrap.prepare_host(console)

        # pass the parsed cli params to the start infra command
        params = click.get_current_context().params

        if network:
            # reconciles the network config and makes sure that MAIN_DOCKER_NETWORK is set automatically if
            # `--network` is set.
            if config.MAIN_DOCKER_NETWORK:
                if config.MAIN_DOCKER_NETWORK != network:
                    raise CLIError(
                        f"Values of MAIN_DOCKER_NETWORK={config.MAIN_DOCKER_NETWORK} and --network={network} "
                        f"do not match"
                    )
            else:
                config.MAIN_DOCKER_NETWORK = network
                os.environ["MAIN_DOCKER_NETWORK"] = network

        if detached:
            bootstrap.start_infra_in_docker_detached(console, params)
        else:
            bootstrap.start_infra_in_docker(console, params)


@localstack.command(name="stop", short_help="Stop LocalStack")
@publish_invocation
def cmd_stop() -> None:
    """
    Stops the current LocalStack runtime.

    This command stops the currently running LocalStack docker container.
    By default, this command looks for a container named `localstack-main` (which is the default
    container name used by the `localstack start` command).
    If your LocalStack container has a different name, set the config variable
    `MAIN_CONTAINER_NAME`.
    """
    from localstack.utils.docker_utils import DOCKER_CLIENT

    from ..utils.container_utils.container_client import NoSuchContainer

    container_name = config.MAIN_CONTAINER_NAME

    try:
        DOCKER_CLIENT.stop_container(container_name)
        console.print("container stopped: %s" % container_name)
    except NoSuchContainer:
        raise CLIError(
            f'Expected a running LocalStack container named "{container_name}", but found none'
        )


@localstack.command(name="restart", short_help="Restart LocalStack")
@publish_invocation
def cmd_restart() -> None:
    """
    Restarts the current LocalStack runtime.
    """
    url = config.external_service_url()

    try:
        response = requests.post(
            f"{url}/_localstack/health",
            json={"action": "restart"},
        )
        response.raise_for_status()
        console.print("LocalStack restarted within the container.")
    except requests.ConnectionError:
        if config.DEBUG:
            console.print_exception()
        raise CLIError("could not restart the LocalStack container")


@localstack.command(
    name="logs",
    short_help="Show LocalStack logs",
)
@click.option(
    "-f",
    "--follow",
    is_flag=True,
    help="Block the terminal and follow the log output",
    default=False,
)
@click.option(
    "-n",
    "--tail",
    type=int,
    help="Print only the last <N> lines of the log output",
    default=None,
    metavar="N",
)
@publish_invocation
def cmd_logs(follow: bool, tail: int) -> None:
    """
    Show the logs of the current LocalStack runtime.

    This command shows the logs of the currently running LocalStack docker container.
    By default, this command looks for a container named `localstack-main` (which is the default
    container name used by the `localstack start` command).
    If your LocalStack container has a different name, set the config variable
    `MAIN_CONTAINER_NAME`.
    """
    from localstack.utils.docker_utils import DOCKER_CLIENT

    container_name = config.MAIN_CONTAINER_NAME
    logfile = get_container_default_logfile_location(container_name)

    if not DOCKER_CLIENT.is_container_running(container_name):
        console.print("localstack container not running")
        if os.path.exists(logfile):
            console.print("printing logs from previous run")
            with open(logfile) as fd:
                for line in fd:
                    click.echo(line, nl=False)
        sys.exit(1)

    if follow:
        num_lines = 0
        for line in DOCKER_CLIENT.stream_container_logs(container_name):
            print(line.decode("utf-8").rstrip("\r\n"))
            num_lines += 1
            if tail is not None and num_lines >= tail:
                break

    else:
        logs = DOCKER_CLIENT.get_container_logs(container_name)
        if tail is not None:
            logs = "\n".join(logs.split("\n")[-tail:])
        print(logs)


@localstack.command(name="wait", short_help="Wait for LocalStack")
@click.option(
    "-t",
    "--timeout",
    type=float,
    help="Only wait for <N> seconds before raising a timeout error",
    default=None,
    metavar="N",
)
@publish_invocation
def cmd_wait(timeout: Optional[float] = None) -> None:
    """
    Wait for the LocalStack runtime to be up and running.

    This commands waits for a started LocalStack runtime to be up and running, ready to serve
    requests.
    By default, this command looks for a container named `localstack-main` (which is the default
    container name used by the `localstack start` command).
    If your LocalStack container has a different name, set the config variable
    `MAIN_CONTAINER_NAME`.
    """
    from localstack.utils.bootstrap import wait_container_is_ready

    if not wait_container_is_ready(timeout=timeout):
        raise CLIError("timeout")


@localstack.command(name="ssh", short_help="Obtain a shell in LocalStack")
@publish_invocation
def cmd_ssh() -> None:
    """
    Obtain a shell in the current LocalStack runtime.

    This command starts a new interactive shell in the currently running LocalStack container.
    By default, this command looks for a container named `localstack-main` (which is the default
    container name used by the `localstack start` command).
    If your LocalStack container has a different name, set the config variable
    `MAIN_CONTAINER_NAME`.
    """
    from localstack.utils.docker_utils import DOCKER_CLIENT

    if not DOCKER_CLIENT.is_container_running(config.MAIN_CONTAINER_NAME):
        raise CLIError(
            f'Expected a running LocalStack container named "{config.MAIN_CONTAINER_NAME}", but found none'
        )
    os.execlp("docker", "docker", "exec", "-it", config.MAIN_CONTAINER_NAME, "bash")


@localstack.group(name="update", short_help="Update LocalStack")
def localstack_update() -> None:
    """
    Update different LocalStack components.
    """
    pass


@localstack_update.command(name="all", short_help="Update all LocalStack components")
@click.pass_context
@publish_invocation
def cmd_update_all(ctx: click.Context) -> None:
    """
    Update all LocalStack components.

    This is the same as executing `localstack update localstack-cli` and
    `localstack update docker-images`.
    Updating the LocalStack CLI is currently only supported if the CLI
    is installed and run via Python / PIP. If you used a different installation method,
    please follow the instructions on https://docs.localstack.cloud/.
    """
    ctx.invoke(localstack_update.get_command(ctx, "localstack-cli"))
    ctx.invoke(localstack_update.get_command(ctx, "docker-images"))


@localstack_update.command(name="localstack-cli", short_help="Update LocalStack CLI")
@publish_invocation
def cmd_update_localstack_cli() -> None:
    """
    Update the LocalStack CLI.

    This command updates the LocalStack CLI. This is currently only supported if the CLI
    is installed and run via Python / PIP. If you used a different installation method,
    please follow the instructions on https://docs.localstack.cloud/.
    """
    if is_frozen_bundle():
        # "update" can only be performed if running from source / in a non-frozen interpreter
        raise CLIError(
            "The LocalStack CLI can only update itself if installed via PIP. "
            "Please follow the instructions on https://docs.localstack.cloud/ to update your CLI."
        )

    import subprocess
    from subprocess import CalledProcessError

    console.rule("Updating LocalStack CLI")
    with console.status("Updating LocalStack CLI..."):
        try:
            subprocess.check_output(
                [sys.executable, "-m", "pip", "install", "--upgrade", "localstack"]
            )
            console.print(":heavy_check_mark: LocalStack CLI updated")
        except CalledProcessError:
            console.print(":heavy_multiplication_x: LocalStack CLI update failed", style="bold red")


@localstack_update.command(
    name="docker-images", short_help="Update docker images LocalStack depends on"
)
@publish_invocation
def cmd_update_docker_images() -> None:
    """
    Update all Docker images LocalStack depends on.

    This command updates all Docker LocalStack docker images, as well as other Docker images
    LocalStack depends on (and which have been used before / are present on the machine).
    """
    from localstack.utils.docker_utils import DOCKER_CLIENT

    console.rule("Updating docker images")

    all_images = DOCKER_CLIENT.get_docker_image_names(strip_latest=False)
    image_prefixes = [
        "localstack/",
        "public.ecr.aws/lambda",
    ]
    localstack_images = [
        image
        for image in all_images
        if any(
            image.startswith(image_prefix) or image.startswith(f"docker.io/{image_prefix}")
            for image_prefix in image_prefixes
        )
        and not image.endswith(":<none>")  # ignore dangling images
    ]
    update_images(localstack_images)


def update_images(image_list: List[str]) -> None:
    from rich.markup import escape
    from rich.progress import MofNCompleteColumn, Progress

    from localstack.utils.container_utils.container_client import ContainerException
    from localstack.utils.docker_utils import DOCKER_CLIENT

    updated_count = 0
    failed_count = 0
    progress = Progress(
        *Progress.get_default_columns(), MofNCompleteColumn(), transient=True, console=console
    )
    with progress:
        for image in progress.track(image_list, description="Processing image..."):
            try:
                updated = False
                hash_before_pull = DOCKER_CLIENT.inspect_image(image_name=image, pull=False)["Id"]
                DOCKER_CLIENT.pull_image(image)
                if (
                    hash_before_pull
                    != DOCKER_CLIENT.inspect_image(image_name=image, pull=False)["Id"]
                ):
                    updated = True
                    updated_count += 1
                console.print(
                    f":heavy_check_mark: Image {escape(image)} {'updated' if updated else 'up-to-date'}.",
                    style="bold" if updated else None,
                    highlight=False,
                )
            except ContainerException as e:
                console.print(
                    f":heavy_multiplication_x: Image {escape(image)} pull failed: {e.message}",
                    style="bold red",
                    highlight=False,
                )
                failed_count += 1
    console.rule()
    console.print(
        f"Images updated: {updated_count}, Images failed: {failed_count}, total images processed: {len(image_list)}."
    )


@localstack.command(name="completion", short_help="CLI shell completion")
@click.pass_context
@click.argument(
    "shell", required=True, type=click.Choice(["bash", "zsh", "fish"], case_sensitive=False)
)
@publish_invocation
def localstack_completion(ctx: click.Context, shell: str) -> None:
    """
     Print shell completion code for the specified shell (bash, zsh, or fish).
     The shell code must be evaluated to enable the interactive shell completion of LocalStack CLI commands.
     This is usually done by sourcing it from the .bash_profile.

     \b
     Examples:
       # Bash
       ## Bash completion on Linux depends on the 'bash-completion' package.
       ## Write the LocalStack CLI completion code for bash to a file and source it from .bash_profile
       localstack completion bash > ~/.localstack/completion.bash.inc
       printf "
       # LocalStack CLI bash completion
       source '$HOME/.localstack/completion.bash.inc'
       " >> $HOME/.bash_profile
       source $HOME/.bash_profile
    \b
       # zsh
       ## Set the LocalStack completion code for zsh to autoload on startup:
       localstack completion zsh > "${fpath[1]}/_localstack"
    \b
       # fish
       ## Set the LocalStack completion code for fish to autoload on startup:
       localstack completion fish > ~/.config/fish/completions/localstack.fish
    """

    # lookup the completion, raise an error if the given completion is not found
    import click.shell_completion

    comp_cls = click.shell_completion.get_completion_class(shell)
    if comp_cls is None:
        raise CLIError("Completion for given shell could not be found.")

    # Click's program name is the base path of sys.argv[0]
    path = sys.argv[0]
    prog_name = os.path.basename(path)

    # create the completion variable according to the docs
    # https://click.palletsprojects.com/en/8.1.x/shell-completion/#enabling-completion
    complete_var = f"_{prog_name}_COMPLETE".replace("-", "_").upper()

    # instantiate the completion class and print the completion source
    comp = comp_cls(ctx.command, {}, prog_name, complete_var)
    click.echo(comp.source())


def print_version() -> None:
    console.print(f"- [bold]LocalStack CLI:[/bold] [blue]{VERSION}[/blue]")


def print_profile() -> None:
    if config.LOADED_PROFILES:
        console.print(f"- [bold]Profile:[/bold] [blue]{', '.join(config.LOADED_PROFILES)}[/blue]")


def print_app() -> None:
    console.print("- [bold]App:[/bold] https://app.localstack.cloud")


def print_banner() -> None:
    print(BANNER)


def is_frozen_bundle() -> bool:
    """
    :return: true if we are currently running in a frozen bundle / a pyinstaller binary.
    """
    # check if we are in a PyInstaller binary
    # https://pyinstaller.org/en/stable/runtime-information.html
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")
