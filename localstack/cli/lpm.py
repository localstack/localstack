from typing import List, Optional

import click
from click import ClickException
from plugin import PluginManager
from rich.console import Console

from localstack import config
from localstack.packages import InstallTarget, Package
from localstack.packages.api import PLUGIN_NAMESPACE, PackagesPlugin
from localstack.utils.bootstrap import setup_logging

console = Console()


@click.group()
def cli():
    """
    The LocalStack Package Manager (lpm) CLI is a set of commands to install third-party packages used by localstack
    service providers.

    Here are some handy commands:

    List all packages

        python -m localstack.cli.lpm list

    Install DynamoDB Local:

        python -m localstack.cli.install dynamodb-local

    Install all community packages, four in parallel:

        python -m localstack.cli.lpm list | grep "/community" | cut -d'/' -f1 | xargs python -m localstack.cli.lpm install --parallel 4
    """
    setup_logging()


def _do_install_package(package: Package, version: str = None, target: InstallTarget = None):
    console.print(f"installing... [bold]{package}[/bold]")
    try:
        package.install(version=version, target=target)
        console.print(f"[green]installed[/green] [bold]{package}[/bold]")
    except Exception as e:
        console.print(f"[red]error[/red] installing {package}: {e}")
        raise e


@cli.command()
@click.argument("package", nargs=-1, required=True)
@click.option(
    "--parallel",
    type=int,
    default=1,
    required=False,
    help="how many installers to run in parallel processes",
)
@click.option(
    "--version",
    type=str,
    default=None,
    required=False,
    help="version to install of a package",
)
@click.option(
    "--target",
    type=click.Choice([target.name.lower() for target in InstallTarget]),
    default=None,
    required=False,
    help="target of the installation",
)
def install(
    package: List[str],
    parallel: Optional[int] = 1,
    version: Optional[str] = None,
    target: Optional[str] = None,
):
    """
    Install one or more packages.
    """
    console.print(f"resolving packages: {package}")

    plugin_manager: PluginManager[PackagesPlugin] = PluginManager(namespace=PLUGIN_NAMESPACE)
    plugin_specs = {
        plugin_spec.name: plugin_spec for plugin_spec in plugin_manager.list_plugin_specs()
    }
    config.dirs.mkdirs()
    package_instances: List[Package] = []
    for pkg in package:
        if pkg not in plugin_specs:
            raise ClickException(f"unable to locate installer for package {pkg}")
        package_instances.append(plugin_manager.load(pkg).get_package())

    if parallel > 1:
        console.print(f"install {parallel} packages in parallel:")

    # collect installers and install in parallel:
    try:
        if target:
            target = InstallTarget[str.upper(target)]
        for package_instance in package_instances:
            _do_install_package(package_instance, version, target)
    except Exception:
        raise ClickException("one or more package installations failed.")


@cli.command(name="list")
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    required=False,
    help="Verbose output (show additional info on packages)",
)
def list_packages(verbose: bool):
    """List available packages of all repositories"""
    plugin_manager: PluginManager[PackagesPlugin] = PluginManager(namespace=PLUGIN_NAMESPACE)
    plugins = plugin_manager.load_all()
    packages = sorted([(plugin.name, plugin.scope, plugin.get_package()) for plugin in plugins])
    for package_name, package_scope, package_instance in packages:
        console.print(f"[green]{package_name}[/green]/{package_scope}")
        if verbose:
            for version in package_instance.get_versions():
                if version == package_instance.default_version:
                    console.print(f"    -  [bold]{version} (default)[/bold]", highlight=False)
                else:
                    console.print(f"    -  {version}", highlight=False)


if __name__ == "__main__":
    cli()
