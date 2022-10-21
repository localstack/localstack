from collections import defaultdict
from multiprocessing.pool import Pool
from typing import Dict, List

import click
from click import ClickException
from rich.console import Console

from localstack import config
from localstack.packages import InstallTarget, Package
from localstack.packages.api import PackagesPluginManager
from localstack.services.install import InstallerManager
from localstack.services.plugins import SERVICE_PLUGINS
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


def _do_install(pkg, version=None, target=None):
    console.print(f"installing... [bold]{pkg}[/bold]")
    try:
        package_installer = InstallerManager().get_installers()[pkg]
        package_installer.install(version=version, target=target)
        console.print(f"[green]installed[/green] [bold]{pkg}[/bold]")
    except Exception as e:
        console.print(f"[red]error[/red] installing {pkg}: {e}")
        raise e


def _do_install_package(package: Package, version=None, target=None):
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
def install(package, parallel, version=None, target=None):
    """
    Install one or more packages.
    """
    console.print(f"resolving packages: {package}")
    installers: Dict[str, Package] = InstallerManager().get_installers()
    config.dirs.mkdirs()

    for pkg in package:
        if pkg not in installers:
            raise ClickException(f"unable to locate installer for package {pkg}")

    if parallel > 1:
        console.print(f"install {parallel} packages in parallel:")

    # collect installers and install in parallel:
    try:
        if version or target:
            if target:
                target = InstallTarget[str.upper(target)]
            for pkg in package:
                _do_install(pkg, version, target)
        else:
            with Pool(processes=parallel) as pool:
                pool.map(_do_install, package)
    except Exception:
        raise ClickException("one or more package installations failed.")


def _get_available_packages() -> Dict[str, Dict[str, List[Package]]]:
    # get all AWS provider specs

    aws_provider_specs = dict(sorted(SERVICE_PLUGINS.api_provider_specs.items()))

    # get all package plugin specs
    packages_plugin_manager = PackagesPluginManager()
    package_plugin_specs = packages_plugin_manager.package_plugin_specs

    package_plugins = packages_plugin_manager.get_packages()
    available_packages = defaultdict(dict)
    for api, names in aws_provider_specs.items():
        for name in sorted(names):
            # check if the plugin is available
            if api not in package_plugin_specs or name not in package_plugin_specs[api]:
                continue
            if api in package_plugins and name in package_plugins[api]:
                available_packages[api][name] = package_plugins[api][name]
    return available_packages


def list_service_packages():
    available_packages = _get_available_packages()
    for api, name_packages in available_packages.items():
        console.print(f"[green]{api}[/green]:")
        for name, packages in name_packages.items():
            for package in packages:
                scope = "community" if name == "default" else name
                console.print(f"  - {package.name} ({scope})", highlight=False)
                for version in package.get_versions():
                    if version == package.default_version:
                        console.print(f"    -  [bold]{version} (default)[/bold]", highlight=False)
                    else:
                        console.print(f"    -  {version}", highlight=False)


@click.argument("services", nargs=-1, required=True)
@click.option(
    "--parallel",
    type=int,
    default=1,
    required=False,
    help="how many installers to run in parallel processes",
)
@click.option(
    "--target",
    type=click.Choice([target.name.lower() for target in InstallTarget]),
    default=None,
    required=False,
    help="target of the installation",
)
def install_service_packages(services: List[str], parallel: int, target: str):
    pass
    """
    available_packages = _get_available_packages()
    service_provider_config = ServiceProviderConfig("pro")
    service_provider_config.load_from_environment()
    aws_provider_specs = dict(sorted(SERVICE_PLUGINS.api_provider_specs.items()))
    packages_plugin_manager = PackagesPluginManager()
    package_plugin_specs = packages_plugin_manager.package_plugin_specs
    package_plugins = packages_plugin_manager.get_packages()
    for api, names in aws_provider_specs.items():
        for name in sorted(names):
            # check if the plugin is available
            if api not in package_plugin_specs or name not in package_plugin_specs[api]:
                continue
            if api in package_plugins and name in package_plugins[api]:
                service_provider_config.set_provider_if_not_exists()
    service_provider_config = config.SERVICE_PROVIDER_CONFIG
    service_provider_config.
    packages = []
    for service in services:
        packages += available_packages.get(service, [])

    if not packages:
        console.print(f"[red]error[/red] installing packages for {services}: No packages found.")
        return

    if target:
        target = InstallTarget[str.upper(target)]

    if parallel > 1:
        console.print(f"install {parallel} packages in parallel:")

    with Pool(processes=parallel) as pool:
        pool.starmap(
            _do_install_package, zip(packages, itertools.repeat(None), itertools.repeat(target))
        )
    """


if not config.LEGACY_LPM_INSTALLERS:
    # TODO remove the feature flag and enable this by default with the next minor version
    # Enables new features for LPM
    cli.command(name="list-service-packages", help="Lists packages used by services.")(
        list_service_packages
    )
    cli.command(name="install-service-packages", help="Installs all packages for a service.")(
        install_service_packages
    )

    click.option(
        "--version",
        type=str,
        default=None,
        required=False,
        help="version to install of a package",
    )(install)
    click.option(
        "--target",
        type=click.Choice([target.name.lower() for target in InstallTarget]),
        default=None,
        required=False,
        help="target of the installation",
    )(install)


@cli.command(name="list")
def list_packages():
    """List available packages of all repositories"""
    # TODO migrate to new package based installers instead of using the repositories
    installers = InstallerManager()

    for repo in installers.repositories.load_all():
        for package, _ in repo.get_installer():
            console.print(f"[green]{package}[/green]/{repo.name}")


if __name__ == "__main__":
    cli()
