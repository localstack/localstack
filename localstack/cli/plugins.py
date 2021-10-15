import os
import time

import click
from rich import print as rprint
from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from localstack.plugin import PluginManager
from localstack.plugin.entrypoint import find_plugins, spec_to_entry_point

console = Console()


@click.group()
def cli():
    """
    The plugins CLI is a set of commands to help troubleshoot LocalStack's plugin mechanism.
    """
    pass


@cli.command()
@click.option("--where", type=str, default=os.path.abspath(os.curdir))
@click.option("--exclude", multiple=True, default=())
@click.option("--include", multiple=True, default=("*",))
def find(where, exclude, include):
    """
    Find plugins by scanning the given path for PluginSpecs.
    It starts from the current directory if --where is not specified.
    This is what a setup.py method would run as a build step, i.e., discovering entry points.
    """
    with console.status(f"Scanning path {where}"):
        plugins = find_plugins(where, exclude, include)

    tree = Tree("Entrypoints")
    for namespace, entry_points in plugins.items():
        node = tree.add(f"[bold]{namespace}")

        t = Table()
        t.add_column("Name")
        t.add_column("Location")

        for ep in entry_points:
            key, value = ep.split("=")
            t.add_row(key, value)

        node.add(t)

    rprint(tree)


@cli.command("list")
@click.option("--namespace", type=str, required=True)
def cmd_list(namespace):
    """
    List all available plugins using a PluginManager from available endpoints.
    """
    manager = PluginManager(namespace)

    t = Table()
    t.add_column("Name")
    t.add_column("Factory")

    for spec in manager.list_plugin_specs():
        ep = spec_to_entry_point(spec)
        t.add_row(spec.name, ep.value)

    rprint(t)


@cli.command()
@click.option("--namespace", type=str, required=True)
@click.option("--name", type=str, required=True)
def load(namespace, name):
    """
    Attempts to load a plugin using a PluginManager.
    """
    manager = PluginManager(namespace)

    with console.status(f"Loading {namespace}:{name}"):
        then = time.time()
        plugin = manager.load(name)
        took = time.time() - then

    rprint(
        f":tada: successfully loaded [bold][green]{namespace}[/green][/bold]:[bold][cyan]{name}[/cyan][/bold] ({type(plugin)}"
    )
    rprint(f":stopwatch:  loading took {took:.4f} s")


@cli.command()
@click.option("--namespace", type=str)
def cache(namespace):
    """
    Outputs the stevedore entrypoints cache from which plugins are loaded.
    """
    from stevedore._cache import _c

    data = _c._get_data_for_path(None)

    tree = Tree("Entrypoints")
    for group, entry_points in data.get("groups").items():
        if namespace and group != namespace:
            continue
        node = tree.add(f"[bold]{group}")

        t = Table()
        t.add_column("Name")
        t.add_column("Value")

        for key, value, _ in entry_points:
            t.add_row(key, value)

        node.add(t)

        if namespace:
            rprint(t)
            return

    rprint(tree)


if __name__ == "__main__":
    cli()
