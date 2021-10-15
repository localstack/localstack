import logging
import os
import time
from pprint import pprint

import click

from localstack.plugin import PluginManager
from localstack.plugin.entrypoint import find_plugins


@click.group()
def cli():
    pass


@cli.command()
@click.option("--where", type=str, default=os.path.abspath(os.curdir))
@click.option("--exclude", multiple=True, default=())
@click.option("--include", multiple=True, default=("*",))
def entrypoints(where, exclude, include):
    logging.basicConfig(level=logging.INFO)
    print(f"path: {where}")

    plugins = find_plugins(where=where, exclude=exclude, include=include)
    pprint(dict(plugins))


@cli.command()
@click.option("--namespace", type=str)
@click.option("--name", type=str)
def load(namespace, name):
    manager = PluginManager(namespace)

    print(manager.list_plugin_specs())

    then = time.time()
    plugin = manager.load(name)
    took = time.time() - then
    print(plugin)
    print(f"loading {namespace}:{name} took {took:.4f}s")


@cli.command()
@click.option("--name", type=str)
def service(name):
    from localstack.services.plugins import ServicePluginManager

    manager = ServicePluginManager()

    then = time.time()
    s = manager.get_service(name)
    print(s, time.time() - then)

    then = time.time()
    s = manager.get_service(name)
    print(s, time.time() - then)

    then = time.time()
    s = manager.get_service("sqs")
    print(s, time.time() - then)


@cli.command()
def cache():
    print("foo")
    from stevedore._cache import _c

    print("loading")
    data = _c._get_data_for_path(None)
    pprint(data.get("groups"))


if __name__ == "__main__":
    cli()
