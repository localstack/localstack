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


#
# @cli.command()
# def generate():
#     from localstack.plugins import do_register_localstack_plugins
#     from localstack.services.plugins import SERVICE_PLUGINS
#     from localstack.utils.common import first_char_to_upper
#
#     do_register_localstack_plugins()
#
#     template = """@aws_provider()
# def {name}():
#     from localstack.services.{name} import {imports}
#
#     return Service({name}, {args})
#
# """
#
#     for name, service in SERVICE_PLUGINS.services.items():
#         # print(name, service.start, service.check, service.listener)
#
#         class_prefix = first_char_to_upper(name)
#
#         imports = []
#         args = []
#
#         if service.listener:
#             imports.append(f"{name}_listener")
#             args.append(f"listener={name}_listener.UPDATE_{name.upper()}")
#
#         if service.start_function:
#             imports.append(f"{name}_starter")
#             args.append(f"start={name}_starter.{service.start_function.__name__}")
#
#         if service.check_function:
#             args.append(f"check={name}_starter.{service.check_function.__name__}")
#
#         d = f"localstack/services/{name}"
#         if not os.path.isdir(d):
#             print(f"# TODO: {name}")
#             continue
#
#         code = template.format(
#             name=name, class_prefix=class_prefix, imports=",".join(imports), args=",".join(args)
#         )
#
#         print(code)


if __name__ == "__main__":
    cli()
