#!/usr/bin/env python
import logging

import click
import yaml

from localstack.logging.setup import setup_logging_from_config
from localstack.services.cloudformation.autogen import formatting, generation, patches, specs

setup_logging_from_config()

LOG = logging.getLogger("localstack.services.cloudformation.autogen.cli")
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"], show_default=True)


@click.group(context_settings=CONTEXT_SETTINGS)
def main():
    pass


@main.command()
@click.option("-r", "--resource", "resource_name", help="Which resource to generate")
@click.option("-O", "--add-optionals", is_flag=True, help="Also generate additional properties")
@click.option("-o", "--output", type=click.File("w"), help="Output file to write to", default="-")
def generate(resource_name: str, add_optionals: bool, output: click.File) -> None:
    LOG.info("Generating resource definition for '%s'", resource_name)

    spec = specs.read_spec_for(resource_name)
    spec = patches.apply_patch_for(spec)
    resource = generation.generate_resource_from_spec(spec, add_optionals)
    yaml.safe_dump({"Resources": {"MyResource": resource}}, output)

    if output.name != "<stdout>":
        formatting.format_file(output.name)


if __name__ == "__main__":
    main()
