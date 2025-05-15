#!/usr/bin/env python
import logging
from pathlib import Path

import click
import yaml

from localstack.logging.setup import setup_logging_from_config
from localstack.services.cloudformation.autogen import (
    formatting,
    generation,
    patches,
    permutations,
    specs,
)
from localstack.services.cloudformation.autogen.generation import generate_resources_from_spec

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
def single(resource_name: str, add_optionals: bool, output: click.File) -> None:
    LOG.info("Generating resource definition for '%s'", resource_name)

    spec = specs.read_spec_for(resource_name)
    spec = patches.apply_patch_for(spec)
    resource = generation.generate_resource_from_spec(spec, add_optionals)
    yaml.safe_dump({"Resources": {"MyResource": resource}}, output)

    if output.name != "<stdout>":
        formatting.format_file(output.name)


@main.command()
@click.option("-t", "--resource-type", multiple=True, help="Available resources to choose from")
@click.option(
    "-r",
    "--range",
    "resource_count",
    nargs=2,
    help="Min and max number of resources to generate",
    default=(1, 5),
)
@click.option("-o", "--output", type=click.File("w"), help="Output file to write to", default="-")
def template(resource_type: list[str], resource_count: tuple[int, int], output: click.File):
    resources = generate_resources_from_spec(resource_type, resource_count)
    yaml.safe_dump({"Resources": resources}, output)

    if output.name != "<stdout>":
        formatting.format_file(output.name)


@main.command(name="permutations")
@click.option(
    "-c", "--count", type=int, default=10, help="Number of template permutations to generate"
)
@click.option("-o", "--output", "output_path", type=Path, help="Output file", required=True)
def gen_permutations(output_path: Path, count: int):
    output_path.mkdir(parents=True, exist_ok=True)
    permutations.generate_templates(output_path, count=count)


if __name__ == "__main__":
    main()
