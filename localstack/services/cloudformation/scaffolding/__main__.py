from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import click
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.syntax import Syntax


@dataclass
class ResourceName:
    fullname: str
    service: str
    resource: str

    def provider_name(self) -> str:
        return f"{self.service}{self.resource}"

    def schema_filename(self) -> str:
        return f"aws-{self.service.lower()}-{self.resource.lower()}.json"

    @classmethod
    def from_name(cls, name: str) -> ResourceName:
        parts = name.split("::")
        if len(parts) != 3 or parts[0] != "AWS":
            raise ValueError(f"Invalid CloudFormation resource name {name}")

        return ResourceName(
            fullname=name,
            service=parts[1].strip(),
            resource=parts[2].strip(),
        )


def run_black(text: str) -> str:
    """Black does not have an API, so spawn a subprocess"""
    # TODO
    return text


def get_formatted_template_output(
    env: Environment, template_name: str, *render_args, **render_kwargs
) -> str:
    template = env.get_template(template_name)
    raw_text = template.render(*render_args, **render_kwargs)
    return run_black(raw_text)


class SchemaProvider:
    def __init__(self, zipfile_path: Path):
        self.schemas = {}
        with zipfile.ZipFile(zipfile_path) as infile:
            for filename in infile.namelist():
                with infile.open(filename) as schema_file:
                    schema = json.load(schema_file)
                    typename = schema["typeName"]
                    self.schemas[typename] = schema

    def schema(self, resource_name: ResourceName) -> dict:
        return self.schemas[resource_name.fullname]


class TemplateRenderer:
    def __init__(self, schema: dict, environment: Environment):
        self.schema = schema
        self.environment = environment

    def render(self, file_type: Literal["provider", "test"], resource_name: ResourceName) -> str:
        template_mapping = {"provider": "provider_template.py.j2", "test": "test_template.py.j2"}
        return get_formatted_template_output(
            self.environment,
            template_mapping[file_type],
            name=resource_name.fullname,
            resource=resource_name.provider_name(),
        )


@click.group()
def cli():
    pass


@cli.command()
@click.option("-s", "--service", required=True, help="Service to generate")
@click.option("--write/--no-write", default=False)
def generate(service: str, write: bool):
    resource_name = ResourceName.from_name(service)

    schema_provider = SchemaProvider(
        zipfile_path=Path(__file__).parent.joinpath("CloudformationSchema.zip")
    )
    schema = schema_provider.schema(resource_name)

    template_root = Path(__file__).parent.joinpath("templates")
    env = Environment(
        loader=FileSystemLoader(template_root),
    )

    template_renderer = TemplateRenderer(schema, env)

    if not write:
        console = Console()
        console.print("[underline]Provider template[/underline]")
        console.print()
        console.print(
            Syntax(template_renderer.render("provider", resource_name), "python")
            # Syntax(
            #     "python",
            # )
        )
        console.print()
        console.print()
        console.print("[underline]Test template[/underline]")
        console.print()
        console.print(
            Syntax(
                get_formatted_template_output(
                    env, "test_template.py.j2", name=service, resource=resource_name.provider_name()
                ),
                "python",
            )
        )


@cli.command()
def capture():
    print("Capturing")


if __name__ == "__main__":
    cli()
