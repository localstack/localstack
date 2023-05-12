from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from functools import reduce
from pathlib import Path
from typing import Any, Generator, Literal, Optional, TypedDict, TypeVar

import click
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
from rich.syntax import Syntax
from yaml import safe_dump


class Property(TypedDict):
    type: Optional[Literal["str"]]
    items: Optional[dict]


class ResourceSchema(TypedDict):
    typeName: str
    description: Optional[str]
    required: Optional[list[str]]
    properties: dict[str, Property]


def resolve_ref(schema: ResourceSchema, target: str) -> dict:
    """
    Given a schema {"a": {"b": "c"}} and the ref "#/a/b" return "c"
    """
    target_path = filter(None, map(lambda elem: elem.strip(), target.lstrip("#").split("/")))

    T = TypeVar("T")

    def lookup(d: dict[str, T], key: str) -> dict | T:
        return d[key]

    return reduce(lookup, target_path, schema)


@dataclass
class ResourceName:
    full_name: str
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
            full_name=name,
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

    def schema(self, resource_name: ResourceName) -> ResourceSchema:
        return self.schemas[resource_name.full_name]


class TemplateRenderer:
    def __init__(self, schema: ResourceSchema, environment: Environment):
        self.schema = schema
        self.environment = environment

    def render(
        self, file_type: Literal["provider", "test", "template"], resource_name: ResourceName
    ) -> str:
        # TODO: remove this ugly conditional
        if file_type == "template":
            return self.render_template(resource_name)

        template_mapping = {
            "provider": "provider_template.py.j2",
            "test": "test_template.py.j2",
        }
        kwargs = dict(
            name=resource_name.full_name,
            resource=resource_name.provider_name(),
        )
        if file_type == "test":
            kwargs["getatt_targets"] = list(self.get_getatt_targets())

        return get_formatted_template_output(
            self.environment, template_mapping[file_type], **kwargs
        )

    def get_getatt_targets(self) -> Generator[str, None, None]:
        for name, defn in self.schema["properties"].items():
            if "type" in defn and defn["type"] in ["string"]:
                yield name

    def render_template(self, resource_name: ResourceName) -> str:
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"Template to exercise {resource_name.full_name}",
            "Parameters": {
                "AttributeName": {
                    "Type": "String",
                    "Description": "Name of the attribute to fetch from the resource",
                },
            },
            "Resources": {
                "MyResource": {
                    "Type": resource_name.full_name,
                    "Properties": {},
                },
            },
            "Outputs": self.render_outputs(),
        }

        return safe_dump(template, sort_keys=False)

    def required_properties(self) -> dict[str, Property]:
        return PropertyRenderer(self.schema).properties()

    def render_outputs(self) -> dict:
        """
        Generate an output for each property in the schema
        """
        outputs = {}

        # ref
        outputs["MyRef"] = {"Fn::Ref": "MyResource"}

        # getatt
        outputs["MyOutput"] = {"Fn::GetAtt": ["MyResource", {"Fn::Ref": "AttributeName"}]}

        return outputs


class PropertyRenderer:
    def __init__(self, schema: ResourceSchema):
        self.schema = schema

    def properties(self) -> dict:
        required_properties = self.schema.get("required", [])

        result = {}
        for name, defn in self.schema["properties"].items():
            if name not in required_properties:
                continue

            value = self.render_property(defn)
            result[name] = value

        return result

    def render_property(self, property: Property) -> str | dict | list:
        if prop_type := property.get("type"):
            if prop_type in {"string"}:
                return self._render_basic(prop_type)
            elif prop_type == "array":
                return [self.render_property(item) for item in property["items"]]
        elif oneof := property.get("oneOf"):
            return self._render_one_of(oneof)
        else:
            raise NotImplementedError(property)

    def _render_basic(self, type: str) -> str:
        return "CHANGEME"

    def _render_one_of(self, options: list[Property]) -> Any:
        return self.render_property(options[0])


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
        console.print("\n[underline]Provider template[/underline]\n")
        console.print(Syntax(template_renderer.render("provider", resource_name), "python"))
        console.print("\n[underline]Test template[/underline]\n")
        console.print(
            Syntax(template_renderer.render("test", resource_name), "python")
            # Syntax(
            #     get_formatted_template_output(
            #         env,
            #         "test_template.py.j2",
            #         name=service,
            #         resource=resource_name.provider_name(),
            #         getatt_targets=["a", "b"],
            #     ),
            #     "python",
            # )
        )
        console.print("\n[underline]Template[/underline]\n")
        console.print(Syntax(template_renderer.render("template", resource_name), "yaml"))


@cli.command()
def capture():
    print("Capturing")


if __name__ == "__main__":
    cli()
