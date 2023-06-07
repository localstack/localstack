from __future__ import annotations

import json
import subprocess as sp
import zipfile
from dataclasses import dataclass
from functools import reduce
from pathlib import Path
from typing import Any, Generator, Literal, Optional, TypedDict, TypeVar

import click
from jinja2 import Environment, FileSystemLoader

try:
    from rich.console import Console
    from rich.syntax import Syntax
except ImportError:

    class Console:
        def print(self, text: str):
            print("# " + text.replace("[underline]", "").replace("[/underline]", ""))

    def Syntax(text: str, *args, **kwargs) -> str:
        return text


from yaml import safe_dump

from localstack.services.cloudformation.scaffolding.propgen import generate_ir_for_type

# Some services require their names to be re-written as we know them by different names
SERVICE_NAME_MAP = {
    "OpenSearchService": "OpenSearch",
    "Lambda": "AWSLambda",
}


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

        raw_service_name = parts[1].strip()
        renamed_service = SERVICE_NAME_MAP.get(raw_service_name, raw_service_name)

        return ResourceName(
            full_name=name,
            service=renamed_service,
            resource=parts[2].strip(),
        )


def run_black(text: str) -> str:
    """Black does not have an API, so spawn a subprocess"""
    try:
        proc = sp.run(["black", "--code", text], capture_output=True, check=True)
    except FileNotFoundError:
        # The user does not have black installed
        return text
    output = proc.stdout.decode("utf8")
    return output


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
            name=resource_name.full_name,  # AWS::SNS::Topic
            resource=resource_name.provider_name(),  # SNSTopic
        )

        # add extra parameters
        match file_type:
            case "test":
                kwargs["getatt_targets"] = list(self.get_getatt_targets())
                kwargs["service"] = resource_name.service.lower()
                kwargs["resource"] = resource_name.resource.lower()
            case "provider":
                property_ir = generate_ir_for_type(
                    [self.schema],
                    resource_name.full_name,
                    provider_prefix=resource_name.provider_name(),
                )
                kwargs["provider_properties"] = property_ir

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
        outputs["MyRef"] = {"Value": {"Ref": "MyResource"}}

        # getatt
        outputs["MyOutput"] = {"Value": {"Fn::GetAtt": ["MyResource", {"Ref": "AttributeName"}]}}

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


class FileWriter:
    destination_files: dict[str, Path]

    def __init__(
        self,
        root: Path,
        resource_name: ResourceName,
        console: Console,
    ):
        self.root = root
        self.resource_name = resource_name
        self.console = console

        self.destination_files = {
            "provider": self.root.joinpath(
                "localstack",
                "services",
                self.resource_name.service.lower(),
                "resource_providers",
                f"aws_{self.resource_name.service.lower()}_{self.resource_name.resource.lower()}.py",
            ),
            "tests": self.root.joinpath(
                "tests",
                "integration",
                "cloudformation",
                "resource_providers",
                self.resource_name.service.lower(),
                f"test_{self.resource_name.resource.lower()}.py",
            ),
            "test_template": self.root.joinpath(
                "tests",
                "integration",
                "templates",
                "resource_providers",
                self.resource_name.service.lower(),
                f"{self.resource_name.resource.lower()}.yaml",
            ),
        }

        self.confirm_if_existing_files()

    def confirm_if_existing_files(self):
        """
        If a file we are about to write to exists, raise an error
        """
        for destination_file in self.destination_files.values():
            if destination_file.is_file():
                if click.confirm("Destination files already exist, overwrite?"):
                    break
                else:
                    raise SystemExit(1)

    def write_provider(self, contents: str):
        destination = self.destination_files["provider"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.write_text(contents, destination)
        self.console.print(f"written provider to {destination}")

    def write_tests(self, contents: str):
        destination = self.destination_files["tests"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.write_text(contents, destination)
        self.console.print(f"written tests to {destination}")

    def write_test_template(self, contents: str):
        destination = self.destination_files["test_template"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.write_text(contents, destination)
        self.console.print(f"written test CFn template to {destination}")

    @staticmethod
    def write_text(contents: str, destination: Path):
        with destination.open("wt") as outfile:
            print(contents, file=outfile)


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
    provider_file = template_renderer.render("provider", resource_name)
    tests_file = template_renderer.render("test", resource_name)
    test_template = template_renderer.render("template", resource_name)

    # for pretty printing
    console = Console()

    if not write:
        console.print("\n[underline]Provider template[/underline]\n")
        console.print(Syntax(provider_file, "python"))
        console.print("\n[underline]Test template[/underline]\n")
        console.print(Syntax(tests_file, "python"))
        console.print("\n[underline]Template[/underline]\n")
        console.print(Syntax(test_template, "yaml"))
        return

    # render the output to the file system locations
    root_path = Path(__file__).joinpath("..", "..", "..", "..", "..").resolve()
    writer = FileWriter(root_path, resource_name, console)
    writer.write_provider(provider_file)
    writer.write_tests(tests_file)
    writer.write_test_template(test_template)
    return


@cli.command()
def capture():
    print("Capturing")


if __name__ == "__main__":
    cli()
