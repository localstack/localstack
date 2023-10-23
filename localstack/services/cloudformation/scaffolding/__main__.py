from __future__ import annotations

import json
import os
import subprocess as sp
import zipfile
from dataclasses import dataclass
from enum import Enum, auto
from functools import reduce
from pathlib import Path
from typing import Any, Generator, Literal, Optional, TypedDict, TypeVar

import click
from jinja2 import Environment, FileSystemLoader
from yaml import safe_dump

from .propgen import generate_ir_for_type

try:
    from rich.console import Console
    from rich.syntax import Syntax
except ImportError:

    class Console:
        def print(self, text: str):
            print("# " + text.replace("[underline]", "").replace("[/underline]", ""))

    def Syntax(text: str, *args, **kwargs) -> str:
        return text


# increase when any major changes are done to the scaffolding,
# so that we can reason better about previously scaffolded resources in the future
SCAFFOLDING_VERSION = 2

# Some services require their names to be re-written as we know them by different names
SERVICE_NAME_MAP = {
    "OpenSearchService": "OpenSearch",
    "Lambda": "lambda_",
}


class Property(TypedDict):
    type: Optional[Literal["str"]]
    items: Optional[dict]


class HandlerDefinition(TypedDict):
    permissions: Optional[list[str]]


class HandlersDefinition(TypedDict):
    create: HandlerDefinition
    read: HandlerDefinition
    update: HandlerDefinition
    delete: HandlerDefinition
    list: HandlerDefinition


class ResourceSchema(TypedDict):
    typeName: str
    description: Optional[str]
    required: Optional[list[str]]
    properties: dict[str, Property]
    handlers: HandlersDefinition


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
    namespace: str
    service: str
    resource: str
    python_compatible_service_name: str

    def provider_name(self) -> str:
        return f"{self.service}{self.resource}"

    def schema_filename(self) -> str:
        return f"{self.namespace.lower()}-{self.service.lower()}-{self.resource.lower()}.json"

    def path_compatible_full_name(self) -> str:
        return f"{self.namespace.lower()}_{self.service.lower()}_{self.resource.lower()}"

    @classmethod
    def from_name(cls, name: str) -> ResourceName:
        parts = name.split("::")
        if len(parts) != 3 or parts[0] != "AWS":
            raise ValueError(f"Invalid CloudFormation resource name {name}")

        raw_service_name = parts[1].strip()
        renamed_service = SERVICE_NAME_MAP.get(raw_service_name, raw_service_name)

        return ResourceName(
            full_name=name,
            namespace=parts[0],
            service=raw_service_name,
            python_compatible_service_name=renamed_service,
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
        try:
            return self.schemas[resource_name.full_name]
        except KeyError as e:
            raise click.ClickException(
                f"Could not find schema for CloudFormation resource type: {resource_name.full_name}"
            ) from e


LOCALSTACK_ROOT_DIR = Path(__file__).parent.joinpath("../../../..").resolve()
TESTS_ROOT_DIR = LOCALSTACK_ROOT_DIR.joinpath("tests/aws/cloudformation/resource_providers")


def template_path(
    resource_name: ResourceName, file_type: FileType, root: Optional[Path] = None
) -> Path:
    """
    Given a resource name and file type, return the path of the template relative to the template root.
    """
    match file_type:
        case FileType.minimal_template:
            stub = "basic.yaml"
        case FileType.attribute_template:
            stub = "getatt_exploration.yaml"
        case FileType.update_without_replacement_template:
            stub = "update.yaml"
        case FileType.autogenerated_template:
            stub = "basic_autogenerated.yaml"
        case _:
            raise ValueError(f"File type {file_type} is not a template")

    output_path = TESTS_ROOT_DIR.joinpath(
        f"{resource_name.python_compatible_service_name.lower()}/{resource_name.path_compatible_full_name()}/templates/{stub}"
    ).resolve()

    if root:
        test_path = LOCALSTACK_ROOT_DIR.joinpath(
            f"tests/aws/cloudformation/resource_providers/{resource_name.python_compatible_service_name.lower()}/{resource_name.path_compatible_full_name()}"
        ).resolve()

        common_root = os.path.relpath(output_path, test_path)
        return Path(common_root)
    else:
        return output_path


class FileType(Enum):
    # service code
    plugin = auto()
    provider = auto()

    # meta test files
    conftest = auto()

    # test files
    integration_test = auto()
    getatt_test = auto()
    # cloudcontrol_test = auto()
    parity_test = auto()

    # templates
    attribute_template = auto()
    minimal_template = auto()
    update_without_replacement_template = auto()
    autogenerated_template = auto()

    # schema
    schema = auto()


class TemplateRenderer:
    def __init__(self, schema: ResourceSchema, environment: Environment):
        self.schema = schema
        self.environment = environment

    def render(
        self,
        file_type: FileType,
        resource_name: ResourceName,
    ) -> str:
        # Generated outputs (template, schema)
        # templates
        if file_type == FileType.attribute_template:
            return self.render_attribute_template(resource_name)
        elif file_type == FileType.minimal_template:
            return self.render_minimal_template(resource_name)
        elif file_type == FileType.update_without_replacement_template:
            return self.render_update_without_replacement_template(resource_name)
        elif file_type == FileType.autogenerated_template:
            return self.render_autogenerated_template(resource_name)
        # schema
        elif file_type == FileType.schema:
            return json.dumps(self.schema, indent=2)

        template_mapping = {
            FileType.plugin: "plugin_template.py.j2",
            FileType.provider: "provider_template.py.j2",
            FileType.getatt_test: "test_getatt_template.py.j2",
            FileType.integration_test: "test_integration_template.py.j2",
            # FileType.cloudcontrol_test: "test_cloudcontrol_template.py.j2",
            FileType.parity_test: "test_parity_template.py.j2",
            FileType.conftest: "conftest.py.j2",
        }
        kwargs = dict(
            name=resource_name.full_name,  # AWS::SNS::Topic
            resource=resource_name.provider_name(),  # SNSTopic
            scaffolding_version=f"v{SCAFFOLDING_VERSION}",
        )
        # TODO: we might want to segregate each provider in its own directory
        # e.g. .../resource_providers/aws_iam_role/test_X.py vs. .../resource_providers/iam/test_X.py
        # add extra parameters
        tests_output_path = LOCALSTACK_ROOT_DIR.joinpath(
            f"tests/aws/cloudformation/resource_providers/{resource_name.python_compatible_service_name.lower()}/{resource_name.full_name.lower()}"
        )
        match file_type:
            case FileType.getatt_test:
                kwargs["getatt_targets"] = list(self.get_getatt_targets())
                kwargs["service"] = resource_name.service.lower()
                kwargs["resource"] = resource_name.resource.lower()
                kwargs["template_path"] = str(
                    template_path(resource_name, FileType.attribute_template, tests_output_path)
                )
            case FileType.provider:
                property_ir = generate_ir_for_type(
                    [self.schema],
                    resource_name.full_name,
                    provider_prefix=resource_name.provider_name(),
                )
                kwargs["provider_properties"] = property_ir
                kwargs["required_properties"] = self.schema.get("required")
                kwargs["create_only_properties"] = self.schema.get("createOnlyProperties")
                kwargs["read_only_properties"] = self.schema.get("readOnlyProperties")
                kwargs["primary_identifier"] = self.schema.get("primaryIdentifier")
                kwargs["create_permissions"] = (
                    self.schema.get("handlers", {}).get("create", {}).get("permissions")
                )
                kwargs["delete_permissions"] = (
                    self.schema.get("handlers", {}).get("delete", {}).get("permissions")
                )
                kwargs["read_permissions"] = (
                    self.schema.get("handlers", {}).get("read", {}).get("permissions")
                )
                kwargs["update_permissions"] = (
                    self.schema.get("handlers", {}).get("update", {}).get("permissions")
                )
                kwargs["list_permissions"] = (
                    self.schema.get("handlers", {}).get("list", {}).get("permissions")
                )
            case FileType.plugin:
                kwargs["service"] = resource_name.service.lower()
                kwargs["lower_resource"] = resource_name.resource.lower()
            case FileType.integration_test:
                kwargs["black_box_template_path"] = str(
                    template_path(resource_name, FileType.minimal_template, tests_output_path)
                )
                kwargs["update_template_path"] = str(
                    template_path(
                        resource_name,
                        FileType.update_without_replacement_template,
                        tests_output_path,
                    )
                )
                kwargs["autogenerated_template_path"] = str(
                    template_path(resource_name, FileType.autogenerated_template, tests_output_path)
                )
            # case FileType.cloudcontrol_test:
            case FileType.parity_test:
                kwargs["parity_test_filename"] = "test_parity.py"
            case FileType.conftest:
                pass
            case _:
                raise NotImplementedError(f"Rendering template of type {file_type}")

        return get_formatted_template_output(
            self.environment, template_mapping[file_type], **kwargs
        )

    def get_getatt_targets(self) -> Generator[str, None, None]:
        for name, defn in self.schema["properties"].items():
            if "type" in defn and defn["type"] in ["string"]:
                yield name

    def render_minimal_template(self, resource_name: ResourceName) -> str:
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"Template to exercise create and delete operations for {resource_name.full_name}",
            "Resources": {
                "MyResource": {
                    "Type": resource_name.full_name,
                    "Properties": {},
                },
            },
            "Outputs": {
                "MyRef": {
                    "Value": {
                        "Ref": "MyResource",
                    },
                },
            },
        }

        return safe_dump(template, sort_keys=False)

    def render_update_without_replacement_template(self, resource_name: ResourceName) -> str:
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"Template to exercise updating {resource_name.full_name}",
            "Parameters": {
                "AttributeValue": {
                    "Type": "String",
                    "Description": "Value of property to change to force an update",
                },
            },
            "Resources": {
                "MyResource": {
                    "Type": resource_name.full_name,
                    "Properties": {
                        "SomeProperty": "!Ref AttributeValue",
                    },
                },
            },
            "Outputs": {
                "MyRef": {
                    "Value": {
                        "Ref": "MyResource",
                    },
                },
                "MyOutput": {
                    "Value": "# TODO: the value to verify",
                },
            },
        }
        return safe_dump(template, sort_keys=False)

    def render_autogenerated_template(self, resource_name: ResourceName) -> str:
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"Template to exercise updating autogenerated properties of {resource_name.full_name}",
            "Resources": {
                "MyResource": {
                    "Type": resource_name.full_name,
                },
            },
            "Outputs": {
                "MyRef": {
                    "Value": {
                        "Ref": "MyResource",
                    },
                },
            },
        }
        return safe_dump(template, sort_keys=False)

    def render_attribute_template(self, resource_name: ResourceName) -> str:
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"Template to exercise getting attributes of {resource_name.full_name}",
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
    destination_files: dict[FileType, Path]

    def __init__(self, resource_name: ResourceName, console: Console, overwrite: bool):
        self.resource_name = resource_name
        self.console = console
        self.overwrite = overwrite

        self.destination_files = {
            FileType.provider: LOCALSTACK_ROOT_DIR.joinpath(
                "localstack",
                "services",
                self.resource_name.python_compatible_service_name.lower(),
                "resource_providers",
                f"{self.resource_name.namespace.lower()}_{self.resource_name.service.lower()}_{self.resource_name.resource.lower()}.py",
            ),
            FileType.plugin: LOCALSTACK_ROOT_DIR.joinpath(
                "localstack",
                "services",
                self.resource_name.python_compatible_service_name.lower(),
                "resource_providers",
                f"{self.resource_name.namespace.lower()}_{self.resource_name.service.lower()}_{self.resource_name.resource.lower()}_plugin.py",
            ),
            FileType.schema: LOCALSTACK_ROOT_DIR.joinpath(
                "localstack",
                "services",
                self.resource_name.python_compatible_service_name.lower(),
                "resource_providers",
                f"aws_{self.resource_name.service.lower()}_{self.resource_name.resource.lower()}.schema.json",
            ),
            FileType.integration_test: TESTS_ROOT_DIR.joinpath(
                self.resource_name.python_compatible_service_name.lower(),
                self.resource_name.path_compatible_full_name(),
                "test_basic.py",
            ),
            FileType.getatt_test: TESTS_ROOT_DIR.joinpath(
                self.resource_name.python_compatible_service_name.lower(),
                self.resource_name.path_compatible_full_name(),
                "test_exploration.py",
            ),
            # FileType.cloudcontrol_test: TESTS_ROOT_DIR.joinpath(
            #     self.resource_name.python_compatible_service_name.lower(),
            #     f"test_aws_{self.resource_name.service.lower()}_{self.resource_name.resource.lower()}_cloudcontrol.py",
            # ),
            FileType.parity_test: TESTS_ROOT_DIR.joinpath(
                self.resource_name.python_compatible_service_name.lower(),
                self.resource_name.path_compatible_full_name(),
                "test_parity.py",
            ),
            FileType.conftest: TESTS_ROOT_DIR.joinpath(
                self.resource_name.python_compatible_service_name.lower(),
                self.resource_name.path_compatible_full_name(),
                "conftest.py",
            ),
        }

        # output files that are templates
        templates = [
            FileType.attribute_template,
            FileType.minimal_template,
            FileType.update_without_replacement_template,
            FileType.autogenerated_template,
        ]
        for template_type in templates:
            self.destination_files[template_type] = template_path(self.resource_name, template_type)

    def write(self, file_type: FileType, contents: str):
        file_destination = self.destination_files[file_type]
        destination_path = file_destination.parent
        destination_path.mkdir(parents=True, exist_ok=True)

        if file_destination.exists():
            should_overwrite = self.confirm_overwrite(file_destination)
            if not should_overwrite:
                self.console.print(f"Skipping {file_destination}")
                return

        match file_type:
            # provider
            case FileType.provider:
                self.ensure_python_init_files(destination_path)
                self.write_text(contents, file_destination)
                self.console.print(f"Written provider to {file_destination}")
            case FileType.plugin:
                self.ensure_python_init_files(destination_path)
                self.write_text(contents, file_destination)
                self.console.print(f"Written plugin to {file_destination}")

            # tests meta
            case FileType.conftest:
                self.ensure_python_init_files(destination_path)
                self.write_text(contents, file_destination)
                self.console.print(f"Written pytest conftest to {file_destination}")

            # tests
            case FileType.integration_test:
                self.ensure_python_init_files(destination_path)
                self.write_text(contents, file_destination)
                self.console.print(f"Written integration test to {file_destination}")
            case FileType.getatt_test:
                self.write_text(contents, file_destination)
                self.console.print(f"Written getatt tests to {file_destination}")
            # case FileType.cloudcontrol_test:
            #     self.write_text(contents, file_destination)
            #     self.console.print(f"Written cloudcontrol tests to {file_destination}")
            case FileType.parity_test:
                self.write_text(contents, file_destination)
                self.console.print(f"Written parity tests to {file_destination}")

            # templates
            case FileType.attribute_template:
                self.write_text(contents, file_destination)
                self.console.print(f"Written attribute template to {file_destination}")
            case FileType.minimal_template:
                self.write_text(contents, file_destination)
                self.console.print(f"Written minimal template to {file_destination}")
            case FileType.update_without_replacement_template:
                self.write_text(contents, file_destination)
                self.console.print(
                    f"Written update without replacement template to {file_destination}"
                )
            case FileType.autogenerated_template:
                self.write_text(contents, file_destination)
                self.console.print(
                    f"Written autogenerated properties template to {file_destination}"
                )

            # schema
            case FileType.schema:
                self.write_text(contents, file_destination)
                self.console.print(f"Written schema to {file_destination}")
            case _:
                raise NotImplementedError(f"Writing {file_type}")

    def confirm_overwrite(self, destination_file: Path) -> bool:
        """
        If a file we are about to write to exists, overwrite or ignore.

        :return True if file should be (over-)written, False otherwise
        """
        return self.overwrite or click.confirm("Destination files already exist, overwrite?")

    @staticmethod
    def write_text(contents: str, destination: Path):
        with destination.open("wt") as outfile:
            print(contents, file=outfile)

    @staticmethod
    def ensure_python_init_files(path: Path):
        """
        Make sure __init__.py files are created correctly
        """
        project_root = path.parent.parent.parent.parent
        path_relative_to_root = path.relative_to(project_root)
        dir = project_root
        for part in path_relative_to_root.parts:
            dir = dir / part
            test_path = dir.joinpath("__init__.py")
            if not test_path.is_file():
                # touch file
                with test_path.open("w"):
                    pass


class OutputFactory:
    def __init__(self, template_renderer: TemplateRenderer, printer: Console, writer: FileWriter):
        self.template_renderer = template_renderer
        self.printer = printer
        self.writer = writer

    def get(self, file_type: FileType, resource_name: ResourceName) -> Output:
        contents = self.template_renderer.render(file_type, resource_name)
        return Output(contents, file_type, self.printer, self.writer, resource_name)


class Output:
    def __init__(
        self,
        contents: str,
        file_type: FileType,
        printer: Console,
        writer: FileWriter,
        resource_name: ResourceName,
    ):
        self.contents = contents
        self.file_type = file_type
        self.printer = printer
        self.writer = writer
        self.resource_name = resource_name

    def handle(self, should_write: bool = False):
        if should_write:
            self.write()
        else:
            self.print()

    def write(self):
        self.writer.write(self.file_type, self.contents)

    def print(self):
        match self.file_type:
            # service code
            case FileType.provider:
                self.printer.print("\n[underline]Provider template[/underline]\n")
                self.printer.print(Syntax(self.contents, "python"))
            case FileType.plugin:
                self.printer.print("\n[underline]Plugin[/underline]\n")
                self.printer.print(Syntax(self.contents, "python"))
            # tests
            case FileType.integration_test:
                self.printer.print("\n[underline]Integration test file[/underline]\n")
                self.printer.print(Syntax(self.contents, "python"))
            case FileType.getatt_test:
                self.printer.print("\n[underline]GetAtt test file[/underline]\n")
                self.printer.print(Syntax(self.contents, "python"))
            # case FileType.cloudcontrol_test:
            #     self.printer.print("\n[underline]CloudControl test[/underline]\n")
            #     self.printer.print(Syntax(self.contents, "python"))
            case FileType.parity_test:
                self.printer.print("\n[underline]Parity test[/underline]\n")
                self.printer.print(Syntax(self.contents, "python"))

            # templates
            case FileType.attribute_template:
                self.printer.print("\n[underline]Attribute Test Template[/underline]\n")
                self.printer.print(Syntax(self.contents, "yaml"))
            case FileType.minimal_template:
                self.printer.print("\n[underline]Minimal template[/underline]\n")
                self.printer.print(Syntax(self.contents, "yaml"))
            case FileType.update_without_replacement_template:
                self.printer.print("\n[underline]Update test template[/underline]\n")
                self.printer.print(Syntax(self.contents, "yaml"))
            case FileType.autogenerated_template:
                self.printer.print("\n[underline]Autogenerated properties template[/underline]\n")
                self.printer.print(Syntax(self.contents, "yaml"))

            # schema
            case FileType.schema:
                self.printer.print("\n[underline]Schema[/underline]\n")
                self.printer.print(Syntax(self.contents, "json"))
            case _:
                raise NotImplementedError(self.file_type)


@click.group()
def cli():
    pass


@cli.command()
@click.option(
    "-r",
    "--resource-type",
    required=True,
    help="CloudFormation resource type (e.g. 'AWS::SSM::Parameter') to generate",
)
@click.option("-w", "--write/--no-write", default=False)
@click.option("--overwrite", is_flag=True, default=False)
@click.option("-t", "--write-tests/--no-write-tests", default=False)
def generate(resource_type: str, write: bool, write_tests: bool, overwrite: bool):
    console = Console()
    console.rule(title=resource_type)

    schema_provider = SchemaProvider(
        zipfile_path=Path(__file__).parent.joinpath("CloudformationSchema.zip")
    )

    template_root = Path(__file__).parent.joinpath("templates")
    env = Environment(
        loader=FileSystemLoader(template_root),
    )

    parts = resource_type.rpartition("::")
    if parts[-1] == "*":
        # generate all resource types for that service
        matching_resources = [x for x in schema_provider.schemas.keys() if x.startswith(parts[0])]
    else:
        matching_resources = [resource_type]

    for matching_resource in matching_resources:
        console.rule(title=matching_resource)
        resource_name = ResourceName.from_name(matching_resource)
        schema = schema_provider.schema(resource_name)

        template_renderer = TemplateRenderer(schema, env)
        writer = FileWriter(resource_name, console, overwrite)
        output_factory = OutputFactory(template_renderer, console, writer)  # noqa
        for file_type in FileType:
            if not write_tests and file_type in {
                FileType.integration_test,
                FileType.getatt_test,
                FileType.parity_test,
                FileType.conftest,
                FileType.minimal_template,
                FileType.update_without_replacement_template,
                FileType.attribute_template,
                FileType.autogenerated_template,
            }:
                # skip test generation
                continue
            output_factory.get(file_type, resource_name).handle(should_write=write)

    console.rule(title="Resources & Instructions")
    console.print(
        "Resource types: https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/resource-types.html"
    )
    # TODO: print for every resource
    for matching_resource in matching_resources:
        resource_name = ResourceName.from_name(matching_resource)
        console.print(
            # lambda_ should become lambda (re-use the same list we use for generating the models)
            f"{matching_resource}: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-{resource_name.service.lower()}-{resource_name.resource.lower()}.html"
        )
    console.print("\nWondering where to get started?")
    console.print(
        "First run `make entrypoints` to make sure your resource provider plugin is actually registered."
    )
    console.print(
        'Then start off by finalizing the generated minimal ("basic") template and get it to deploy against AWS.'
    )


if __name__ == "__main__":
    cli()
