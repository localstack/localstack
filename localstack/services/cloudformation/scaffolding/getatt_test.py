import argparse
import json
import sys
from pathlib import Path
from typing import TypedDict

import black
from jinja2 import Template

TEMPLATE_DIR = Path(__file__).parent / "templates"


class Resource(TypedDict):
    typeName: str
    properties: dict


Schema = list[Resource]


def error(msg):
    print(msg, file=sys.stderr)
    exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--schema",
        required=True,
        type=argparse.FileType("r"),
        help="JSON schema definition",
    )
    parser.add_argument("type", help="AWS resource type")
    parser.add_argument(
        "-o",
        "--output",
        required=False,
        default="-",
        type=argparse.FileType("w"),
        help="File to output to (defaults to stdout)",
    )
    args = parser.parse_args()
    with TEMPLATE_DIR.joinpath("getatt_test.py.j2").open() as infile:
        template = Template(infile.read())

    schema: Schema = json.load(args.schema)
    if not isinstance(schema, list):
        error(
            f"Schema is of an unexpected format. The default value is a list, but we received a {type(args.schema)}"
        )

    resource_schema = [resource for resource in schema if resource["typeName"] == args.type]
    if len(resource_schema) != 1:
        error(f"could not find schema for resource {args.type}")

    resource_schema = resource_schema[0]
    attribute_names = list(resource_schema["properties"].keys())

    raw_template = template.render(attributes=set(attribute_names), resource_type=args.type)
    # format the template with black
    formatted_template = black.format_str(raw_template, mode=black.FileMode())
    print(formatted_template, file=args.output)
