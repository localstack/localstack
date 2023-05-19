"""
Implementation of generating the types for a provider from the schema
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from functools import reduce
from typing import Optional, TypedDict


@dataclass
class Item:
    name: str
    type: str

    def __str__(self) -> str:
        return f"{self.name}: {self.type}"

    @classmethod
    def new(cls, name: str, type: str, required: bool = False) -> Item:
        if required:
            return cls(name=name, type=type)
        else:
            return cls(name=name, type=f"Optional[{type}]")


@dataclass
class Struct:
    name: str
    items: list[Item]

    def __str__(self) -> str:
        if self.items:
            raw_text = "\n".join(map(str, self.items))
        else:
            raw_text = "pass"
        formatted_items = textwrap.indent(raw_text, "    ")
        return f"""
@dataclass
class {self.name}:
{formatted_items}
"""


@dataclass
class IR:
    structs: list[Struct]

    def __str__(self) -> str:
        """
        Pretty print the IR
        """
        return "\n\n".join(map(str, self.structs))


class Schema(TypedDict):
    properties: dict
    typeName: str
    required: Optional[list[str]]


TYPE_MAP = {
    "string": "str",
    "boolean": "bool",
    "integer": "int",
}


def render_types(
    schema: Schema,
    required_properties: list[str],
    name: Optional[str] = None,
    sub_schema: Optional[dict] = None,
    trace_logging: bool = False,
) -> list[Struct]:
    """
    Render the types contained within a schema to a list of structs.
    """
    structs = []

    top_level_props = Struct(name=name or "Properties", items=[])

    if sub_schema is not None:
        current_schema = sub_schema
    else:
        current_schema = schema

    if "properties" not in current_schema:
        # Simple type
        if prop_type := current_schema.get("type"):
            if isinstance(prop_type, str) and (python_type := TYPE_MAP.get(prop_type)):
                item = Item.new(name=name, type=python_type, required=name in required_properties)
                top_level_props.items.append(item)
                return structs
        raise NotImplementedError

    for property, defn in current_schema["properties"].items():
        if prop_type := defn.get("type"):
            if isinstance(prop_type, str) and (python_type := TYPE_MAP.get(prop_type)):
                item = Item.new(
                    name=property, type=python_type, required=property in required_properties
                )
            elif isinstance(prop_type, list):
                # e.g. ["object", "string"] => dict[str, str]
                container = prop_type[0]
                match container:
                    case "object":
                        # value types are the next element
                        value_type = TYPE_MAP[prop_type[1]]
                        item = Item.new(
                            name=property,
                            type=f"dict[str, {value_type}]]",
                            required=property in required_properties,
                        )
                    case _:
                        raise NotImplementedError(property, prop_type)
            else:
                match prop_type:
                    case "object":
                        item = Item.new(
                            name=property, type="dict", required=property in required_properties
                        )
                    case "array":
                        # TODO
                        item = Item.new(
                            name=property, type="list", required=property in required_properties
                        )
                    case _:
                        raise NotImplementedError(prop_type)

            top_level_props.items.append(item)
        elif ref := defn.get("$ref"):
            new_defn_path = ref[2:].split("/")
            new_defn = reduce(lambda s, p: s[p], new_defn_path, schema)
            new_structs = render_types(
                schema=schema,
                required_properties=required_properties,
                name=property,
                sub_schema=new_defn,
                trace_logging=trace_logging,
            )
            structs.extend(new_structs)
            item = Item.new(name=property, type=property, required=property in required_properties)
            top_level_props.items.append(item)
        elif options := defn.get("oneOf"):
            for option in options:
                if type := option.get("type"):
                    match type:
                        case "object":
                            item = Item.new(
                                name=property, type="dict", required=property in required_properties
                            )
                            top_level_props.items.append(item)
                            break
                        case _:
                            continue
        else:
            raise NotImplementedError(property, defn)

    structs.append(top_level_props)

    return structs


def generate_ir_for_type(schema: list[Schema], type_name: str, trace_logging: bool = False) -> IR:
    try:
        resource_schema = [every for every in schema if every["typeName"] == type_name][0]
    except IndexError:
        raise ValueError(f"could not find schema for type {type_name}")

    required_properties = resource_schema.get("required", [])
    structs = render_types(
        resource_schema, required_properties=required_properties, trace_logging=trace_logging
    )
    return IR(structs=structs)
