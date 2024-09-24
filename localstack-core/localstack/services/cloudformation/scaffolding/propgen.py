"""
Implementation of generating the types for a provider from the schema
"""

from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass
from typing import Optional, TypedDict

LOG = logging.getLogger(__name__)


@dataclass
class Item:
    """An Item is a single field definition"""

    name: str
    type: str
    required: bool

    def __str__(self) -> str:
        return f"{self.name}: {self.type}"

    @classmethod
    def new(cls, name: str, type: str, required: bool = False) -> Item:
        if required:
            return cls(name=name, type=type, required=required)
        else:
            return cls(name=name, type=f"Optional[{type}]", required=required)


@dataclass
class PrimitiveStruct:
    name: str
    primitive_type: str

    def __str__(self) -> str:
        return f"""
{self.name} = {self.primitive_type}
"""


@dataclass
class Struct:
    """A struct represents a single rendered class"""

    name: str
    items: list[Item]

    def __str__(self) -> str:
        if self.items:
            raw_text = "\n".join(map(str, self.sorted_items))
        else:
            raw_text = "pass"
        formatted_items = textwrap.indent(raw_text, "    ")
        return f"""
class {self.name}(TypedDict):
{formatted_items}
"""

    @property
    def sorted_items(self) -> list[Item]:
        required_items = sorted(
            [item for item in self.items if item.required], key=lambda item: item.name
        )
        optional_items = sorted(
            [item for item in self.items if not item.required], key=lambda item: item.name
        )
        return required_items + optional_items


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
    definitions: dict
    typeName: str
    required: Optional[list[str]]


TYPE_MAP = {
    "string": "str",
    "boolean": "bool",
    "integer": "int",
    "number": "float",
    "object": "dict",
    "array": "list",
}


class PropertyTypeScaffolding:
    resource_type: str
    provider_prefix: str
    schema: Schema

    structs: list[Struct]

    required_properties: list[str]

    def __init__(self, resource_type: str, provider_prefix: str, schema: Schema):
        self.resource_type = resource_type
        self.provider_prefix = provider_prefix
        self.schema = schema
        self.structs = []
        self.required_properties = schema.get("required", [])

    def get_structs(self) -> list[Struct]:
        root_struct = Struct(f"{self.provider_prefix}Properties", items=[])
        self._add_struct(root_struct)

        for property_name, property_def in self.schema["properties"].items():
            is_required = property_name in self.required_properties
            item = self.property_to_item(property_name, property_def, is_required)
            root_struct.items.append(item)

        return self.structs

    def _add_struct(self, struct: Struct):
        if struct.name in [s.name for s in self.structs]:
            return
        else:
            self.structs.append(struct)

    def get_ref_definition(self, property_ref: str) -> dict:
        property_ref_name = property_ref.lstrip("#").rpartition("/")[-1]
        return self.schema["definitions"][property_ref_name]

    def resolve_type_of_property(self, property_def: dict) -> str:
        if property_ref := property_def.get("$ref"):
            ref_definition = self.get_ref_definition(property_ref)
            ref_type = ref_definition.get("type")
            if ref_type not in ["object", "array"]:
                # in this case we simply flatten it (instead of for example creating a type alias)
                resolved_type = TYPE_MAP.get(ref_type)
                if resolved_type is None:
                    LOG.warning(
                        "Type for %s not found in the TYPE_MAP. Using `Any` as fallback.", ref_type
                    )
                    resolved_type = "Any"
            else:
                if ref_type == "object":
                    # the object might only have a pattern defined and no actual properties
                    if "properties" not in ref_definition:
                        resolved_type = "dict"
                    else:
                        nested_struct = self.ref_to_struct(property_ref)
                        resolved_type = nested_struct.name
                        self._add_struct(nested_struct)
                elif ref_type == "array":
                    item_def = ref_definition["items"]
                    item_type = self.resolve_type_of_property(item_def)
                    resolved_type = f"list[{item_type}]"
                else:
                    raise Exception(f"Unknown property type encountered: {ref_type}")
        else:
            match property_type := property_def.get("type"):
                # primitives
                case "string":
                    resolved_type = "str"
                case "boolean":
                    resolved_type = "bool"
                case "integer":
                    resolved_type = "int"
                case "number":
                    resolved_type = "float"
                # complex objects
                case "object":
                    resolved_type = "dict"  # TODO: any cases where we need to continue here?
                case "array":
                    try:
                        item_type = self.resolve_type_of_property(property_def["items"])
                        resolved_type = f"list[{item_type}]"
                    except RecursionError:
                        resolved_type = "list[Any]"
                case _:
                    # TODO: allOf, anyOf, patternProperties (?)
                    # AWS::ApiGateway::RestApi passes a ["object", "string"] here for the "Body" property
                    # it probably makes sense to assume this behaves the same as a "oneOf"
                    if one_of := property_def.get("oneOf"):
                        resolved_type = "|".join([self.resolve_type_of_property(o) for o in one_of])
                    elif isinstance(property_type, list):
                        resolved_type = "|".join([TYPE_MAP[pt] for pt in property_type])
                    else:
                        raise Exception(f"Unknown property type: {property_type}")
        return resolved_type

    def property_to_item(self, property_name: str, property_def: dict, required: bool) -> Item:
        resolved_type = self.resolve_type_of_property(property_def)
        return Item(name=property_name, type=f"Optional[{resolved_type}]", required=required)

    def ref_to_struct(self, property_ref: str) -> Struct:
        property_ref_name = property_ref.lstrip("#").rpartition("/")[-1]
        resolved_def = self.schema["definitions"][property_ref_name]
        nested_struct = Struct(name=property_ref_name, items=[])
        if resolved_properties := resolved_def.get("properties"):
            required_props = resolved_def.get("required", [])
            for k, v in resolved_properties.items():
                is_required = k in required_props
                item = self.property_to_item(k, v, is_required)
                nested_struct.items.append(item)
        else:
            raise Exception("Unknown resource format. Expected properties on object")

        return nested_struct


def generate_ir_for_type(schema: list[Schema], type_name: str, provider_prefix: str = "") -> IR:
    try:
        resource_schema = [every for every in schema if every["typeName"] == type_name][0]
    except IndexError:
        raise ValueError(f"could not find schema for type {type_name}")

    structs = PropertyTypeScaffolding(
        resource_type=type_name, provider_prefix=provider_prefix, schema=resource_schema
    ).get_structs()
    return IR(structs=structs)
