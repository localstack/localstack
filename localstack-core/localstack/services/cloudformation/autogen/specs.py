import json
from pathlib import Path
from typing import Any, Literal, NotRequired, TypedDict

ROOT_DIR = Path(__file__).parent.parent.parent.resolve()


class HandlerSchema(TypedDict, total=False):
    properties: dict[str, Any]
    required: list[str]
    allOf: list[Any]
    anyOf: list[Any]
    oneOf: list[Any]


class HandlerDefinitionWithSchemaOverride(TypedDict):
    permissions: list[str]
    handlerSchema: HandlerSchema
    timeoutInMinutes: NotRequired[int]  # default 120, min=2, max=2160


class HandlerDefinition(TypedDict):
    permissions: list[str]
    timeoutInMinutes: NotRequired[int]  # default 120, min=2, max=2160


ReplacementStrategy = Literal["create_then_delete", "delete_then_create"]


class Tagging(TypedDict, total=False):
    taggable: bool  # default True
    tagOnCreate: bool  # default True
    tagUpdatable: bool  # default True
    cloudFormationSystemTags: bool  # default True
    tagProperty: str  # default "/properties/Tags"
    permissions: list[str]


class Handlers(TypedDict, total=False):
    create: HandlerDefinition
    read: HandlerDefinition
    update: HandlerDefinition
    delete: HandlerDefinition
    list: HandlerDefinitionWithSchemaOverride


class StringProperty(TypedDict, total=False):
    type: Literal["string"]
    description: NotRequired[str]
    enum: NotRequired[list[str]]


class ObjectProperty(TypedDict, total=False):
    type: Literal["object"]
    additionalProperties: bool

    description: NotRequired[str]
    patternProperties: NotRequired[dict]
    properties: NotRequired[dict[str, Any]]
    required: NotRequired[list[str]]


ArrayReference = TypedDict("ArrayReference", {"$ref": str})


class ArrayProperty(TypedDict, total=False):
    type: Literal["array"]
    items: ArrayReference

    uniqueItems: NotRequired[bool]
    insertionOrder: NotRequired[bool]


class BooleanProperty(TypedDict, total=False):
    type: Literal["boolean"]


class IntegerProperty(TypedDict, total=False):
    type: Literal["integer"]

    # TODO: minValue, maxValue


PropertyDefinition = (
    StringProperty | ObjectProperty | ArrayProperty | BooleanProperty | IntegerProperty
)


class ResourceProviderDefinition(TypedDict):
    # required top‐level properties
    typeName: str
    properties: dict[str, PropertyDefinition]
    description: str
    primaryIdentifier: list[str]
    additionalProperties: bool

    # optional metadata and others
    tagging: NotRequired[Tagging]
    replacementStrategy: NotRequired[ReplacementStrategy]
    definitions: NotRequired[dict[str, Any]]
    handlers: NotRequired[Handlers]
    readOnlyProperties: NotRequired[list[str]]
    writeOnlyProperties: NotRequired[list[str]]
    conditionalCreateOnlyProperties: NotRequired[list[str]]
    createOnlyProperties: NotRequired[list[str]]
    deprecatedProperties: NotRequired[list[str]]
    additionalIdentifiers: NotRequired[list[list[str]]]
    required: NotRequired[list[str]]


def read_spec_for(resource_name: str) -> ResourceProviderDefinition:
    _, service, resource = resource_name.lower().split("::")
    schema_path = (
        ROOT_DIR / service / "resource_providers" / f"aws_{service}_{resource}.schema.json"
    )
    with schema_path.open() as infile:
        return json.load(infile)
