import builtins
import logging
import types
import typing

from localstack.constants import VERSION
from localstack.services.stores import BaseStore

LOG = logging.getLogger(__name__)

TypeHint = types.GenericAlias | type

INTERNAL_MODULE_PREFIXES = ["localstack", "moto"]
"""Modules that starts with this prefix are considered internal classes and are evaluated"""


AttributeName = str
FQN = str
SerializedHint = str | dict[str, typing.Any]

AttributeSchema = dict[AttributeName, SerializedHint]
"""Maps an attribute name its serialized hints"""

AdditionalClasses = dict[FQN, AttributeSchema]
"""Maps the a FQN of a class to its Attribute Schema"""

TAG_TYPE = "LS/TYPE"
TAG_ARGS = "LS/ARGS"
"""Tags for subscribed types and their args. See ``StoreSchemaBuilder`` for examples."""


class StoreSchema(typing.TypedDict):
    type: str
    localstack_version: str
    additional_classes: AdditionalClasses
    attributes: AttributeSchema


def get_fully_qualified_name(obj: type) -> str:
    """Get the fully qualified name of a type"""
    try:
        module = getattr(obj, "__module__", None)
        qualname = getattr(obj, "__qualname__", None)
        if module and qualname:
            return f"{module}.{qualname}"
        return getattr(obj, "__name__", str(obj))
    except Exception as e:
        LOG.debug("Unable to compute the FQN for '%s': %s", obj, e)
        return str(obj)


def is_internal_class(_type: TypeHint, module_prefixes: list[str] | None = None) -> bool:
    """
    We define a simple heuristic for internal classes by simply looking at the prefix of the module.
    """
    module_prefixes = module_prefixes or INTERNAL_MODULE_PREFIXES
    module = getattr(_type, "__module__", None)
    if not module:
        return False
    if any(str(module).startswith(prefix) for prefix in module_prefixes):
        return True
    return False


class StoreSchemaBuilder:
    """
    This class builds a schema for a ``BaseStore`` class by recursively parsing its type hints.

    Example::

        class SqsStore(BaseStore):
            attribute1: dict[str, str] = CrossRegionAttribute(default=dict)
            attribute2: dict[str, dict[str, int]] = CrossRegionAttribute(default=dict)

        ssb = StoreSchemaBuilder(SqsStore)
        schema = ssb.build_schema()
        pprint(schema)
        >>
        {
          "type": "localstack.services.sqs.models.SqsStore",
          "localstack_version": "4.6.1.dev70",
          "attributes": {
            "attribute1": {
              "LS/TYPE": "builtins.dict",
              "LS/HINTS": [
                "builtins.str",
                "builtins.str"
              ]
            },
            "attribute2": {
              "LS/TYPE": "builtins.dict",
              "LS/HINTS": [
                "builtins.str",
                {
                  "LS/TYPE": "builtins.dict",
                  "LS/HINTS": [
                    "builtins.str",
                    "builtins.int"
                  ]
                }
              ]
            }
          },
          "additional_classes": {}
        }


    When a custom class if found as a type hint for store attribute, that class is also examined.

    Examples::

        class MessageMoveTask:
            destination_arn: str
            source_arn: str | None = None

        class SqsStore(BaseStore):
            attribute1: dict[str, str] = CrossRegionAttribute(default=dict)
            move_tasks: dict[str, MessageMoveTask] = CrossRegionAttribute(default=dict)

        ssb = StoreSchemaBuilder(SqsStore)
        schema = ssb.build_schema()
        pprint(schema)
        >>
        {
          "type": "localstack.services.sqs.models.SqsStore",
          "localstack_version": "4.6.1.dev70",
          "attributes": {
            "attribute1": {
              "LS/TYPE": "builtins.dict",
              "LS/HINTS": [
                "builtins.str",
                "builtins.str"
              ]
            },
            "move_tasks": {
              "LS/TYPE": "builtins.dict",
              "LS/HINTS": [
                "builtins.str",
                "localstack.services.sqs.models.MessageMoveTask"
              ]
            }
          },
          "additional_classes": {
            "localstack.services.sqs.models.MessageMoveTask": {
              "destination_arn": "builtins.str",
              "source_arn": {
                "LS/TYPE": "types.UnionType",
                "LS/HINTS": [
                  "builtins.str",
                  "builtins.NoneType"
                ]
              }
            }
          }
        }
    """

    skip_attributes = list(BaseStore.__annotations__.keys())
    """Set of attributes that are not serialized into a schema"""

    def __init__(self, store_type: type) -> None:
        self.store_type = store_type
        self.schema = StoreSchema(
            type=get_fully_qualified_name(store_type),
            localstack_version=VERSION,
            attributes={},
            additional_classes={},
        )

    def build_schema(self) -> StoreSchema:
        self.schema["attributes"] = self._attribute_schema(self.store_type, self.skip_attributes)
        return self.schema

    def _attribute_schema(self, _type: type, skip_attributes: list[str]) -> AttributeSchema:
        """Computes the schema of the attributes for a type using its type hints"""
        try:
            class_var_hints = typing.get_type_hints(_type)
        except NameError as e:
            LOG.debug("An error occurred while getting the type hints for '%s': %s", _type, e)
            return {}
        class_var_hints = {k: v for k, v in class_var_hints.items() if k not in skip_attributes}

        _attributes = {}
        for name, type_hint in class_var_hints.items():
            _attributes[name] = self._serialize_hint(type_hint)
        return _attributes

    def _serialize_hint(self, type_hint: TypeHint) -> SerializedHint:
        """
        Tries to serialize type information for a given type. If the type is subscribed, it fetches its args and
        recursively tries to serialize them.
        """
        origin = typing.get_origin(type_hint)

        # If origin is None, we are dealing with a base type and we return its fully qualified name
        if not origin:
            fqn = get_fully_qualified_name(type_hint)
            # This type is a custom one and has already been visited. We avoid infinite recursion.
            if fqn in self.schema["additional_classes"]:
                return fqn
            if is_internal_class(type_hint):
                # We add in advance the FQN of this class to the keys of ``additional_classes`` in case ``type_hint``
                #   fields point recursively to ``type_hint`` itself.
                self.schema["additional_classes"][fqn] = {}
                self.schema["additional_classes"][fqn] = self._attribute_schema(type_hint, [])
            return fqn

        match origin:
            case builtins.dict:
                _hint = {TAG_TYPE: get_fully_qualified_name(origin)}
                args = typing.get_args(type_hint)
                if len(args) == 2:
                    _hint[TAG_ARGS] = [self._serialize_hint(args[0]), self._serialize_hint(args[1])]
                # If the hints are incomplete, e.g., ``dict[str]``, we just return the FQN, i.e., ```builtins.dict```
                return _hint
            case builtins.list | builtins.set:
                _hint = {TAG_TYPE: get_fully_qualified_name(origin)}
                args = typing.get_args(type_hint)
                if args:
                    _hint[TAG_ARGS] = [self._serialize_hint(args[0])]
                return _hint
            case types.UnionType | typing.Union | typing.Tuple | builtins.tuple:
                _hint = {TAG_TYPE: get_fully_qualified_name(origin)}
                args = typing.get_args(type_hint)
                if args:
                    _hint[TAG_ARGS] = [self._serialize_hint(_arg) for _arg in args]
                return _hint
            case _:
                # A few things that can end up here: generics, or Literal. See ``get_origin`` for more.
                return get_fully_qualified_name(origin)
