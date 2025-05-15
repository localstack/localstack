import logging
import random
import string
from typing import Any, Final

from localstack.services.cloudformation.autogen.specs import (
    ArrayProperty,
    BooleanProperty,
    IntegerProperty,
    ObjectProperty,
    ResourceProviderDefinition,
    StringProperty,
)
from localstack.services.cloudformation.scaffolding.__main__ import resolve_ref

LOG = logging.getLogger(__name__)

Resource = dict[str, Any]


def random_short_string(count: int = 10, character_set: str = string.ascii_letters) -> str:
    return "".join(random.choices(character_set, k=count))


class Visitor:
    resource_type: Final[str]
    definition: Resource

    def __init__(self, spec: ResourceProviderDefinition):
        self.spec = spec
        self.resource_type = spec["typeName"]
        self.definition = {}

        # internal tracking state
        self._added_fields: set[str] = set()

    def visit(self, include_optionals: bool):
        self.definition.clear()

        self._visit_required()
        if include_optionals:
            num_optional = random.randint(0, self.num_optional_fields)
            for _ in range(num_optional):
                self._add_optional()

    def get(self, include_optionals: bool) -> Resource:
        self.visit(include_optionals)
        return self.definition

    def _visit_required(self):
        for field_name in self.required_field_names:
            property_definition = self.spec["properties"][field_name]
            value = self._visit_property_definition(field_name, property_definition)
            self._set_value(field_name, value)

    def _add_optional(self):
        remaining_properties = (
            set(self.spec["properties"].keys())
            - set(self.required_field_names)
            - self._added_fields
        )
        chosen_prop_name = random.choice(list(remaining_properties))
        property_definition = self.spec["properties"][chosen_prop_name]
        value = self._visit_property_definition(chosen_prop_name, property_definition)
        self._set_value(chosen_prop_name, value)

    def _visit_property_definition(self, name: str, property_definition: dict) -> Any:
        LOG.debug("Visiting property '%s'", name)
        if property_type := property_definition.get("type"):
            method_name = f"_gen_property_{property_type}"
            method = getattr(self, method_name, None)
            if not method:
                raise NotImplementedError(
                    f"No visit method '{method_name}' found for spec '{property_definition}'"
                )
            return method(name, property_definition)
        elif definition_path := property_definition.get("$ref"):
            # we need to look up the property from the definitions array
            definition = resolve_ref(self.spec, definition_path)

            try:
                return self._visit_property_definition(name, definition)
            except KeyError:
                raise RuntimeError(f"Missing field 'properties' in definition '{definition}'")
        elif one_of := property_definition.get("oneOf"):
            definition = random.choice(one_of)
            return self._visit_property_definition(name, definition)
        else:
            raise NotImplementedError(f"Unhandled definition: {property_definition}")

    @property
    def num_optional_fields(self) -> int:
        num_required_fields = len(self.required_field_names)
        total_num_fields = len(self.spec["properties"])
        return total_num_fields - num_required_fields

    @property
    def required_field_names(self) -> list[str]:
        return self.spec.get("required", [])

    def _gen_property_string(self, name, property_definition: StringProperty) -> str:
        assert property_definition["type"] == "string"
        if allowed_values := property_definition.get("enum"):
            return random.choice(allowed_values)
        else:
            return random_short_string()

    def _gen_property_array(self, name: str, property_definition: ArrayProperty) -> list[Any]:
        result = []

        if item_ref := property_definition.get("items"):
            for _ in range(random.randint(1, 3)):
                value = self._visit_property_definition(name, item_ref)
                result.append(value)
        else:
            raise NotImplementedError

        return result

    def _gen_property_boolean(self, name: str, property_definition: BooleanProperty) -> bool:
        return random.uniform(0.0, 1.0) < 0.5

    def _gen_property_integer(self, name: str, property_definition: IntegerProperty) -> int:
        return random.randint(0, 100)

    def _gen_property_object(
        self, name: str, property_definition: ObjectProperty
    ) -> dict[str, Any]:
        result = {}
        if required_prop_names := property_definition.get("required"):
            for prop_name in required_prop_names:
                prop_defn = property_definition["properties"][prop_name]
                value = self._visit_property_definition(prop_name, prop_defn)
                result[prop_name] = value
        else:
            for prop_name, prop_defn in property_definition.get("properties", {}).items():
                value = self._visit_property_definition(prop_name, prop_defn)
                result[prop_name] = value
        return result

    def _set_value(self, name: str, value: str):
        self.definition[name] = value
        self._added_fields.add(name)
