import random
from typing import Any

from localstack.services.cloudformation.autogen.specs import ResourceProviderDefinition
from localstack.services.cloudformation.autogen.visitors.base import Visitor


class DynamoDBTableVisitor(Visitor):
    def __init__(self, spec: ResourceProviderDefinition):
        super().__init__(spec)

        def random_attribute_name() -> str:
            return self._gen_property_string("AttributeName", {"type": "string"})

        self.keys = {
            random_attribute_name(): {
                "type": "S",
                "key_type": "HASH",
            },
        }
        if random.uniform(0.0, 1.0) < 0.5:
            self.keys[random_attribute_name()] = {
                "type": "S",
                "key_type": "RANGE",
            }

    def _visit_property_definition(self, name: str, property_definition: dict) -> Any:
        match name:
            case "KeySchema":
                return [
                    {"AttributeName": k, "KeyType": v["key_type"]} for (k, v) in self.keys.items()
                ]
            case "AttributeDefinitions":
                return [
                    {"AttributeName": k, "AttributeType": v["type"]} for (k, v) in self.keys.items()
                ]
            case "BillingMode":
                return "PAY_PER_REQUEST"

        return super()._visit_property_definition(name, property_definition)
