import logging
import random

from localstack.services.cloudformation.autogen import patches, specs
from localstack.services.cloudformation.autogen.specs import (
    ResourceProviderDefinition,
)
from localstack.services.cloudformation.autogen.visitors.base import (
    Resource,
    Visitor,
    random_short_string,
)

LOG = logging.getLogger(__name__)


def visitor_factory(spec: ResourceProviderDefinition) -> Visitor:
    match spec["typeName"]:
        case "AWS::DynamoDB::Table":
            from localstack.services.cloudformation.autogen.visitors.dynamodb_table import (
                DynamoDBTableVisitor,
            )

            return DynamoDBTableVisitor(spec)

    return Visitor(spec)


def generate_resource_from_spec(
    spec: ResourceProviderDefinition, include_optionals: bool = False
) -> Resource:
    properties = visitor_factory(spec).get(include_optionals)
    if properties:
        return {"Type": spec["typeName"], "Properties": properties}
    else:
        return {"Type": spec["typeName"]}


def generate_resources_from_spec(
    resource_whitelist: list[str] | None = None,
    resource_count: tuple[int, int] = (1, 5),
) -> dict:
    spec_cache: dict[str, ResourceProviderDefinition] = {}

    resources = {}
    for _ in range(*resource_count):
        resource_name = random_short_string()
        current_resource_type = random.choice(resource_whitelist)
        if current_resource_type not in spec_cache:
            spec = specs.read_spec_for(current_resource_type)
            spec = patches.apply_patch_for(spec)
            spec_cache[current_resource_type] = spec

        spec = spec_cache[current_resource_type]
        resource = generate_resource_from_spec(spec, False)
        resources[resource_name] = resource

    return resources
