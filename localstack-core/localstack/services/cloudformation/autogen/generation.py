import logging

from localstack.services.cloudformation.autogen.specs import (
    ResourceProviderDefinition,
)
from localstack.services.cloudformation.autogen.visitors.base import Resource, Visitor

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
