from collections import OrderedDict

from localstack.services.cloudformation.engine.changes import ChangeConfig
from localstack.services.cloudformation.engine.parameters import StackParameter
from localstack.services.cloudformation.engine.template_utils import get_deps_for_resource


class NoResourceInStack(ValueError):
    """Raised when we preprocess the template and do not find a resource"""

    def __init__(self, logical_resource_id: str):
        msg = f"Template format error: Unresolved resource dependencies [{logical_resource_id}] in the Resources block of the template"

        super().__init__(msg)


def order_resources(
    resources: dict,
    resolved_parameters: dict[str, StackParameter],
    resolved_conditions: dict[str, bool],
    reverse: bool = False,
) -> OrderedDict:
    """
    Given a dictionary of resources, topologically sort the resources based on
    inter-resource dependencies (e.g. usages of intrinsic functions).
    """
    nodes: dict[str, list[str]] = {}
    for logical_resource_id, properties in resources.items():
        nodes.setdefault(logical_resource_id, [])
        deps = get_deps_for_resource(properties, resolved_conditions)
        for dep in deps:
            if dep in resolved_parameters:
                # we only care about other resources
                continue
            nodes.setdefault(dep, [])
            nodes[dep].append(logical_resource_id)

    # implementation from https://dev.to/leopfeiffer/topological-sort-with-kahns-algorithm-3dl1
    indegrees = dict.fromkeys(nodes.keys(), 0)
    for dependencies in nodes.values():
        for dependency in dependencies:
            indegrees[dependency] += 1

    # Place all elements with indegree 0 in queue
    queue = [k for k in nodes.keys() if indegrees[k] == 0]

    sorted_logical_resource_ids = []

    # Continue until all nodes have been dealt with
    while len(queue) > 0:
        # node of current iteration is the first one from the queue
        curr = queue.pop(0)
        sorted_logical_resource_ids.append(curr)

        # remove the current node from other dependencies
        for dependency in nodes[curr]:
            indegrees[dependency] -= 1

            if indegrees[dependency] == 0:
                queue.append(dependency)

    # check for circular dependencies
    if len(sorted_logical_resource_ids) != len(nodes):
        raise Exception("Circular dependency found.")

    sorted_mapping = []
    for logical_resource_id in sorted_logical_resource_ids:
        if properties := resources.get(logical_resource_id):
            sorted_mapping.append((logical_resource_id, properties))
        else:
            if (
                logical_resource_id not in resolved_parameters
                and logical_resource_id not in resolved_conditions
            ):
                raise NoResourceInStack(logical_resource_id)

    if reverse:
        sorted_mapping = sorted_mapping[::-1]
    return OrderedDict(sorted_mapping)


def order_changes(
    given_changes: list[ChangeConfig],
    resources: dict,
    resolved_parameters: dict[str, StackParameter],
    # TODO: remove resolved conditions somehow
    resolved_conditions: dict[str, bool],
    reverse: bool = False,
) -> list[ChangeConfig]:
    """
    Given a list of changes, a dictionary of resources and a dictionary of resolved conditions, topologically sort the
    changes based on inter-resource dependencies (e.g. usages of intrinsic functions).
    """
    ordered_resources = order_resources(
        resources=resources,
        resolved_parameters=resolved_parameters,
        resolved_conditions=resolved_conditions,
        reverse=reverse,
    )
    sorted_changes = []
    for logical_resource_id in ordered_resources.keys():
        for change in given_changes:
            if change["ResourceChange"]["LogicalResourceId"] == logical_resource_id:
                sorted_changes.append(change)
                break
    assert len(sorted_changes) > 0
    if reverse:
        sorted_changes = sorted_changes[::-1]
    return sorted_changes
