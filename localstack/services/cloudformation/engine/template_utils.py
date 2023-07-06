import re
from typing import Any

from localstack.aws.accounts import get_aws_account_id
from localstack.services.cloudformation.deployment_utils import PLACEHOLDER_AWS_NO_VALUE
from localstack.utils.aws import aws_stack

# TODO: deduplicate
AWS_URL_SUFFIX = "localhost.localstack.cloud"


def get_deps_for_resource(resource: dict, evaluated_conditions: dict[str, bool]) -> set[str]:
    deps = set()
    deps = deps.union(resolve_dependencies(resource.get("Properties", {}), evaluated_conditions))
    deps = deps.union(resource.get("DependsOn", []))
    return deps


def resolve_dependencies(d: dict, evaluated_conditions: dict[str, bool]) -> set[str]:
    # TODO: depends on
    items = set()

    if isinstance(d, dict):
        for k, v in d.items():
            if k == "Fn::If":
                # check the condition and only traverse down the correct path
                condition_name, true_value, false_value = v
                try:
                    if evaluated_conditions[condition_name]:
                        items = items.union(resolve_dependencies(true_value, evaluated_conditions))
                    else:
                        items = items.union(resolve_dependencies(false_value, evaluated_conditions))
                except Exception as e:
                    # TODO: remove try/except block
                    print(e)
            elif k == "Ref":
                items.add(v)
            elif k == "Fn::GetAtt":
                items.add(v[0])
            elif k == "Fn::Sub":
                # we can assume anything in there is a ref
                if isinstance(v, str):
                    variables_found = re.findall("\\${([^}]+)}", v)
                    for var in variables_found:
                        if "." in var:
                            var = var.split(".")[0]
                        items.add(var)
                elif isinstance(v, list):
                    variables_found = re.findall("\\${([^}]+)}", v[0])
                    for var in variables_found:
                        if "." in var:
                            var = var.split(".")[0]
                        elif var in v[1]:
                            # don't add if its included in the mapping
                            continue
                        items.add(var)
                else:
                    raise Exception(f"Invalid template structure in Fn::Sub: {v}")
            elif isinstance(v, dict):
                items = items.union(resolve_dependencies(v, evaluated_conditions))
            elif isinstance(v, list):
                for item in v:
                    # TODO: assumption that every element is a dict might not be true
                    items = items.union(resolve_dependencies(item, evaluated_conditions))
            else:
                pass

    return {i for i in items if not i.startswith("AWS::")}


def resolve_stack_conditions(
    conditions: dict, parameters: dict, mappings: dict, stack_name: str
) -> dict[str, bool]:
    """
    Within each condition, you can reference another:
        condition
        parameter value
        mapping

    You can use the following intrinsic functions to define conditions:
        Fn::And
        Fn::Equals
        Fn::If
        Fn::Not
        Fn::Or

    TODO: more checks on types from references (e.g. in a mapping value)
    TODO: does a ref ever return a non-string value?
    TODO: when unifying/reworking intrinsic functions rework this to a class structure
    """
    result = {}
    for condition_name, condition in conditions.items():
        result[condition_name] = resolve_condition(
            condition, conditions, parameters, mappings, stack_name
        )
    return result


def resolve_pseudo_parameter(pseudo_parameter: str, stack_name: str) -> Any:
    """
    TODO: this function needs access to more stack context
    """
    # pseudo parameters
    match pseudo_parameter:
        case "AWS::Region":
            return aws_stack.get_region()
        case "AWS::Partition":
            return "aws"
        case "AWS::StackName":
            return stack_name
        case "AWS::StackId":
            # TODO return proper stack id!
            return stack_name
        case "AWS::AccountId":
            return get_aws_account_id()
        case "AWS::NoValue":
            return PLACEHOLDER_AWS_NO_VALUE
        case "AWS::NotificationARNs":
            # TODO!
            return {}
        case "AWS::URLSuffix":
            return AWS_URL_SUFFIX


def resolve_condition(condition, conditions, parameters, mappings, stack_name):
    if isinstance(condition, dict):
        for k, v in condition.items():
            match k:
                case "Ref":
                    if isinstance(v, str) and v.startswith("AWS::"):
                        return resolve_pseudo_parameter(
                            v, stack_name
                        )  # TODO: this pseudo parameter resolving needs context(!)
                    # TODO: add util function for resolving individual refs (e.g. one util for resolving pseudo parameters)
                    # TODO: pseudo-parameters like AWS::Region
                    # can only really be a parameter here
                    # TODO: how are conditions references written here? as {"Condition": "ConditionA"} or via Ref?
                    # TODO: test for a boolean parameter?
                    param = parameters[v]
                    return param[
                        "ParameterValue"
                    ]  # TODO: extend this logic, e.g. what about lists, other types, ... why is string interpreted as a boolean?
                    # return parameters[v]
                case "Fn::FindInMap":
                    map_name, top_level_key, second_level_key = v
                    return mappings[map_name][top_level_key][second_level_key]
                case "Fn::If":
                    if_condition_name, true_branch, false_branch = v
                    if resolve_condition(
                        if_condition_name, conditions, parameters, mappings, stack_name
                    ):
                        return resolve_condition(
                            true_branch, conditions, parameters, mappings, stack_name
                        )
                    else:
                        return resolve_condition(
                            false_branch, conditions, parameters, mappings, stack_name
                        )
                case "Fn::Not":
                    return not resolve_condition(v[0], conditions, parameters, mappings, stack_name)
                case "Fn::And":
                    # TODO: should actually restrict this a bit
                    return resolve_condition(
                        v[0], conditions, parameters, mappings, stack_name
                    ) and resolve_condition(v[1], conditions, parameters, mappings, stack_name)
                case "Fn::Or":
                    return resolve_condition(
                        v[0], conditions, parameters, mappings, stack_name
                    ) or resolve_condition(v[1], conditions, parameters, mappings, stack_name)
                case "Fn::Equals":
                    return resolve_condition(
                        v[0], conditions, parameters, mappings, stack_name
                    ) == resolve_condition(v[1], conditions, parameters, mappings, stack_name)
    else:
        return condition
