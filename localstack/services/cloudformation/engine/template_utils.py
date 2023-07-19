import re
from typing import Any

from localstack.aws.accounts import get_aws_account_id
from localstack.services.cloudformation.deployment_utils import PLACEHOLDER_AWS_NO_VALUE
from localstack.utils.aws import aws_stack

# TODO: deduplicate
AWS_URL_SUFFIX = "localhost.localstack.cloud"


def get_deps_for_resource(resource: dict, evaluated_conditions: dict[str, bool]) -> set[str]:
    """
    :param resource: the resource definition to be checked for dependencies
    :param evaluated_conditions:
    :return: a set of logical resource IDs which this resource depends on
    """
    property_dependencies = resolve_dependencies(
        resource.get("Properties", {}), evaluated_conditions
    )
    explicit_dependencies = resource.get("DependsOn", [])
    if not isinstance(explicit_dependencies, list):
        explicit_dependencies = [explicit_dependencies]
    return property_dependencies.union(explicit_dependencies)


def resolve_dependencies(d: dict, evaluated_conditions: dict[str, bool]) -> set[str]:
    items = set()

    if isinstance(d, dict):
        for k, v in d.items():
            if k == "Fn::If":
                # check the condition and only traverse down the correct path
                condition_name, true_value, false_value = v
                if evaluated_conditions[condition_name]:
                    items = items.union(resolve_dependencies(true_value, evaluated_conditions))
                else:
                    items = items.union(resolve_dependencies(false_value, evaluated_conditions))
            elif k == "Ref":
                items.add(v)
            elif k == "Fn::GetAtt":
                items.add(v[0])
            elif k == "Fn::Sub":
                # we can assume anything in there is a ref
                if isinstance(v, str):
                    # { "Fn::Sub" : "Hello ${Name}" }
                    variables_found = re.findall("\\${([^}]+)}", v)
                    for var in variables_found:
                        if "." in var:
                            var = var.split(".")[0]
                        items.add(var)
                elif isinstance(v, list):
                    # { "Fn::Sub" : [ "Hello ${Name}", { "Name": "SomeName" } ] }
                    variables_found = re.findall("\\${([^}]+)}", v[0])
                    for var in variables_found:

                        if var in v[1]:
                            # variable is included in provided mapping and can either be a static value or another reference
                            if isinstance(v[1][var], dict):
                                # e.g. { "Fn::Sub" : [ "Hello ${Name}", { "Name": {"Ref": "NameParam"} } ] }
                                #   the values can have references, so we need to go deeper
                                items = items.union(
                                    resolve_dependencies(v[1][var], evaluated_conditions)
                                )
                        else:
                            # it's now either a GetAtt call or a direct reference
                            if "." in var:
                                var = var.split(".")[0]
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
                    parameter_type: str = param["ParameterType"]
                    parameter_value = param.get("ResolvedValue") or param.get("ParameterValue")

                    if parameter_type in ["CommaDelimitedList"] or parameter_type.startswith(
                        "List<"
                    ):
                        return [p.strip() for p in parameter_value.split(",")]
                    else:
                        return parameter_value

                case "Condition":
                    return resolve_condition(
                        conditions[v], conditions, parameters, mappings, stack_name
                    )
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
                    left = resolve_condition(v[0], conditions, parameters, mappings, stack_name)
                    right = resolve_condition(v[1], conditions, parameters, mappings, stack_name)
                    return fn_equals_type_conversion(left) == fn_equals_type_conversion(right)
                case "Fn::Join":
                    join_list = v[1]
                    if isinstance(v[1], dict):
                        join_list = resolve_condition(
                            v[1], conditions, parameters, mappings, stack_name
                        )
                    result = v[0].join(
                        [
                            resolve_condition(x, conditions, parameters, mappings, stack_name)
                            for x in join_list
                        ]
                    )
                    return result
                case "Fn::Sub":
                    # we can assume anything in there is a ref
                    if isinstance(v, str):
                        # { "Fn::Sub" : "Hello ${Name}" }
                        result = v
                        variables_found = re.findall("\\${([^}]+)}", v)
                        for var in variables_found:
                            # can't be a resource here (!), so also not attribute access
                            if var.startswith("AWS::"):
                                # pseudo-parameter
                                resolved_pseudo_param = resolve_pseudo_parameter(var, stack_name)
                                result = result.replace(f"${{{var}}}", resolved_pseudo_param)
                            else:
                                # parameter
                                param = parameters[var]
                                parameter_type: str = param["ParameterType"]
                                resolved_parameter = param.get("ResolvedValue") or param.get(
                                    "ParameterValue"
                                )

                                if parameter_type in [
                                    "CommaDelimitedList"
                                ] or parameter_type.startswith("List<"):
                                    resolved_parameter = [
                                        p.strip() for p in resolved_parameter.split(",")
                                    ]

                                result = result.replace(f"${{{var}}}", resolved_parameter)

                        return result
                    elif isinstance(v, list):
                        # { "Fn::Sub" : [ "Hello ${Name}", { "Name": "SomeName" } ] }
                        result = v[0]
                        variables_found = re.findall("\\${([^}]+)}", v[0])
                        for var in variables_found:
                            if var in v[1]:
                                # variable is included in provided mapping and can either be a static value or another reference
                                if isinstance(v[1][var], dict):
                                    # e.g. { "Fn::Sub" : [ "Hello ${Name}", { "Name": {"Ref": "NameParam"} } ] }
                                    #   the values can have references, so we need to go deeper
                                    resolved_var = resolve_condition(
                                        v[1][var], conditions, parameters, mappings, stack_name
                                    )
                                    result = result.replace(f"${{{var}}}", resolved_var)
                                else:
                                    result = result.replace(f"${{{var}}}", v[1][var])
                            else:
                                # it's now either a GetAtt call or a direct reference
                                if var.startswith("AWS::"):
                                    # pseudo-parameter
                                    resolved_pseudo_param = resolve_pseudo_parameter(
                                        var, stack_name
                                    )
                                    result = result.replace(f"${{{var}}}", resolved_pseudo_param)
                                else:
                                    # parameter
                                    param = parameters[var]
                                    parameter_type: str = param["ParameterType"]
                                    resolved_parameter = param.get("ResolvedValue") or param.get(
                                        "ParameterValue"
                                    )

                                    if parameter_type in [
                                        "CommaDelimitedList"
                                    ] or parameter_type.startswith("List<"):
                                        resolved_parameter = [
                                            p.strip() for p in resolved_parameter.split(",")
                                        ]

                                    result = result.replace(f"${{{var}}}", resolved_parameter)
                        return result
                    else:
                        raise Exception(f"Invalid template structure in Fn::Sub: {v}")
                case _:
                    raise Exception(f"Invalid condition structure encountered: {condition=}")
    else:
        return condition


def fn_equals_type_conversion(value) -> str:
    if isinstance(value, str):
        return value
    elif isinstance(value, bool):
        return "true" if value else "false"
    else:
        return str(value)  # TODO: investigate correct behavior
