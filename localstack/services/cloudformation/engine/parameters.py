"""
TODO: ordering & grouping of parameters
TODO: design proper structure for parameters to facilitate validation etc.
TODO: clearer language around both parameters and "resolving"

Documentation extracted from AWS docs (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html):
    The following requirements apply when using parameters:

        You can have a maximum of 200 parameters in an AWS CloudFormation template.
        Each parameter must be given a logical name (also called logical ID), which must be alphanumeric and unique among all logical names within the template.
        Each parameter must be assigned a parameter type that is supported by AWS CloudFormation. For more information, see Type.
        Each parameter must be assigned a value at runtime for AWS CloudFormation to successfully provision the stack. You can optionally specify a default value for AWS CloudFormation to use unless another value is provided.
        Parameters must be declared and referenced from within the same template. You can reference parameters from the Resources and Outputs sections of the template.

        When you create or update stacks and create change sets, AWS CloudFormation uses whatever values exist in Parameter Store at the time the operation is run. If a specified parameter doesn't exist in Parameter Store under the caller's AWS account, AWS CloudFormation returns a validation error.

        For stack updates, the Use existing value option in the console and the UsePreviousValue attribute for update-stack tell AWS CloudFormation to use the existing Systems Manager parameter key—not its value. AWS CloudFormation always fetches the latest values from Parameter Store when it updates stacks.

"""
from typing import Literal, Optional, TypedDict

from localstack.aws.api.cloudformation import Parameter, ParameterDeclaration
from localstack.aws.connect import connect_to


def extract_stack_parameter_declarations(template: dict) -> dict[str, ParameterDeclaration]:
    """
    Extract and build a dict of stack parameter declarations from a CloudFormation stack templatef

    :param template: the parsed CloudFormation stack template
    :return: a dictionary of declared parameters, mapping logical IDs to the corresponding parameter declaration
    """
    result = {}
    for param_key, param in template.get("Parameters", {}).items():
        result[param_key] = ParameterDeclaration(
            ParameterKey=param_key,
            DefaultValue=param.get("Default"),
            ParameterType=param.get("Type"),
            # TODO: test & implement rest here
            # NoEcho=?,
            # ParameterConstraints=?,
            # Description=?
        )
    return result


class StackParameter(Parameter):
    # we need the type information downstream when actually using the resolved value
    # e.g. in case of lists so that we know that we should interpret the string as a comma-separated list.
    ParameterType: str


def resolve_parameters(
    parameter_declarations: dict[str, ParameterDeclaration],
    new_parameters: dict[str, Parameter],
    old_parameters: dict[str, Parameter],
) -> dict[str, StackParameter]:
    """
    Resolves stack parameters or raises an exception if any parameter can not be resolved.

    Assumptions:
        - There are no extra undeclared parameters given (validate before calling this method)

    TODO: is UsePreviousValue=False equivalent to not specifying it, in all situations?

    :param parameter_declarations: The parameter declaration from the (potentially new) template, i.e. the "Parameters" section
    :param new_parameters: The parameters to resolve
    :param old_parameters: The old parameters from the previous stack deployment, if available
    :return: a copy of new_parameters with resolved values
    """
    resolved_parameters = dict()

    # populate values for every parameter declared in the template
    for pm in parameter_declarations.values():
        pm_key = pm["ParameterKey"]
        resolved_param = StackParameter(ParameterKey=pm_key, ParameterType=pm["ParameterType"])
        new_parameter = new_parameters.get(pm_key)
        old_parameter = old_parameters.get(pm_key)

        if new_parameter is None:
            # since no value has been specified for the deployment, we need to be able to resolve the default or fail
            default_value = pm["DefaultValue"]
            if default_value is None:
                raise Exception(
                    "Invalid. Needs to have either param specified or Default. (TODO)"
                )  # TODO: test and verify

            resolved_param["ParameterValue"] = default_value
        else:
            if (
                new_parameter.get("UsePreviousValue", False)
                and new_parameter.get("ParameterValue") is not None
            ):
                raise Exception(
                    "Can't set both 'UsePreviousValue' and a concrete value. (TODO)"
                )  # TODO: test and verify

            if new_parameter.get("UsePreviousValue", False):
                if old_parameter is None:
                    raise Exception(
                        "Set 'UsePreviousValue' but stack has no previous value for this parameter. (TODO)"
                    )  # TODO: test and verify

                resolved_param["ParameterValue"] = old_parameter["ParameterValue"]
            else:
                resolved_param["ParameterValue"] = new_parameter["ParameterValue"]

        resolved_parameters[pm_key] = resolved_param

        # Note that SSM parameters always need to be resolved anew here
        # TODO: support more parameter types
        if pm["ParameterType"].startswith("AWS::SSM"):
            if pm["ParameterType"] in [
                "AWS::SSM::Parameter::Value<String>",
                "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
            ]:
                # TODO: error handling (e.g. no permission to lookup SSM parameter or SSM parameter doesn't exist)
                resolved_param["ResolvedValue"] = resolve_ssm_parameter(
                    resolved_param["ParameterValue"]
                )
            else:
                raise Exception(f"Unsupported stack parameter type: {pm['ParameterType']}")

    return resolved_parameters


# TODO: inject credentials / client factory for proper account/region lookup
def resolve_ssm_parameter(stack_parameter_value: str) -> str:
    """
    Resolve the SSM stack parameter from the SSM service with a name equal to the stack parameter value.
    """
    return connect_to().ssm.get_parameter(Name=stack_parameter_value)["Parameter"]["Value"]


def strip_parameter_type(in_param: StackParameter) -> Parameter:
    result = in_param.copy()
    result.pop("ParameterType", None)
    return result


def convert_stack_parameters_to_list(
    in_params: dict[str, StackParameter] | None
) -> list[StackParameter]:
    if not in_params:
        return []
    return list(in_params.values())


def convert_stack_parameters_to_dict(in_params: list[Parameter] | None) -> dict[str, Parameter]:
    if not in_params:
        return {}
    return {p["ParameterKey"]: p for p in in_params}


class LegacyParameterProperties(TypedDict):
    Value: str
    ParameterType: str
    ParameterValue: Optional[str]
    ResolvedValue: Optional[str]


class LegacyParameter(TypedDict):
    LogicalResourceId: str
    Type: Literal["Parameter"]
    Properties: LegacyParameterProperties


# TODO: not actually parameter_type but the logical "ID"
def map_to_legacy_structure(parameter_name: str, new_parameter: StackParameter) -> LegacyParameter:
    """
    Helper util to convert a normal (resolved) stack parameter to a legacy parameter structure that can then be merged with stack resources.

    :param new_parameter: a resolved stack parameter
    :return: legacy parameter that can be merged with stack resources for uniform lookup based on logical ID
    """
    return LegacyParameter(
        LogicalResourceId=new_parameter["ParameterKey"],
        Type="Parameter",
        Properties=LegacyParameterProperties(
            ParameterType=new_parameter.get("ParameterType"),
            ParameterValue=new_parameter.get("ParameterValue"),
            ResolvedValue=new_parameter.get("ResolvedValue"),
            Value=new_parameter.get("ResolvedValue", new_parameter.get("ParameterValue")),
        ),
    )
