"""
AWS docs (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html):

The following requirements apply when using parameters:

    You can have a maximum of 200 parameters in an AWS CloudFormation template.
    Each parameter must be given a logical name (also called logical ID), which must be alphanumeric and unique among all logical names within the template.
    Each parameter must be assigned a parameter type that is supported by AWS CloudFormation. For more information, see Type.
    Each parameter must be assigned a value at runtime for AWS CloudFormation to successfully provision the stack. You can optionally specify a default value for AWS CloudFormation to use unless another value is provided.
    Parameters must be declared and referenced from within the same template. You can reference parameters from the Resources and Outputs sections of the template.



    When you create or update stacks and create change sets, AWS CloudFormation uses whatever values exist in Parameter Store at the time the operation is run. If a specified parameter doesn't exist in Parameter Store under the caller's AWS account, AWS CloudFormation returns a validation error.

    For stack updates, the Use existing value option in the console and the UsePreviousValue attribute for update-stack tell AWS CloudFormation to use the existing Systems Manager parameter key—not its value. AWS CloudFormation always fetches the latest values from Parameter Store when it updates stacks.


    TODO: ordering & grouping of parameters
    TODO: design proper structure for parameters to facilitate validation etc.
    TODO: clearer language around both parameters and "resolving"
"""
from typing import Literal, Optional, TypedDict

from localstack.aws.api.cloudformation import Parameter, ParameterDeclaration
from localstack.aws.connect import connect_to


def resolve_parameters(
    parameter_declarations: dict[str, ParameterDeclaration],
    new_parameters: dict[str, Parameter],
    old_parameters: dict[str, Parameter],
) -> dict[str, Parameter]:
    """
    Resolves stack parameters or raises an exception if any parameter can not be resolved.

    Assumptions:
        - There are no extra undeclared parameters given (validate before calling this method)

    TODO: does "UsePreviousValue" refer to the value or the resolved value? Will an update stack do a new lookup on the same parameter if it has been updated since?
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
        resolved_param = Parameter(ParameterKey=pm_key)
        new_parameter = new_parameters.get(pm_key)
        old_parameter = old_parameters.get(pm_key)

        if new_parameter is None:
            # since no value has been specified for the deployment, we need to be able to resolve the default or fail
            default_value = pm["DefaultValue"]
            if default_value is None:
                raise Exception("Invalid. Needs to have either param specified or Default. todo")

            resolved_param["ParameterValue"] = default_value
        else:
            if (
                new_parameter.get("UsePreviousValue", False)
                and new_parameter.get("ParameterValue") is not None
            ):
                raise Exception("Can't use both previous value and specifying one. todo")

            if new_parameter.get("UsePreviousValue", False):
                if old_parameter is None:
                    raise Exception("no previous value :(")

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
                # TODO: error handling
                resolved_param["ResolvedValue"] = resolve_dynamic_parameter(
                    resolved_param["ParameterValue"]
                )
            else:
                raise Exception(f"Unsupported stack parameter type: {pm['ParameterType']}")

    return resolved_parameters


# TODO: inject credentials / client factory for proper account/region lookup
def resolve_dynamic_parameter(parameter_value: str) -> str:
    """
    Resolve the SSM stack parameter with the name specified via the given `parameter_value`.

    Given a stack template with parameter {"param1": {"Type": "AWS::SSM::Parameter::Value<String>"}} and
    a stack instance with stack parameter {"ParameterKey": "param1", "ParameterValue": "test-param"}, this
    function will resolve the SSM parameter with name `test-param` and return the SSM parameter's value.
    """
    return connect_to().ssm.get_parameter(Name=parameter_value)["Parameter"]["Value"]


def convert_stack_parameters_to_list(in_params: dict[str, Parameter]) -> list[Parameter]:
    return list(in_params.values())


def convert_stack_parameters_to_dict(in_params: list[Parameter]) -> dict[str, Parameter]:
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


def map_to_legacy_structure(parameter_type: str, new_parameter: Parameter) -> LegacyParameter:
    return LegacyParameter(
        LogicalResourceId=new_parameter["ParameterKey"],
        Type="Parameter",
        Properties=LegacyParameterProperties(
            ParameterType=parameter_type,
            ParameterValue=new_parameter.get("ParameterValue"),
            ResolvedValue=new_parameter.get("ResolvedValue"),
            Value=new_parameter.get("ResolvedValue", new_parameter.get("ParameterValue")),
        ),
    )


def extract_parameter_declarations_from_template(template: dict) -> dict[str, ParameterDeclaration]:
    if "Parameters" not in template:
        return {}

    result = {}

    for param_key, param in template["Parameters"].items():
        result[param_key] = ParameterDeclaration(
            ParameterKey=param_key,
            DefaultValue=param.get("Default"),
            ParameterType=param.get("Type"),
            # TODO: rest
        )

    return result
