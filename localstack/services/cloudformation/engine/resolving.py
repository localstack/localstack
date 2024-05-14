import base64
import json
import logging
import re
from typing import Optional

from localstack import config
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import PLACEHOLDER_AWS_NO_VALUE
from localstack.services.cloudformation.engine.attributes import get_attr_from_model_instance
from localstack.services.cloudformation.engine.conditions import evaluate_resource_condition
from localstack.services.cloudformation.engine.parameters import StackParameter
from localstack.services.cloudformation.engine.template_utils import (
    AWS_URL_SUFFIX,
    fn_equals_type_conversion,
)
from localstack.services.cloudformation.resource_provider import get_resource_type
from localstack.services.cloudformation.service_models import DependencyNotYetSatisfied
from localstack.services.cloudformation.stores import exports_map
from localstack.utils.functions import prevent_stack_overflow
from localstack.utils.strings import to_bytes, to_str
from localstack.utils.urls import localstack_host

LOG = logging.getLogger(__name__)

REGEX_DYNAMIC_REF = re.compile("{{resolve:([^:]+):(.+)}}")

REGEX_OUTPUT_APIGATEWAY = re.compile(
    rf"^(https?://.+\.execute-api\.)(?:[^-]+-){{2,3}}\d\.(amazonaws\.com|{AWS_URL_SUFFIX})/?(.*)$"
)

# list of static attribute references to be replaced in {'Fn::Sub': '...'} strings
STATIC_REFS = ["AWS::Region", "AWS::Partition", "AWS::StackName", "AWS::AccountId"]


def resolve_ref(
    account_id: str,
    region_name: str,
    stack_name: str,
    resources: dict,
    parameters: dict[str, StackParameter],
    ref: str,
) -> Optional[str]:
    """
    ref always needs to be a static string
    ref can be one of these:
    1. a pseudo-parameter (e.g. AWS::Region)
    2. a parameter
    3. the id of a resource (PhysicalResourceId
    """
    # pseudo parameter
    if ref == "AWS::Region":
        return region_name
    if ref == "AWS::Partition":
        return "aws"
    if ref == "AWS::StackName":
        return stack_name
    if ref == "AWS::StackId":
        # TODO return proper stack id!
        return stack_name
    if ref == "AWS::AccountId":
        return account_id
    if ref == "AWS::NoValue":
        return PLACEHOLDER_AWS_NO_VALUE
    if ref == "AWS::NotificationARNs":
        # TODO!
        return {}
    if ref == "AWS::URLSuffix":
        return AWS_URL_SUFFIX

    # parameter
    if parameter := parameters.get(ref):
        parameter_type: str = parameter["ParameterType"]
        parameter_value = parameter.get("ResolvedValue") or parameter.get("ParameterValue")

        if parameter_type in ["CommaDelimitedList"] or parameter_type.startswith("List<"):
            return [p.strip() for p in parameter_value.split(",")]
        else:
            return parameter_value

    # resource
    resource = resources.get(ref)
    if not resource:
        raise Exception(
            f"Resource target for `Ref {ref}` could not be found. Is there a resource with name {ref} in your stack?"
        )

    return resources[ref].get("PhysicalResourceId")


@prevent_stack_overflow(match_parameters=True)
def _resolve_refs_recursively(
    account_id: str,
    region_name: str,
    stack_name: str,
    resources: dict,
    mappings: dict,
    conditions: dict,
    parameters: dict,
    value: dict | list | str | bytes | None,
):
    if isinstance(value, dict):
        keys_list = list(value.keys())
        stripped_fn_lower = keys_list[0].lower().split("::")[-1] if len(keys_list) == 1 else None

        # process special operators
        if keys_list == ["Ref"]:
            ref = resolve_ref(
                account_id, region_name, stack_name, resources, parameters, value["Ref"]
            )
            if ref is None:
                msg = 'Unable to resolve Ref for resource "%s" (yet)' % value["Ref"]
                LOG.debug("%s - %s", msg, resources.get(value["Ref"]) or set(resources.keys()))
                raise DependencyNotYetSatisfied(resource_ids=value["Ref"], message=msg)
            ref = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                ref,
            )
            return ref

        if stripped_fn_lower == "getatt":
            attr_ref = value[keys_list[0]]
            attr_ref = attr_ref.split(".") if isinstance(attr_ref, str) else attr_ref
            resource_logical_id = attr_ref[0]
            attribute_name = attr_ref[1]

            # the attribute name can be a Ref
            attribute_name = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                attribute_name,
            )
            resource = resources.get(resource_logical_id)

            resolved_getatt = get_attr_from_model_instance(
                resource, attribute_name, get_resource_type(resource), resource_logical_id
            )
            # TODO: we should check the deployment state and not try to GetAtt from a resource that is still IN_PROGRESS or hasn't started yet.
            if resolved_getatt is None:
                raise DependencyNotYetSatisfied(
                    resource_ids=resource_logical_id,
                    message=f"Could not resolve attribute '{attribute_name}' on resource '{resource_logical_id}'",
                )
            return resolved_getatt

        if stripped_fn_lower == "join":
            join_values = value[keys_list[0]][1]

            # this can actually be another ref that produces a list as output
            if isinstance(join_values, dict):
                join_values = resolve_refs_recursively(
                    account_id,
                    region_name,
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    join_values,
                )

            join_values = [
                resolve_refs_recursively(
                    account_id,
                    region_name,
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    v,
                )
                for v in join_values
            ]

            none_values = [v for v in join_values if v is None]
            if none_values:
                raise Exception(
                    f"Cannot resolve CF Fn::Join {value} due to null values: {join_values}"
                )
            return value[keys_list[0]][0].join([str(v) for v in join_values])

        if stripped_fn_lower == "sub":
            item_to_sub = value[keys_list[0]]

            attr_refs = {r: {"Ref": r} for r in STATIC_REFS}
            if not isinstance(item_to_sub, list):
                item_to_sub = [item_to_sub, {}]
            result = item_to_sub[0]
            item_to_sub[1].update(attr_refs)

            for key, val in item_to_sub[1].items():
                resolved_val = resolve_refs_recursively(
                    account_id,
                    region_name,
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    val,
                )
                if not isinstance(resolved_val, str):
                    # We don't have access to the resource that's a dependency in this case,
                    # so do the best we can with the resource ids
                    raise DependencyNotYetSatisfied(
                        resource_ids=key, message=f"Could not resolve {val} to terminal value type"
                    )
                result = result.replace("${%s}" % key, resolved_val)

            # resolve placeholders
            result = resolve_placeholders_in_string(
                account_id,
                region_name,
                result,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
            )
            return result

        if stripped_fn_lower == "findinmap":
            # "Fn::FindInMap"
            mapping_id = value[keys_list[0]][0]

            if isinstance(mapping_id, dict) and "Ref" in mapping_id:
                # TODO: ??
                mapping_id = resolve_ref(
                    account_id, region_name, stack_name, resources, parameters, mapping_id["Ref"]
                )

            selected_map = mappings.get(mapping_id)
            if not selected_map:
                raise Exception(
                    f"Cannot find Mapping with ID {mapping_id} for Fn::FindInMap: {value[keys_list[0]]} {list(resources.keys())}"  # TODO: verify
                )

            first_level_attribute = value[keys_list[0]][1]
            first_level_attribute = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                first_level_attribute,
            )

            second_level_attribute = value[keys_list[0]][2]
            if not isinstance(second_level_attribute, str):
                second_level_attribute = resolve_refs_recursively(
                    account_id,
                    region_name,
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    second_level_attribute,
                )

            return selected_map.get(first_level_attribute).get(second_level_attribute)

        if stripped_fn_lower == "importvalue":
            import_value_key = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                value[keys_list[0]],
            )
            exports = exports_map(account_id, region_name)
            stack_export = exports.get(import_value_key) or {}
            if not stack_export.get("Value"):
                LOG.info(
                    'Unable to find export "%s" in stack "%s", existing export names: %s',
                    import_value_key,
                    stack_name,
                    list(exports.keys()),
                )
                return None
            return stack_export["Value"]

        if stripped_fn_lower == "if":
            condition, option1, option2 = value[keys_list[0]]
            condition = conditions[condition]
            result = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                option1 if condition else option2,
            )
            return result

        if stripped_fn_lower == "condition":
            # FIXME: this should only allow strings, no evaluation should be performed here
            #   see https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-condition.html
            return conditions[value[keys_list[0]]]

        if stripped_fn_lower == "not":
            condition = value[keys_list[0]][0]
            condition = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                condition,
            )
            return not condition

        if stripped_fn_lower in ["and", "or"]:
            conditions = value[keys_list[0]]
            results = [
                resolve_refs_recursively(
                    account_id,
                    region_name,
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    cond,
                )
                for cond in conditions
            ]
            result = all(results) if stripped_fn_lower == "and" else any(results)
            return result

        if stripped_fn_lower == "equals":
            operand1, operand2 = value[keys_list[0]]
            operand1 = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                operand1,
            )
            operand2 = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                operand2,
            )
            # TODO: investigate type coercion here
            return fn_equals_type_conversion(operand1) == fn_equals_type_conversion(operand2)

        if stripped_fn_lower == "select":
            index, values = value[keys_list[0]]
            index = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                index,
            )
            values = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                values,
            )
            try:
                return values[index]
            except TypeError:
                return values[int(index)]

        if stripped_fn_lower == "split":
            delimiter, string = value[keys_list[0]]
            delimiter = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                delimiter,
            )
            string = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                string,
            )
            return string.split(delimiter)

        if stripped_fn_lower == "getazs":
            region = (
                resolve_refs_recursively(
                    account_id,
                    region_name,
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    value["Fn::GetAZs"],
                )
                or region_name
            )
            azs = []
            for az in ("a", "b", "c", "d", "e", "f"):
                azs.append("%s%s" % (region, az))

            return azs

        if stripped_fn_lower == "base64":
            value_to_encode = value[keys_list[0]]
            value_to_encode = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                value_to_encode,
            )
            return to_str(base64.b64encode(to_bytes(value_to_encode)))

        for key, val in dict(value).items():
            value[key] = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                val,
            )

    if isinstance(value, list):
        # in some cases, intrinsic functions are passed in as, e.g., `[['Fn::Sub', '${MyRef}']]`
        if len(value) == 1 and isinstance(value[0], list) and len(value[0]) == 2:
            inner_list = value[0]
            if str(inner_list[0]).lower().startswith("fn::"):
                return resolve_refs_recursively(
                    account_id,
                    region_name,
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    {inner_list[0]: inner_list[1]},
                )

        for i in range(len(value)):
            value[i] = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                value[i],
            )

    return value


# Using a @prevent_stack_overflow decorator here to avoid infinite recursion
# in case we load stack exports that have circular dependencies (see issue 3438)
# TODO: Potentially think about a better approach in the future
@prevent_stack_overflow(match_parameters=True)
def resolve_refs_recursively(
    account_id: str,
    region_name: str,
    stack_name: str,
    resources: dict,
    mappings: dict,
    conditions: dict[str, bool],
    parameters: dict,
    value,
):
    result = _resolve_refs_recursively(
        account_id, region_name, stack_name, resources, mappings, conditions, parameters, value
    )

    # localstack specific patches
    if isinstance(result, str):
        # we're trying to filter constructed API urls here (e.g. via Join in the template)
        api_match = REGEX_OUTPUT_APIGATEWAY.match(result)
        if api_match:
            prefix = api_match[1]
            host = api_match[2]
            path = api_match[3]
            port = localstack_host().port
            return f"{prefix}{host}:{port}/{path}"

        # basic dynamic reference support
        # see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html
        # technically there are more restrictions for each of these services but checking each of these
        # isn't really necessary for the current level of emulation
        dynamic_ref_match = REGEX_DYNAMIC_REF.match(result)
        if dynamic_ref_match:
            service_name = dynamic_ref_match[1]
            reference_key = dynamic_ref_match[2]

            # only these 3 services are supported for dynamic references right now
            if service_name == "ssm":
                ssm_client = connect_to(aws_access_key_id=account_id, region_name=region_name).ssm
                return ssm_client.get_parameter(Name=reference_key)["Parameter"]["Value"]
            elif service_name == "ssm-secure":
                ssm_client = connect_to(aws_access_key_id=account_id, region_name=region_name).ssm
                return ssm_client.get_parameter(Name=reference_key, WithDecryption=True)[
                    "Parameter"
                ]["Value"]
            elif service_name == "secretsmanager":
                # reference key needs to be parsed further
                # because {{resolve:secretsmanager:secret-id:secret-string:json-key:version-stage:version-id}}
                # we match for "secret-id:secret-string:json-key:version-stage:version-id"
                # where
                #   secret-id can either be the secret name or the full ARN of the secret
                #   secret-string *must* be SecretString
                #   all other values are optional
                secret_id = reference_key
                [json_key, version_stage, version_id] = [None, None, None]
                if "SecretString" in reference_key:
                    parts = reference_key.split(":SecretString:")
                    secret_id = parts[0]
                    # json-key, version-stage and version-id are optional.
                    [json_key, version_stage, version_id] = f"{parts[1]}::".split(":")[:3]

                kwargs = {}  # optional args for get_secret_value
                if version_id:
                    kwargs["VersionId"] = version_id
                if version_stage:
                    kwargs["VersionStage"] = version_stage

                secretsmanager_client = connect_to(
                    aws_access_key_id=account_id, region_name=region_name
                ).secretsmanager
                secret_value = secretsmanager_client.get_secret_value(SecretId=secret_id, **kwargs)[
                    "SecretString"
                ]
                if json_key:
                    json_secret = json.loads(secret_value)
                    if json_key not in json_secret:
                        raise DependencyNotYetSatisfied(
                            resource_ids=secret_id,
                            message=f"Key {json_key} is not yet available in secret {secret_id}.",
                        )
                    return json_secret[json_key]
                else:
                    return secret_value
            else:
                LOG.warning(f"Unsupported service for dynamic parameter: {service_name=}")

    return result


def resolve_placeholders_in_string(
    account_id: str,
    region_name: str,
    result,
    stack_name: str,
    resources: dict,
    mappings: dict,
    conditions: dict[str, bool],
    parameters: dict,
):
    """
    Resolve individual Fn::Sub variable replacements

    Variables can be template parameter names, resource logical IDs, resource attributes, or a variable in a key-value map
    """

    def _replace(match):
        ref_expression = match.group(1)
        parts = ref_expression.split(".")
        if len(parts) >= 2:
            # Resource attributes specified => Use GetAtt to resolve
            logical_resource_id, _, attr_name = ref_expression.partition(".")
            resolved = get_attr_from_model_instance(
                resources[logical_resource_id],
                attr_name,
                get_resource_type(resources[logical_resource_id]),
                logical_resource_id,
            )
            if resolved is None:
                raise DependencyNotYetSatisfied(
                    resource_ids=logical_resource_id,
                    message=f"Unable to resolve attribute ref {ref_expression}",
                )
            if not isinstance(resolved, str):
                resolved = str(resolved)
            return resolved
        if len(parts) == 1:
            if parts[0] in resources or parts[0].startswith("AWS::"):
                # Logical resource ID or parameter name specified => Use Ref for lookup
                result = resolve_ref(
                    account_id, region_name, stack_name, resources, parameters, parts[0]
                )

                if result is None:
                    raise DependencyNotYetSatisfied(
                        resource_ids=parts[0],
                        message=f"Unable to resolve attribute ref {ref_expression}",
                    )
                # TODO: is this valid?
                # make sure we resolve any functions/placeholders in the extracted string
                result = resolve_refs_recursively(
                    account_id,
                    region_name,
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    result,
                )
                # make sure we convert the result to string
                # TODO: do this more systematically
                result = "" if result is None else str(result)
                return result
            elif parts[0] in parameters:
                parameter = parameters[parts[0]]
                parameter_type: str = parameter["ParameterType"]
                parameter_value = parameter.get("ResolvedValue") or parameter.get("ParameterValue")

                if parameter_type in ["CommaDelimitedList"] or parameter_type.startswith("List<"):
                    return [p.strip() for p in parameter_value.split(",")]
                else:
                    return parameter_value
            else:
                raise DependencyNotYetSatisfied(
                    resource_ids=parts[0],
                    message=f"Unable to resolve attribute ref {ref_expression}",
                )
        # TODO raise exception here?
        return match.group(0)

    regex = r"\$\{([^\}]+)\}"
    result = re.sub(regex, _replace, result)
    return result


# FIXME: resolve_refs_recursively should not be needed, the resources themselves should have those values available already
def resolve_outputs(account_id: str, region_name: str, stack) -> list[dict]:
    result = []
    for k, details in stack.outputs.items():
        if not evaluate_resource_condition(stack.resolved_conditions, details):
            continue
        value = None
        try:
            resolve_refs_recursively(
                account_id,
                region_name,
                stack.stack_name,
                stack.resources,
                stack.mappings,
                stack.resolved_conditions,
                stack.resolved_parameters,
                details,
            )
            value = details["Value"]
        except Exception as e:
            log_method = LOG.debug
            if config.CFN_VERBOSE_ERRORS:
                raise  # unresolvable outputs cause a stack failure
                # log_method = getattr(LOG, "exception")
            log_method("Unable to resolve references in stack outputs: %s - %s", details, e)
        exports = details.get("Export") or {}
        export = exports.get("Name")
        export = resolve_refs_recursively(
            account_id,
            region_name,
            stack.stack_name,
            stack.resources,
            stack.mappings,
            stack.resolved_conditions,
            stack.resolved_parameters,
            export,
        )
        description = details.get("Description")
        entry = {
            "OutputKey": k,
            "OutputValue": value,
            "Description": description,
            "ExportName": export,
        }
        result.append(entry)
    return result
