import base64
import json
import logging
import re
import traceback
import uuid
from typing import Any, Callable, Literal, Optional, Type, TypedDict

import botocore

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.connect import connect_to
from localstack.services.cloudformation import usage
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    dump_resource_as_json,
    fix_boto_parameters_based_on_report,
    get_action_name_for_resource_change,
    log_not_available_message,
    remove_none_values,
)
from localstack.services.cloudformation.engine.entities import Stack, StackChangeSet
from localstack.services.cloudformation.engine.parameters import StackParameter
from localstack.services.cloudformation.engine.template_utils import (
    fn_equals_type_conversion,
    get_deps_for_resource,
)
from localstack.services.cloudformation.engine.types import DeployTemplates, FuncDetails
from localstack.services.cloudformation.resource_provider import (
    Credentials,
    ResourceProviderExecutor,
    ResourceProviderPayload,
    check_not_found_exception,
    get_resource_type,
)
from localstack.services.cloudformation.service_models import (
    DependencyNotYetSatisfied,
    GenericBaseModel,
)
from localstack.services.cloudformation.stores import exports_map
from localstack.utils.aws import aws_stack
from localstack.utils.functions import prevent_stack_overflow
from localstack.utils.json import clone_safe
from localstack.utils.objects import get_all_subclasses
from localstack.utils.strings import first_char_to_lower, to_bytes, to_str
from localstack.utils.threads import start_worker_thread

from localstack.services.cloudformation.models import *  # noqa: F401, isort:skip

ACTION_CREATE = "create"
ACTION_DELETE = "delete"
AWS_URL_SUFFIX = "localhost.localstack.cloud"  # value is "amazonaws.com" in real AWS

REGEX_OUTPUT_APIGATEWAY = re.compile(
    rf"^(https?://.+\.execute-api\.)(?:[^-]+-){{2,3}}\d\.(amazonaws\.com|{AWS_URL_SUFFIX})/?(.*)$"
)
REGEX_DYNAMIC_REF = re.compile("{{resolve:([^:]+):(.+)}}")

LOG = logging.getLogger(__name__)

# list of static attribute references to be replaced in {'Fn::Sub': '...'} strings
STATIC_REFS = ["AWS::Region", "AWS::Partition", "AWS::StackName", "AWS::AccountId"]

# maps resource type string to model class
RESOURCE_MODELS: dict[str, Type[GenericBaseModel]] = {
    model.cloudformation_type(): model for model in get_all_subclasses(GenericBaseModel)
}


class NoStackUpdates(Exception):
    """Exception indicating that no actions are to be performed in a stack update (which is not allowed)"""

    pass


# ---------------------
# CF TEMPLATE HANDLING
# ---------------------


def get_deployment_config(res_type: str) -> DeployTemplates | None:
    resource_class = RESOURCE_MODELS.get(res_type)
    if resource_class:
        return resource_class.get_deploy_templates()
    else:
        usage.missing_resource_types.record(res_type)


# TODO(ds): remove next
def retrieve_resource_details(
    resource_id, resource_status, resources: dict[str, Type[GenericBaseModel]], stack_name
):
    resource = resources.get(resource_id)
    resource_id = resource_status.get("PhysicalResourceId") or resource_id
    if not resource:
        resource = {}
    resource_type = get_resource_type(resource)
    resource_props = resource.get("Properties")
    if resource_props is None:
        raise Exception(
            f'Unable to find properties for resource "{resource_id}": {resource} - {resources}'
        )
    try:
        # TODO(srw): assign resource objects rather than fetching state all the time
        # convert resource props to resource entity
        instance = get_resource_model_instance(resource_id, resources)
        if instance:
            state = instance.fetch_and_update_state(stack_name=stack_name, resources=resources)
            return state

        message = (
            f"Unexpected resource type {resource_type} when resolving "
            f"references of resource {resource_id}: {dump_resource_as_json(resource)}"
        )
        log_not_available_message(resource_type=resource_type, message=message)

    except DependencyNotYetSatisfied:
        if config.CFN_VERBOSE_ERRORS:
            LOG.exception(f"dependency not yet satisfied for {resource_id}")
        return

    except Exception as e:
        check_not_found_exception(e, resource_type, resource, resource_status)

    return None


# TODO(srw): this becomes a property lookup
# TODO(ds): remove next
def extract_resource_attribute(
    resource_type,
    resource_state,
    attribute,
    resource_id=None,
    resource=None,
    resources=None,
    stack_name=None,
):
    LOG.debug("Extract resource attribute: %s %s", resource_type, attribute)
    is_ref_attribute = attribute in ["PhysicalResourceId", "Ref"]
    resource = resource or {}
    if not resource and resources:
        resource = resources[resource_id]

    if not resource_state:
        resource_state = retrieve_resource_details(resource_id, {}, resources, stack_name)
        if not resource_state:
            raise DependencyNotYetSatisfied(
                resource_ids=resource_id,
                message=f'Unable to fetch details for resource "{resource_id}" (attribute "{attribute}")',
            )

    if isinstance(resource_state, GenericBaseModel):
        if hasattr(resource_state, "get_cfn_attribute"):
            try:
                return resource_state.get_cfn_attribute(attribute)
            except Exception:
                if config.CFN_VERBOSE_ERRORS:
                    LOG.exception("could not fetch cfn attribute {attribute} from resource")
        raise Exception(
            f'Unable to extract attribute "{attribute}" from "{resource_type}" model class {type(resource_state)}'
        )

    # extract resource specific attributes
    # TODO: remove the code below - move into resource model classes!

    resource_props = resource.get("Properties", {})
    attribute_lower = first_char_to_lower(attribute)
    result = resource_state.get(attribute) or resource_state.get(attribute_lower)
    if result is None and isinstance(resource, dict):
        result = resource_props.get(attribute) or resource_props.get(attribute_lower)
        if result is None:
            result = get_attr_from_model_instance(
                resource,
                attribute,
                resource_type=resource_type,
                resource_id=resource_id,
            )
    if is_ref_attribute:
        # TODO: remove
        for attr in ["Id", "PhysicalResourceId", "Ref"]:
            if result is None:
                for obj in [resource_state, resource]:
                    result = result or obj.get(attr)
    return result


def get_attr_from_model_instance(
    resource: dict, attribute: str, resource_type: str, resource_id: Optional[str] = None
):
    model_class = RESOURCE_MODELS.get(resource_type)
    if not model_class:
        LOG.debug('Unable to find model class for resource type "%s"', resource_type)
    try:
        inst = model_class(resource_name=resource_id, resource_json=resource)
        return inst.get_cfn_attribute(attribute)
    except Exception:
        log_method = getattr(LOG, "debug")
        if config.CFN_VERBOSE_ERRORS:
            log_method = getattr(LOG, "exception")
        log_method("Failed to retrieve model attribute: %s", attribute)


def get_ref_from_model(resources: dict, logical_resource_id: str) -> Optional[str]:
    resource = resources[logical_resource_id]
    resource_type = get_resource_type(resource)
    model_class = RESOURCE_MODELS.get(resource_type)
    if model_class:
        return model_class(resource_name=logical_resource_id, resource_json=resource).get_ref()

    LOG.error("Unsupported resource type: %s", resource_type)


def resolve_ref(
    stack_name: str,
    resources: dict,
    mappings: dict,
    conditions: dict[str, bool],
    parameters: dict[str, StackParameter],
    ref: str,
    attribute: str,
):
    # pseudo parameters
    if ref == "AWS::Region":
        return aws_stack.get_region()
    if ref == "AWS::Partition":
        return "aws"
    if ref == "AWS::StackName":
        return stack_name
    if ref == "AWS::StackId":
        # TODO return proper stack id!
        return stack_name
    if ref == "AWS::AccountId":
        return get_aws_account_id()
    if ref == "AWS::NoValue":
        return PLACEHOLDER_AWS_NO_VALUE
    if ref == "AWS::NotificationARNs":
        # TODO!
        return {}
    if ref == "AWS::URLSuffix":
        return AWS_URL_SUFFIX

    if attribute == "Ref":
        # ref always needs to be a static string
        # ref can be one of these:
        # 1. a parameter
        # 2. a pseudo-parameter (e.g. AWS::Region)
        # 3. the "value" of a resource

        if parameter := parameters.get(ref):
            parameter_type: str = parameter["ParameterType"]
            parameter_value = parameter.get("ResolvedValue") or parameter.get("ParameterValue")

            if parameter_type in ["CommaDelimitedList"] or parameter_type.startswith("List<"):
                return [p.strip() for p in parameter_value.split(",")]
            else:
                return parameter_value

        resource = resources.get(ref)
        if not resource:
            raise Exception("Should be detected earlier.")

        # TODO: this shouldn't be needed when dependency graph and deployment status is honored
        resolve_refs_recursively(
            stack_name, resources, mappings, conditions, parameters, resources.get(ref)
        )
        return get_ref_from_model(resources, ref)

    if resources.get(ref):
        if isinstance(resources[ref].get(attribute), (str, int, float, bool, dict)):
            return resources[ref][attribute]

    # TODO: when do we go into the branch below?
    # TODO(ds): remove all below next
    # fetch resource details
    resource_new = retrieve_resource_details(ref, {}, resources, stack_name)
    if not resource_new:
        raise DependencyNotYetSatisfied(
            resource_ids=ref,
            message='Unable to fetch details for resource "%s" (resolving attribute "%s")'
            % (ref, attribute),
        )

    resource = resources.get(ref)
    resource_type = get_resource_type(resource)
    result = extract_resource_attribute(
        resource_type,
        resource_new,
        attribute,
        resource_id=ref,
        resource=resource,
        resources=resources,
        stack_name=stack_name,
    )
    if result is None:
        LOG.warning(
            'Unable to extract reference attribute "%s" from resource: %s %s',
            attribute,
            resource_new,
            resource,
        )
    return result


# Using a @prevent_stack_overflow decorator here to avoid infinite recursion
# in case we load stack exports that have circular dependencies (see issue 3438)
# TODO: Potentially think about a better approach in the future
@prevent_stack_overflow(match_parameters=True)
def resolve_refs_recursively(
    stack_name: str,
    resources: dict,
    mappings: dict,
    conditions: dict[str, bool],
    parameters: dict,
    value,
):
    result = _resolve_refs_recursively(
        stack_name, resources, mappings, conditions, parameters, value
    )

    # localstack specific patches
    if isinstance(result, str):
        # we're trying to filter constructed API urls here (e.g. via Join in the template)
        api_match = REGEX_OUTPUT_APIGATEWAY.match(result)
        if api_match:
            prefix = api_match[1]
            host = api_match[2]
            path = api_match[3]
            port = config.service_port("apigateway")
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
                ssm_client = connect_to().ssm
                return ssm_client.get_parameter(Name=reference_key)["Parameter"]["Value"]
            elif service_name == "ssm-secure":
                ssm_client = connect_to().ssm
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

                secretsmanager_client = connect_to().secretsmanager
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


@prevent_stack_overflow(match_parameters=True)
def _resolve_refs_recursively(
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
                stack_name,
                resources,
                mappings,
                conditions,
                parameters,
                value["Ref"],
                attribute="Ref",
            )
            if ref is None:
                msg = 'Unable to resolve Ref for resource "%s" (yet)' % value["Ref"]
                LOG.debug("%s - %s", msg, resources.get(value["Ref"]) or set(resources.keys()))
                raise DependencyNotYetSatisfied(resource_ids=value["Ref"], message=msg)
            ref = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, ref
            )
            return ref

        if stripped_fn_lower == "getatt":
            attr_ref = value[keys_list[0]]
            attr_ref = attr_ref.split(".") if isinstance(attr_ref, str) else attr_ref
            resource_logical_id = attr_ref[0]
            attribute_name = attr_ref[1]

            # the attribute name can be a Ref
            attribute_name = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, attribute_name
            )
            resource = resources.get(resource_logical_id)

            resolved_getatt = get_attr_from_model_instance(
                resource, attribute_name, get_resource_type(resource)
            )
            # TODO: we should check the deployment state and not try to GetAtt from a resource that is still IN_PROGRESS or hasn't started yet.
            if resolved_getatt is None:
                raise DependencyNotYetSatisfied(resource_ids=resource_logical_id, message="")
            return resolved_getatt

        if stripped_fn_lower == "join":
            join_values = value[keys_list[0]][1]

            # this can actually be another ref that produces a list as output
            if isinstance(join_values, dict):
                join_values = resolve_refs_recursively(
                    stack_name, resources, mappings, conditions, parameters, join_values
                )

            join_values = [
                resolve_refs_recursively(stack_name, resources, mappings, conditions, parameters, v)
                for v in join_values
            ]

            none_values = [v for v in join_values if v is None]
            if none_values:
                raise Exception(
                    "Cannot resolve CF fn::Join %s due to null values: %s" % (value, join_values)
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
                val = resolve_refs_recursively(
                    stack_name, resources, mappings, conditions, parameters, val
                )
                result = result.replace("${%s}" % key, val)

            # resolve placeholders
            result = resolve_placeholders_in_string(
                result, stack_name, resources, mappings, conditions, parameters
            )
            return result

        if stripped_fn_lower == "findinmap":
            # "Fn::FindInMap"
            mapping_id = value[keys_list[0]][0]

            if isinstance(mapping_id, dict) and "Ref" in mapping_id:
                # TODO: ??
                mapping_id = resolve_ref(
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    mapping_id["Ref"],
                    "Ref",
                )

            selected_map = mappings.get(mapping_id)
            if not selected_map:
                raise Exception(
                    f"Cannot find Mapping with ID {mapping_id} for Fn::FindInMap: {value[keys_list[0]]} {list(resources.keys())}"  # TODO: verify
                )

            first_level_attribute = value[keys_list[0]][1]
            first_level_attribute = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, first_level_attribute
            )

            second_level_attribute = value[keys_list[0]][2]
            if not isinstance(second_level_attribute, str):
                second_level_attribute = resolve_refs_recursively(
                    stack_name, resources, mappings, conditions, parameters, second_level_attribute
                )

            return selected_map.get(first_level_attribute).get(second_level_attribute)

        if stripped_fn_lower == "importvalue":
            import_value_key = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, value[keys_list[0]]
            )
            exports = exports_map()
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
                stack_name, resources, mappings, conditions, parameters, condition
            )
            return not condition

        if stripped_fn_lower in ["and", "or"]:
            conditions = value[keys_list[0]]
            results = [
                resolve_refs_recursively(
                    stack_name, resources, mappings, conditions, parameters, cond
                )
                for cond in conditions
            ]
            result = all(results) if stripped_fn_lower == "and" else any(results)
            return result

        if stripped_fn_lower == "equals":
            operand1, operand2 = value[keys_list[0]]
            operand1 = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, operand1
            )
            operand2 = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, operand2
            )
            # TODO: investigate type coercion here
            return fn_equals_type_conversion(operand1) == fn_equals_type_conversion(operand2)

        if stripped_fn_lower == "select":
            index, values = value[keys_list[0]]
            index = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, index
            )
            values = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, values
            )
            try:
                return values[index]
            except TypeError:
                return values[int(index)]

        if stripped_fn_lower == "split":
            delimiter, string = value[keys_list[0]]
            delimiter = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, delimiter
            )
            string = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, string
            )
            return string.split(delimiter)

        if stripped_fn_lower == "getazs":
            region = (
                resolve_refs_recursively(
                    stack_name, resources, mappings, conditions, parameters, value["Fn::GetAZs"]
                )
                or aws_stack.get_region()
            )
            azs = []
            for az in ("a", "b", "c", "d"):
                azs.append("%s%s" % (region, az))

            return azs

        if stripped_fn_lower == "base64":
            value_to_encode = value[keys_list[0]]
            value_to_encode = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, value_to_encode
            )
            return to_str(base64.b64encode(to_bytes(value_to_encode)))

        for key, val in dict(value).items():
            value[key] = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, val
            )

    if isinstance(value, list):
        # in some cases, intrinsic functions are passed in as, e.g., `[['Fn::Sub', '${MyRef}']]`
        if len(value) == 1 and isinstance(value[0], list) and len(value[0]) == 2:
            inner_list = value[0]
            if str(inner_list[0]).lower().startswith("fn::"):
                return resolve_refs_recursively(
                    stack_name,
                    resources,
                    mappings,
                    conditions,
                    parameters,
                    {inner_list[0]: inner_list[1]},
                )

        for i in range(len(value)):
            value[i] = resolve_refs_recursively(
                stack_name, resources, mappings, conditions, parameters, value[i]
            )

    return value


def resolve_placeholders_in_string(
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
            resource_name, _, attr_name = ref_expression.partition(".")
            resolved = get_attr_from_model_instance(
                resources[resource_name],
                attr_name,
                get_resource_type(resources[resource_name]),
                resource_name,
            )
            if resolved is None:
                raise DependencyNotYetSatisfied(
                    resource_ids=resource_name,
                    message=f"Unable to resolve attribute ref {ref_expression}",
                )
            if not isinstance(resolved, str):
                resolved = str(resolved)
            return resolved
        if len(parts) == 1:
            if parts[0] in resources:
                # Logical resource ID or parameter name specified => Use Ref for lookup
                result = resolve_ref(
                    stack_name, resources, mappings, conditions, parameters, parts[0], "Ref"
                )

                if result is None:
                    raise DependencyNotYetSatisfied(
                        resource_ids=parts[0],
                        message=f"Unable to resolve attribute ref {ref_expression}",
                    )
                # TODO: is this valid?
                # make sure we resolve any functions/placeholders in the extracted string
                result = resolve_refs_recursively(
                    stack_name, resources, mappings, conditions, parameters, result
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


def evaluate_resource_condition(
    stack_name: str, resources: dict, mappings: dict, conditions: dict[str, bool], resource: dict
) -> bool:
    condition = resource.get("Condition")
    if condition:
        return conditions.get(condition, True)
    return True


# TODO: move (registry/util)
def get_resource_model_instance(resource_id: str, resources) -> Optional[GenericBaseModel]:
    """Obtain a typed resource entity instance representing the given stack resource."""
    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    resource_class = RESOURCE_MODELS.get(resource_type)
    if not resource_class:
        return None
    instance = resource_class(resource)
    return instance


def invoke_function(
    function: Callable,
    params: dict,
    resource_type: str,
    func_details: FuncDetails,
    action_name: str,
    resource: Any,
) -> Any:
    try:
        LOG.debug(
            'Request for resource type "%s" in region %s: %s %s',
            resource_type,
            aws_stack.get_region(),
            func_details["function"],
            params,
        )
        try:
            result = function(**params)
        except botocore.exceptions.ParamValidationError as e:
            # alternatively we could also use the ParamValidator directly
            report = e.kwargs.get("report")
            if not report:
                raise

            LOG.debug("Converting parameters to allowed types")
            converted_params = fix_boto_parameters_based_on_report(params, report)
            LOG.debug("Original parameters:  %s", params)
            LOG.debug("Converted parameters: %s", converted_params)

            result = function(**converted_params)
    except Exception as e:
        if action_name == "delete" and check_not_found_exception(e, resource_type, resource):
            return
        log_method = getattr(LOG, "warning")
        if config.CFN_VERBOSE_ERRORS:
            log_method = getattr(LOG, "exception")
        log_method("Error calling %s with params: %s for resource: %s", function, params, resource)
        raise e

    return result


# TODO: this shouldn't be called for stack parameters
# TODO: refactor / remove (should just be a lookup on the resource state)
def determine_resource_physical_id(
    resource_id: str, resources: dict, stack_name: str
) -> Optional[str]:
    assert resource_id and isinstance(resource_id, str)

    resource = resources.get(resource_id)
    if not resource:
        return
    resource_type = get_resource_type(resource)

    # determine result from resource class
    resource_class = RESOURCE_MODELS.get(resource_type)
    if resource_class:
        resource_inst = resource_class(resource)
        resource_inst.fetch_state_if_missing(stack_name=stack_name, resources=resources)
        result = resource_inst.physical_resource_id
        if result:
            return result

    # TODO: should be able to remove this as well and unify with the one above
    res_id = resource.get("PhysicalResourceId")
    if res_id:
        return res_id
    LOG.info(
        'Unable to determine PhysicalResourceId for "%s" resource, ID "%s"',
        resource_type,
        resource_id,
    )


# -----------------------
# MAIN TEMPLATE DEPLOYER
# -----------------------


Action = str


class ResourceChange(TypedDict):
    Action: Action
    LogicalResourceId: str
    PhysicalResourceId: Optional[str]
    ResourceType: str
    Scope: list
    Details: list
    Replacement: Optional[Literal["False"]]


class ChangeConfig(TypedDict):
    Type: str
    ResourceChange: ResourceChange


# TODO: replace
class TemplateDeployer:
    def __init__(self, stack):
        self.stack = stack

        try:
            self.provider_config = json.loads(config.CFN_RESOURCE_PROVIDER_OVERRIDES)
        except json.JSONDecodeError:
            LOG.warning(
                "Failed to parse CFN_RESOURCE_PROVIDER_OVERRIDES config. Not a valid JSON document.",
                exc_info=True,
            )
            raise

    @property
    def resources(self):
        return self.stack.resources

    @property
    def mappings(self):
        return self.stack.mappings

    @property
    def stack_name(self):
        return self.stack.stack_name

    # ------------------
    # MAIN ENTRY POINTS
    # ------------------

    def deploy_stack(self):
        self.stack.set_stack_status("CREATE_IN_PROGRESS")
        try:
            self.apply_changes(
                self.stack,
                self.stack,
                initialize=True,
                action="CREATE",
            )
        except Exception:
            log_method = getattr(LOG, "info")
            if config.CFN_VERBOSE_ERRORS:
                log_method = getattr(LOG, "exception")
            log_method("Unable to create stack %s: %s", self.stack.stack_name)
            self.stack.set_stack_status("CREATE_FAILED")
            raise

    def apply_change_set(self, change_set: StackChangeSet):
        action = (
            "UPDATE"
            if change_set.stack.status in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            else "CREATE"
        )
        change_set.stack.set_stack_status(f"{action}_IN_PROGRESS")
        # update parameters on parent stack
        change_set.stack.set_resolved_parameters(change_set.resolved_parameters)
        # update conditions on parent stack
        change_set.stack.set_resolved_stack_conditions(change_set.resolved_conditions)

        # update attributes that the stack inherits from the changeset
        change_set.stack.metadata["Capabilities"] = change_set.metadata.get("Capabilities")

        try:
            self.apply_changes(
                change_set.stack,
                change_set,
                action=action,
            )
        except Exception as e:
            LOG.info(
                "Unable to apply change set %s: %s", change_set.metadata.get("ChangeSetName"), e
            )
            change_set.metadata["Status"] = f"{action}_FAILED"
            self.stack.set_stack_status(f"{action}_FAILED")
            raise

    def update_stack(self, new_stack):
        self.stack.set_stack_status("UPDATE_IN_PROGRESS")
        # apply changes
        self.apply_changes(self.stack, new_stack, action="UPDATE")
        self.stack.set_time_attribute("LastUpdatedTime")

    def delete_stack(self):
        if not self.stack:
            return
        self.stack.set_stack_status("DELETE_IN_PROGRESS")
        stack_resources = list(self.stack.resources.values())
        resources = {r["LogicalResourceId"]: clone_safe(r) for r in stack_resources}

        # TODO: what is this doing?
        for key, resource in resources.items():
            resource["Properties"] = resource.get(
                "Properties", clone_safe(resource)
            )  # TODO: why is there a fallback?
            resource["ResourceType"] = get_resource_type(resource)

        def _safe_lookup_is_deleted(r_id):
            """handles the case where self.stack.resource_status(..) fails for whatever reason"""
            try:
                return self.stack.resource_status(r_id).get("ResourceStatus") == "DELETE_COMPLETE"
            except Exception:
                if config.CFN_VERBOSE_ERRORS:
                    LOG.exception(f"failed to lookup if resource {r_id} is deleted")
                return True  # just an assumption

        # a bit of a workaround until we have a proper dependency graph
        max_cycle = 10  # 10 cycles should be a safe choice for now
        for iteration_cycle in range(1, max_cycle + 1):
            resources = {
                r_id: r for r_id, r in resources.items() if not _safe_lookup_is_deleted(r_id)
            }
            if len(resources) == 0:
                break
            for resource_id, resource in resources.items():
                try:
                    # TODO: cache condition value in resource details on deployment and use cached value here
                    if evaluate_resource_condition(
                        self.stack_name,
                        self.resources,
                        self.mappings,
                        self.stack.resolved_conditions,
                        resource,
                    ):
                        executor = self.create_resource_provider_executor()
                        resource_provider_payload = self.create_resource_provider_payload(
                            "Remove", logical_resource_id=resource_id
                        )
                        executor.deploy_loop(resource_provider_payload)  # noqa
                        self.stack.set_resource_status(resource_id, "DELETE_COMPLETE")
                except Exception as e:
                    if iteration_cycle == max_cycle:
                        LOG.exception(
                            "Last cycle failed to delete resource with id %s. Final exception: %s",
                            resource_id,
                            e,
                        )
                    else:
                        log_method = getattr(LOG, "warning")
                        if config.CFN_VERBOSE_ERRORS:
                            log_method = getattr(LOG, "exception")
                        log_method(
                            "Failed delete of resource with id %s in iteration cycle %d. Retrying in next cycle.",
                            resource_id,
                            iteration_cycle,
                        )

        # update status
        self.stack.set_stack_status("DELETE_COMPLETE")
        self.stack.set_time_attribute("DeletionTime")

    # ----------------------------
    # DEPENDENCY RESOLUTION UTILS
    # ----------------------------

    def is_deployable_resource(self, resource):
        resource_type = get_resource_type(resource)
        entry = get_deployment_config(resource_type)
        if entry is None:
            resource_str = dump_resource_as_json(resource)
            LOG.warning(f'Unable to deploy resource type "{resource_type}": {resource_str}')
        return bool(entry and entry.get(ACTION_CREATE))

    def is_deployed(self, resource):
        # TODO: make this a check on the actual resource status instead(!)
        resource_status = {}
        resource_id = resource["LogicalResourceId"]
        details = retrieve_resource_details(
            resource_id, resource_status, self.stack.resources, self.stack.stack_name
        )
        return bool(details)

    def is_updateable(self, resource):
        """Return whether the given resource can be updated or not."""
        if not self.is_deployable_resource(resource) or not self.is_deployed(resource):
            return False
        resource_instance = get_resource_model_instance(
            resource["LogicalResourceId"], self.stack.resources
        )
        return resource_instance.is_updatable()

    def all_resource_dependencies_satisfied(self, resource) -> bool:
        unsatisfied = self.get_unsatisfied_dependencies(resource)
        return not unsatisfied

    def get_unsatisfied_dependencies(self, resource):
        res_deps = self.get_resource_dependencies(
            resource
        )  # the output here is currently a set of merged IDs from both resources and parameters
        parameter_deps = {d for d in res_deps if d in self.stack.resolved_parameters}
        resource_deps = res_deps.difference(parameter_deps)
        res_deps_mapped = {v: self.stack.resources.get(v) for v in resource_deps}
        return self.get_unsatisfied_dependencies_for_resources(res_deps_mapped, resource)

    def get_unsatisfied_dependencies_for_resources(
        self, resources, depending_resource=None, return_first=True
    ):
        result = {}
        for resource_id, resource in resources.items():
            if self.is_deployable_resource(resource):
                if not self.is_deployed(resource):
                    LOG.debug(
                        "Dependency for resource %s not yet deployed: %s %s",
                        depending_resource,
                        resource_id,
                        resource,
                    )
                    result[resource_id] = resource
                    if return_first:
                        break
        return result

    def get_resource_dependencies(self, resource: dict) -> set[str]:
        """
        Takes a resource and returns its dependencies on other resources via a str -> str mapping
        """
        # Note: using the original, unmodified template here to preserve Ref's ...
        raw_resources = self.stack.template_original["Resources"]
        raw_resource = raw_resources[resource["LogicalResourceId"]]
        return get_deps_for_resource(raw_resource, self.stack.resolved_conditions)

    # -----------------
    # DEPLOYMENT UTILS
    # -----------------

    def init_resource_status(self, resources=None, stack=None, action="CREATE"):
        resources = resources or self.resources
        stack = stack or self.stack
        for resource_id, resource in resources.items():
            stack.set_resource_status(resource_id, f"{action}_IN_PROGRESS")

    # Stack is needed here
    def update_resource_details(self, resource_id, stack=None, action="CREATE"):
        stack = stack or self.stack
        # update physical resource id
        resource = stack.resources[resource_id]

        physical_id = resource.get("PhysicalResourceId")

        physical_id = physical_id or determine_resource_physical_id(
            resource_id, resources=stack.resources, stack_name=stack.stack_name
        )
        if not resource.get("PhysicalResourceId") or action == "UPDATE":
            if physical_id:
                resource["PhysicalResourceId"] = physical_id

        # Fetch state for compatibility purposes
        # Since we now have the PhysicalResourceId available without a fetch_state, other attributes that still depend on fetch-state state might not work otherwise
        if not resource:
            return
        resource_type = get_resource_type(resource)
        resource_class = RESOURCE_MODELS.get(resource_type)
        if resource_class:
            resource_inst = resource_class(resource)
            resource_inst.fetch_state_if_missing(
                stack_name=stack.stack_name, resources=stack.resources
            )

        # set resource status
        stack.set_resource_status(resource_id, f"{action}_COMPLETE", physical_res_id=physical_id)

        return physical_id

    def get_change_config(
        self, action: str, resource: dict, change_set_id: Optional[str] = None
    ) -> ChangeConfig:
        result = ChangeConfig(
            **{
                "Type": "Resource",
                "ResourceChange": ResourceChange(
                    **{
                        "Action": action,
                        # TODO(srw): how can the resource not contain a logical resource id?
                        "LogicalResourceId": resource.get("LogicalResourceId"),
                        "PhysicalResourceId": resource.get("PhysicalResourceId"),
                        "ResourceType": resource["Type"],
                        # TODO ChangeSetId is only set for *nested* change sets
                        # "ChangeSetId": change_set_id,
                        "Scope": [],  # TODO
                        "Details": [],  # TODO
                    }
                ),
            }
        )
        if action == "Modify":
            result["ResourceChange"]["Replacement"] = "False"
        return result

    def resource_config_differs(self, resource_new):
        """Return whether the given resource properties differ from the existing config (for stack updates)."""
        # TODO: this is broken for default fields when they're added to the properties in the model
        resource_id = resource_new["LogicalResourceId"]
        resource_old = self.resources[resource_id]
        props_old = resource_old["Properties"]
        props_new = resource_new["Properties"]
        ignored_keys = ["LogicalResourceId", "PhysicalResourceId"]
        old_keys = set(props_old.keys()) - set(ignored_keys)
        new_keys = set(props_new.keys()) - set(ignored_keys)
        if old_keys != new_keys:
            return True
        for key in old_keys:
            if props_old[key] != props_new[key]:
                return True
        old_status = self.stack.resource_states.get(resource_id) or {}
        previous_state = (
            old_status.get("PreviousResourceStatus") or old_status.get("ResourceStatus") or ""
        )
        if old_status and "DELETE" in previous_state:
            return True

    def merge_properties(self, resource_id, old_stack, new_stack):
        old_resources = old_stack.template["Resources"]
        new_resources = new_stack.template["Resources"]
        new_resource = new_resources[resource_id]
        old_resource = old_resources[resource_id] = old_resources.get(resource_id) or {}
        for key, value in new_resource.items():
            if key == "Properties":
                continue
            old_resource[key] = old_resource.get(key, value)
        old_res_props = old_resource["Properties"] = old_resource.get("Properties", {})
        for key, value in new_resource["Properties"].items():
            old_res_props[key] = value

        # overwrite original template entirely
        old_stack.template_original["Resources"][resource_id] = new_stack.template_original[
            "Resources"
        ][resource_id]

    def construct_changes(
        self,
        existing_stack,
        new_stack,
        # TODO: remove initialize argument from here, and determine action based on resource status
        initialize: Optional[bool] = False,
        change_set_id=None,
        append_to_changeset: Optional[bool] = False,
        filter_unchanged_resources: Optional[bool] = False,
    ):
        old_resources = existing_stack.template["Resources"]
        new_resources = new_stack.template["Resources"]
        deletes = [val for key, val in old_resources.items() if key not in new_resources]
        adds = [val for key, val in new_resources.items() if initialize or key not in old_resources]
        modifies = [
            val for key, val in new_resources.items() if not initialize and key in old_resources
        ]

        changes = []
        for action, items in (("Remove", deletes), ("Add", adds), ("Modify", modifies)):
            for item in items:
                item["Properties"] = item.get("Properties", {})
                if (
                    not filter_unchanged_resources
                    or action != "Modify"
                    or self.resource_config_differs(item)
                ):
                    change = self.get_change_config(action, item, change_set_id=change_set_id)
                    changes.append(change)

        # append changes to change set
        if append_to_changeset and isinstance(new_stack, StackChangeSet):
            new_stack.changes.extend(changes)

        return changes

    def apply_changes(
        self,
        existing_stack: Stack,
        new_stack: StackChangeSet,
        change_set_id: Optional[str] = None,
        initialize: Optional[bool] = False,
        action: Optional[str] = None,
    ):
        old_resources = existing_stack.template["Resources"]
        new_resources = new_stack.template["Resources"]
        action = action or "CREATE"
        self.init_resource_status(old_resources, action="UPDATE")

        # apply parameter changes to existing stack
        # self.apply_parameter_changes(existing_stack, new_stack)

        # construct changes
        changes = self.construct_changes(
            existing_stack,
            new_stack,
            initialize=initialize,
            change_set_id=change_set_id,
        )

        # check if we have actual changes in the stack, and prepare properties
        contains_changes = False
        for change in changes:
            res_action = change["ResourceChange"]["Action"]
            resource = new_resources.get(change["ResourceChange"]["LogicalResourceId"])
            if res_action != "Modify" or self.resource_config_differs(resource):
                contains_changes = True
            if res_action in ["Modify", "Add"]:
                self.merge_properties(resource["LogicalResourceId"], existing_stack, new_stack)
        if not contains_changes:
            raise NoStackUpdates("No updates are to be performed.")

        # merge stack outputs and conditions
        existing_stack.outputs.update(new_stack.outputs)
        existing_stack.conditions.update(new_stack.conditions)

        # TODO: ideally the entire template has to be replaced, but tricky at this point
        existing_stack.template["Metadata"] = new_stack.template.get("Metadata")

        # start deployment loop
        return self.apply_changes_in_loop(
            changes, existing_stack, action=action, new_stack=new_stack
        )

    def apply_changes_in_loop(self, changes, stack, action=None, new_stack=None):
        def _run(*args):
            try:
                self.do_apply_changes_in_loop(changes, stack)
                status = f"{action}_COMPLETE"
            except Exception as e:
                log_method = getattr(LOG, "debug")
                if config.CFN_VERBOSE_ERRORS:
                    log_method = getattr(LOG, "exception")
                log_method(
                    'Error applying changes for CloudFormation stack "%s": %s %s',
                    stack.stack_name,
                    e,
                    traceback.format_exc(),
                )
                status = f"{action}_FAILED"
            stack.set_stack_status(status)
            if isinstance(new_stack, StackChangeSet):
                new_stack.metadata["Status"] = status
                exec_result = "EXECUTE_FAILED" if "FAILED" in status else "EXECUTE_COMPLETE"
                new_stack.metadata["ExecutionStatus"] = exec_result
                result = "failed" if "FAILED" in status else "succeeded"
                new_stack.metadata["StatusReason"] = f"Deployment {result}"

        # run deployment in background loop, to avoid client network timeouts
        return start_worker_thread(_run)

    def do_apply_changes_in_loop(self, changes, stack):
        # apply changes in a retry loop, to resolve resource dependencies and converge to the target state
        changes_done = []
        max_iters = 30
        new_resources = stack.resources

        # start deployment loop
        for i in range(max_iters):
            j = 0
            updated = False
            while j < len(changes):
                change = changes[j]
                res_change = change["ResourceChange"]
                action = res_change["Action"]
                is_add_or_modify = action in ["Add", "Modify"]
                resource_id = res_change["LogicalResourceId"]

                # TODO: do resolve_refs_recursively once here
                try:
                    if is_add_or_modify:
                        resource = new_resources[resource_id]
                        should_deploy = self.prepare_should_deploy_change(
                            resource_id, change, stack, new_resources
                        )
                        LOG.debug(
                            'Handling "%s" for resource "%s" (%s/%s) type "%s" in loop iteration %s (should_deploy=%s)',
                            action,
                            resource_id,
                            j + 1,
                            len(changes),
                            res_change["ResourceType"],
                            i + 1,
                            should_deploy,
                        )
                        if not should_deploy:
                            del changes[j]
                            stack_action = get_action_name_for_resource_change(action)
                            stack.set_resource_status(resource_id, f"{stack_action}_COMPLETE")
                            continue
                        if not self.all_resource_dependencies_satisfied(resource):
                            j += 1
                            continue
                    elif action == "Remove":
                        should_remove = self.prepare_should_deploy_change(
                            resource_id, change, stack, new_resources
                        )
                        if not should_remove:
                            del changes[j]
                            continue
                    self.apply_change(change, stack=stack)
                    changes_done.append(change)
                    del changes[j]
                    updated = True
                except DependencyNotYetSatisfied as e:
                    log_method = getattr(LOG, "debug")
                    if config.CFN_VERBOSE_ERRORS:
                        log_method = getattr(LOG, "exception")
                    log_method(
                        'Dependencies for "%s" not yet satisfied, retrying in next loop: %s',
                        resource_id,
                        e,
                    )
                    j += 1
                except Exception as e:
                    status_action = {
                        "Add": "CREATE",
                        "Modify": "UPDATE",
                        "Dynamic": "UPDATE",
                        "Remove": "DELETE",
                    }[action]
                    stack.add_stack_event(
                        resource_id=resource_id,
                        physical_res_id=new_resources[resource_id].get("PhysicalResourceId"),
                        status=f"{status_action}_FAILED",
                        status_reason=str(e),
                    )
                    if config.CFN_VERBOSE_ERRORS:
                        LOG.exception(
                            f"Failed to deploy resource {resource_id}, stack deploy failed"
                        )
                    raise
            if not changes:
                break
            if not updated:
                raise Exception(
                    "Resource deployment loop completed, pending resource changes: %s" % changes
                )

        # clean up references to deleted resources in stack
        deletes = [c for c in changes_done if c["ResourceChange"]["Action"] == "Remove"]
        for delete in deletes:
            stack.template["Resources"].pop(delete["ResourceChange"]["LogicalResourceId"], None)

        # resolve outputs
        stack.resolved_outputs = resolve_outputs(stack)

        return changes_done

    def prepare_should_deploy_change(self, resource_id, change, stack, new_resources):
        """
        TODO: document
        """
        resource = new_resources[resource_id]
        res_change = change["ResourceChange"]
        action = res_change["Action"]

        # TODO: this needs to happen much earlier
        # check resource condition, if present
        if not evaluate_resource_condition(
            stack.stack_name, stack.resources, stack.mappings, stack.resolved_conditions, resource
        ):
            LOG.debug(
                'Skipping deployment of "%s", as resource condition evaluates to false', resource_id
            )
            return

        # resolve refs in resource details
        resolve_refs_recursively(
            stack.stack_name,
            stack.resources,
            stack.mappings,
            stack.resolved_conditions,
            stack.resolved_parameters,
            resource,
        )

        if action in ["Add", "Modify"]:
            if action == "Add" and not self.is_deployable_resource(resource):
                return False
            is_deployed = self.is_deployed(resource)
            # TODO: Attaching the cached _deployed info here, as we should not change the "Add"/"Modify" attribute
            #  here, which is used further down the line to determine the resource action CREATE/UPDATE. This is a
            #  temporary workaround for now - to be refactored once we introduce proper stack resource state models.
            res_change["_deployed"] = is_deployed
            if not is_deployed:
                return True
            if action == "Add":
                return False
            if action == "Modify" and not self.is_updateable(resource):
                LOG.debug(
                    'Action "update" not yet implemented for CF resource type %s',
                    resource.get("Type"),
                )
                return False
        elif action == "Remove":
            should_remove = self.is_deployable_resource(resource)
            if not should_remove:
                LOG.debug(
                    f"Action 'remove' not yet implemented for CF resource type {resource.get('Type')}"
                )
            return should_remove
        return True

    # Stack is needed here
    def apply_change(self, change: ChangeConfig, stack: Stack):
        change_details = change["ResourceChange"]
        action = change_details["Action"]
        resource_id = change_details["LogicalResourceId"]
        resources = stack.resources
        resource = resources[resource_id]

        # TODO: this should not be needed as resources are filtered out if the
        # condition evaluates to False.
        if not evaluate_resource_condition(
            stack.stack_name, resources, stack.mappings, stack.resolved_conditions, resource
        ):
            return

        # remove AWS::NoValue entries
        resource_props = resource.get("Properties")
        if resource_props:
            resource["Properties"] = remove_none_values(resource_props)

        executor = self.create_resource_provider_executor()
        resource_provider_payload = self.create_resource_provider_payload(
            action, logical_resource_id=resource_id
        )

        # TODO: verify event
        executor.deploy_loop(resource_provider_payload)  # noqa

        # TODO: update resource state with returned state from progress event

        # update resource status and physical resource id
        stack_action = get_action_name_for_resource_change(action)
        self.update_resource_details(resource_id, stack=stack, action=stack_action)

    def create_resource_provider_executor(self) -> ResourceProviderExecutor:
        return ResourceProviderExecutor(
            stack_name=self.stack.stack_name,
            stack_id=self.stack.stack_id,
            provider_config=self.provider_config,
            # FIXME: ugly
            resources=self.resources,
            legacy_base_models=RESOURCE_MODELS,
        )

    def create_resource_provider_payload(
        self, action: str, logical_resource_id: str
    ) -> ResourceProviderPayload:
        creds: Credentials = {
            "accessKeyId": "test",
            "secretAccessKey": "test",
            "sessionToken": "",
        }
        resource = self.resources[logical_resource_id]
        resource_provider_payload: ResourceProviderPayload = {
            "awsAccountId": "000000000000",
            "callbackContext": {},
            "stackId": self.stack.stack_name,
            "resourceType": resource["Type"],
            "resourceTypeVersion": "000000",
            # TODO: not actually a UUID
            "bearerToken": str(uuid.uuid4()),
            # TODO: get the current region
            "region": "us-east-1",
            "action": action,
            "requestData": {
                "logicalResourceId": logical_resource_id,
                "resourceProperties": resource["Properties"],
                "previousResourceProperties": None,
                "callerCredentials": creds,
                "providerCredentials": creds,
                "systemTags": {},
                "previousSystemTags": {},
                "stackTags": {},
                "previousStackTags": {},
            },
        }
        return resource_provider_payload


# FIXME: resolve_refs_recursively should not be needed, the resources themselves should have those values available already
def resolve_outputs(stack) -> list[dict]:
    result = []
    for k, details in stack.outputs.items():
        value = None
        try:
            resolve_refs_recursively(
                stack.stack_name,
                stack.resources,
                stack.mappings,
                stack.resolved_conditions,
                stack.resolved_parameters,
                details,
            )
            value = details["Value"]
        except Exception as e:
            log_method = getattr(LOG, "debug")
            if config.CFN_VERBOSE_ERRORS:
                log_method = getattr(LOG, "exception")
            log_method("Unable to resolve references in stack outputs: %s - %s", details, e)
        exports = details.get("Export") or {}
        export = exports.get("Name")
        export = resolve_refs_recursively(
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
