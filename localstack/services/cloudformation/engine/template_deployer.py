import base64
import json
import logging
import re
import traceback
from typing import Dict, List, Optional, Type, Union

import botocore

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.constants import FALSE_STRINGS
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    fix_boto_parameters_based_on_report,
    is_none_or_empty_value,
    remove_none_values,
)
from localstack.services.cloudformation.engine.entities import Stack, StackChangeSet
from localstack.services.cloudformation.service_models import (
    KEY_RESOURCE_STATE,
    DependencyNotYetSatisfied,
    GenericBaseModel,
)
from localstack.services.cloudformation.stores import exports_map
from localstack.utils.aws import aws_stack
from localstack.utils.collections import merge_recursive
from localstack.utils.functions import prevent_stack_overflow, run_safe
from localstack.utils.json import clone_safe, json_safe
from localstack.utils.objects import get_all_subclasses, recurse_object
from localstack.utils.strings import first_char_to_lower, is_string, to_bytes, to_str
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

# list of resource types that can be updated
# TODO: make this a property of the model classes themselves
UPDATEABLE_RESOURCES = [
    "AWS::CDK::Metadata",
    "AWS::Lambda::Function",
    "AWS::Lambda::Permission",
    "AWS::ApiGateway::Method",
    "AWS::ApiGateway::UsagePlan",
    "AWS::SSM::Parameter",
    "AWS::StepFunctions::StateMachine",
    "AWS::IAM::Role",
    "AWS::EC2::Instance",
]

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


def get_deployment_config(res_type):
    canonical_type = canonical_resource_type(res_type)
    resource_class = RESOURCE_MODELS.get(canonical_type)
    if resource_class:
        return resource_class.get_deploy_templates()


# FIXME: still too many cases
def get_resource_type(resource):
    return resource.get("ResourceType") or resource.get("Type") or ""


def get_service_name(resource):
    res_type = resource.get("Type", resource.get("ResourceType", ""))
    parts = res_type.split("::")
    if len(parts) == 1:
        return None
    if res_type.endswith("Cognito::UserPool"):
        return "cognito-idp"
    if parts[-2] == "Cognito":
        return "cognito-idp"
    if parts[-2] == "Elasticsearch":
        return "es"
    if parts[-2] == "OpenSearchService":
        return "opensearch"
    if parts[-2] == "KinesisFirehose":
        return "firehose"
    if parts[-2] == "ResourceGroups":
        return "resource-groups"
    if parts[-2] == "CertificateManager":
        return "acm"
    return parts[1].lower()


def get_client(resource: dict, func_config: dict):
    resource_type = get_resource_type(resource)
    service = get_service_name(resource)
    resource_config = get_deployment_config(resource_type)
    if resource_config is None:
        raise Exception(
            "CloudFormation deployment for resource type %s not yet implemented" % resource_type
        )
    try:
        if func_config.get("boto_client") == "resource":
            return aws_stack.connect_to_resource(service)
        return aws_stack.connect_to_service(service)
    except Exception as e:
        LOG.warning('Unable to get client for "%s" API, skipping deployment: %s', service, e)
        return None


def retrieve_resource_details(resource_id, resource_status, stack):
    resources = stack.resources
    stack_name = stack.stack_name

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
        # convert resource props to resource entity
        instance = get_resource_model_instance(resource_id, stack=stack)
        if instance:
            state = instance.fetch_and_update_state(stack_name=stack_name, resources=resources)
            return state

        # special case for stack parameters
        if resource_type == "Parameter":
            return resource_props

        message = (
            f"Unexpected resource type {resource_type} when resolving "
            f"references of resource {resource_id}: {dump_resource_as_json(resource)}"
        )
        log_not_available_message(resource_type=resource_type, message=message)

    except DependencyNotYetSatisfied:
        return

    except Exception as e:
        check_not_found_exception(e, resource_type, resource, resource_status)

    return None


def check_not_found_exception(e, resource_type, resource, resource_status=None):
    # we expect this to be a "not found" exception
    markers = [
        "NoSuchBucket",
        "ResourceNotFound",
        "NoSuchEntity",
        "NotFoundException",
        "404",
        "not found",
        "not exist",
    ]

    markers_hit = [m for m in markers if m in str(e)]
    if not markers_hit:
        LOG.warning(
            "Unexpected error retrieving details for resource type %s: Exception: %s - %s - status: %s",
            resource_type,
            str(e),
            resource,
            resource_status,
        )
        return False

    return True


def extract_resource_attribute(
    resource_type,
    resource_state,
    attribute,
    resource_id=None,
    resource=None,
    stack=None,
):
    LOG.debug("Extract resource attribute: %s %s", resource_type, attribute)
    is_ref_attribute = attribute in ["PhysicalResourceId", "Ref"]
    is_ref_attr_or_arn = is_ref_attribute or attribute == "Arn"
    resource = resource or {}
    if not resource and stack.resources:
        resource = stack.resources[resource_id]

    if not resource_state:
        resource_state = retrieve_resource_details(resource_id, {}, stack=stack)
        if not resource_state:
            raise DependencyNotYetSatisfied(
                resource_ids=resource_id,
                message='Unable to fetch details for resource "%s" (attribute "%s")'
                % (resource_id, attribute),
            )

    if isinstance(resource_state, GenericBaseModel):
        if hasattr(resource_state, "get_cfn_attribute"):
            try:
                return resource_state.get_cfn_attribute(attribute)
            except Exception:
                pass
        raise Exception(
            'Unable to extract attribute "%s" from "%s" model class %s'
            % (attribute, resource_type, type(resource_state))
        )

    # extract resource specific attributes
    # TODO: remove the code below - move into resource model classes!

    resource_props = resource.get("Properties", {})
    if resource_type == "Parameter":
        result = None
        param_value = resource_props.get(
            "Value",
            resource.get("Value", resource_props.get("Properties", {}).get("Value")),
        )
        if is_ref_attr_or_arn:
            result = param_value
        elif isinstance(param_value, dict):
            result = param_value.get(attribute)
        if result is not None:
            return result
        return ""
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
        for attr in ["Id", "PhysicalResourceId", "Ref"]:
            if result is None:
                for obj in [resource_state, resource]:
                    result = result or obj.get(attr)
    return result


def canonical_resource_type(resource_type):
    if "::" in resource_type and not resource_type.startswith("AWS::"):
        resource_type = "AWS::%s" % resource_type
    return resource_type


def get_attr_from_model_instance(resource, attribute, resource_type, resource_id=None):
    resource_type = canonical_resource_type(resource_type)
    model_class = RESOURCE_MODELS.get(resource_type)
    if not model_class:
        if resource_type not in ["AWS::Parameter", "Parameter"]:
            LOG.debug('Unable to find model class for resource type "%s"', resource_type)
        return
    try:
        inst = model_class(resource_name=resource_id, resource_json=resource)
        return inst.get_cfn_attribute(attribute)
    except Exception as e:
        LOG.debug("Failed to retrieve model attribute: %s", attribute, exc_info=e)


def resolve_ref(stack, ref, attribute):
    stack_name = stack.stack_name
    resources = stack.resources
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

    is_ref_attribute = attribute in ["Ref", "PhysicalResourceId", "Arn"]
    if is_ref_attribute:
        # extract the Properties here, as we only want to recurse over the resource props...
        resource_props = resources.get(ref, {}).get("Properties")
        resolve_refs_recursively(stack, resource_props)
        return determine_resource_physical_id(
            resource_id=ref,
            attribute=attribute,
            stack=stack,
        )

    if resources.get(ref):
        if isinstance(resources[ref].get(attribute), (str, int, float, bool, dict)):
            return resources[ref][attribute]

    # fetch resource details
    resource_new = retrieve_resource_details(ref, {}, stack=stack)
    if not resource_new:
        raise DependencyNotYetSatisfied(
            resource_ids=ref,
            message='Unable to fetch details for resource "%s" (resolving attribute "%s")'
            % (ref, attribute),
        )

    resource = resources.get(ref)
    resource_type = get_resource_type(resource)
    result = extract_resource_attribute(
        resource_type, resource_new, attribute, resource_id=ref, resource=resource, stack=stack
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
def resolve_refs_recursively(stack, value):
    result = _resolve_refs_recursively(stack, value)

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
                ssm_client = aws_stack.connect_to_service("ssm")
                return ssm_client.get_parameter(Name=reference_key)["Parameter"]["Value"]
            elif service_name == "ssm-secure":
                ssm_client = aws_stack.connect_to_service("ssm")
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

                secretsmanager_client = aws_stack.connect_to_service("secretsmanager")
                secret_value = secretsmanager_client.get_secret_value(SecretId=secret_id, **kwargs)[
                    "SecretString"
                ]
                if json_key:
                    return json.loads(secret_value)[json_key]
                else:
                    return secret_value
            else:
                LOG.warning(f"Unsupported service for dynamic parameter: {service_name=}")

    return result


@prevent_stack_overflow(match_parameters=True)
def _resolve_refs_recursively(
    stack: Union[Stack, "TemplateDeployer"], value: dict | list | str | bytes | None
):
    if isinstance(value, dict):
        keys_list = list(value.keys())
        stripped_fn_lower = keys_list[0].lower().split("::")[-1] if len(keys_list) == 1 else None

        # process special operators
        if keys_list == ["Ref"]:
            ref = resolve_ref(stack, value["Ref"], attribute="Ref")
            if ref is None:
                resources = stack.resources
                msg = 'Unable to resolve Ref for resource "%s" (yet)' % value["Ref"]
                LOG.debug("%s - %s", msg, resources.get(value["Ref"]) or set(resources.keys()))
                raise DependencyNotYetSatisfied(resource_ids=value["Ref"], message=msg)
            ref = resolve_refs_recursively(stack, ref)
            return ref

        if stripped_fn_lower == "getatt":
            attr_ref = value[keys_list[0]]
            attr_ref = attr_ref.split(".") if isinstance(attr_ref, str) else attr_ref
            return resolve_ref(stack, attr_ref[0], attribute=attr_ref[1])

        if stripped_fn_lower == "join":
            join_values = value[keys_list[0]][1]
            join_values = [resolve_refs_recursively(stack, v) for v in join_values]
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
                val = resolve_refs_recursively(stack, val)
                result = result.replace("${%s}" % key, val)

            # resolve placeholders
            result = resolve_placeholders_in_string(result, stack=stack)
            return result

        if stripped_fn_lower == "findinmap":
            attr = resolve_refs_recursively(stack, value[keys_list[0]][1])
            result = resolve_ref(stack, value[keys_list[0]][0], attribute=attr)
            if not result:
                resources = stack.resources
                raise Exception(
                    f"Cannot resolve fn::FindInMap: {value[keys_list[0]]} {list(resources.keys())}"
                )

            key = value[keys_list[0]][2]
            if not isinstance(key, str):
                key = resolve_refs_recursively(stack, key)

            return result.get(key)

        if stripped_fn_lower == "importvalue":
            import_value_key = resolve_refs_recursively(stack, value[keys_list[0]])
            exports = exports_map()
            stack_export = exports.get(import_value_key) or {}
            if not stack_export.get("Value"):
                LOG.info(
                    'Unable to find export "%s" in stack "%s", existing export names: %s',
                    import_value_key,
                    stack.stack_name,
                    list(exports.keys()),
                )
                return None
            return stack_export["Value"]

        if stripped_fn_lower == "if":
            condition, option1, option2 = value[keys_list[0]]
            condition = evaluate_condition(stack, condition)
            return resolve_refs_recursively(stack, option1 if condition else option2)

        if stripped_fn_lower == "condition":
            result = evaluate_condition(stack, value[keys_list[0]])
            return result

        if stripped_fn_lower == "not":
            condition = value[keys_list[0]][0]
            condition = resolve_refs_recursively(stack, condition)
            return not condition

        if stripped_fn_lower in ["and", "or"]:
            conditions = value[keys_list[0]]
            results = [resolve_refs_recursively(stack, cond) for cond in conditions]
            result = all(results) if stripped_fn_lower == "and" else any(results)
            return result

        if stripped_fn_lower == "equals":
            operand1, operand2 = value[keys_list[0]]
            operand1 = resolve_refs_recursively(stack, operand1)
            operand2 = resolve_refs_recursively(stack, operand2)
            return str(operand1) == str(operand2)

        if stripped_fn_lower == "select":
            index, values = value[keys_list[0]]
            index = resolve_refs_recursively(stack, index)
            values = resolve_refs_recursively(stack, values)
            return values[index]

        if stripped_fn_lower == "split":
            delimiter, string = value[keys_list[0]]
            delimiter = resolve_refs_recursively(stack, delimiter)
            string = resolve_refs_recursively(stack, string)
            return string.split(delimiter)

        if stripped_fn_lower == "getazs":
            region = resolve_refs_recursively(stack, value["Fn::GetAZs"]) or aws_stack.get_region()
            azs = []
            for az in ("a", "b", "c", "d"):
                azs.append("%s%s" % (region, az))

            return azs

        if stripped_fn_lower == "base64":
            value_to_encode = value[keys_list[0]]
            value_to_encode = resolve_refs_recursively(stack, value_to_encode)
            return to_str(base64.b64encode(to_bytes(value_to_encode)))

        for key, val in dict(value).items():
            value[key] = resolve_refs_recursively(stack, val)

    if isinstance(value, list):
        # in some cases, intrinsic functions are passed in as, e.g., `[['Fn::Sub', '${MyRef}']]`
        if len(value) == 1 and isinstance(value[0], list) and len(value[0]) == 2:
            inner_list = value[0]
            if str(inner_list[0]).lower().startswith("fn::"):
                return resolve_refs_recursively(stack, {inner_list[0]: inner_list[1]})

        for i in range(len(value)):
            value[i] = resolve_refs_recursively(stack, value[i])

    return value


def resolve_placeholders_in_string(result, stack):
    resources = stack.resources

    def _replace(match):
        parts = match.group(1).split(".")
        if len(parts) >= 2:
            resource_name, _, attr_name = match.group(1).partition(".")
            resolved = resolve_ref(stack, resource_name.strip(), attribute=attr_name.strip())
            if resolved is None:
                raise DependencyNotYetSatisfied(
                    resource_ids=resource_name,
                    message="Unable to resolve attribute ref %s" % match.group(1),
                )
            return resolved
        if len(parts) == 1 and parts[0] in resources:
            resource_json = resources[parts[0]]
            resource_type = get_resource_type(resource_json)
            # FIXME: ???
            result = extract_resource_attribute(
                resource_type,
                resource_json.get(KEY_RESOURCE_STATE, {}),
                "Ref",
                stack=stack,
                resource_id=parts[0],
            )
            if result is None:
                raise DependencyNotYetSatisfied(
                    resource_ids=parts[0],
                    message="Unable to resolve attribute ref %s" % match.group(1),
                )
            # make sure we resolve any functions/placeholders in the extracted string
            result = resolve_refs_recursively(stack, result)
            # make sure we convert the result to string
            result = "" if result is None else str(result)
            return result
        # TODO raise exception here?
        return match.group(0)

    regex = r"\$\{([^\}]+)\}"
    result = re.sub(regex, _replace, result)
    return result


def evaluate_condition(stack, condition):
    condition = resolve_refs_recursively(stack, condition)
    condition = resolve_ref(stack, condition, attribute="Ref")
    condition = resolve_refs_recursively(stack, condition)
    return condition


def evaluate_resource_condition(stack, resource):
    condition = resource.get("Condition")
    if condition:
        condition = evaluate_condition(stack, condition)
        if condition is False or condition in FALSE_STRINGS or is_none_or_empty_value(condition):
            return False
    return True


# FIXME: rework
def update_resource(resource_id, stack):
    resources = stack.resources
    stack_name = stack.stack_name

    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    if resource_type not in UPDATEABLE_RESOURCES:
        LOG.warning('Unable to update resource type "%s", id "%s"', resource_type, resource_id)
        return
    LOG.info("Updating resource %s of type %s", resource_id, resource_type)

    instance = get_resource_model_instance(resource_id, stack=stack)
    if instance:
        result = instance.update_resource(resource, stack_name=stack_name, resources=resources)
        instance.fetch_and_update_state(stack_name=stack_name, resources=resources)
        return result


def get_resource_model_instance(resource_id: str, stack) -> Optional[GenericBaseModel]:
    """Obtain a typed resource entity instance representing the given stack resource."""
    resource = stack.resources[resource_id]
    resource_type = get_resource_type(resource)
    canonical_type = canonical_resource_type(resource_type)
    resource_class = RESOURCE_MODELS.get(canonical_type)
    if not resource_class:
        return None
    instance = resource_class(resource)
    return instance


def fix_account_id_in_arns(params):
    def fix_ids(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if is_string(v, exclude_binary=True):
                    o[k] = aws_stack.fix_account_id_in_arns(v)
        elif is_string(o, exclude_binary=True):
            o = aws_stack.fix_account_id_in_arns(o)
        return o

    result = recurse_object(params, fix_ids)
    return result


def convert_data_types(func_details, params):
    """Convert data types in the "params" object, with the type defs
    specified in the 'types' attribute of "func_details"."""
    types = func_details.get("types") or {}
    attr_names = types.keys() or []

    def cast(_obj, _type):
        if _type == bool:
            return _obj in ["True", "true", True]
        if _type == str:
            if isinstance(_obj, bool):
                return str(_obj).lower()
            return str(_obj)
        if _type in (int, float):
            return _type(_obj)
        return _obj

    def fix_types(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in attr_names:
                    o[k] = cast(v, types[k])
        return o

    result = recurse_object(params, fix_types)
    return result


def log_not_available_message(resource_type: str, message: str):
    LOG.warning(
        f"{message}. To find out if {resource_type} is supported in LocalStack Pro, "
        "please check out our docs at https://docs.localstack.cloud/user-guide/aws/cloudformation/#resources-pro--enterprise-edition"
    )


def dump_resource_as_json(resource: Dict) -> str:
    return str(run_safe(lambda: json.dumps(json_safe(resource))) or resource)


def execute_resource_action(resource_id: str, stack: "TemplateDeployer", action_name: str):
    stack_name = stack.stack_name
    resources = stack.resources

    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    func_details = get_deployment_config(resource_type)

    if not func_details or action_name not in func_details:
        if resource_type in ["Parameter"]:
            return
        log_not_available_message(
            resource_type=resource_type,
            message=f"Action {action_name} for resource type {resource_type} not available",
        )
        return

    LOG.debug(
        'Running action "%s" for resource type "%s" id "%s"',
        action_name,
        resource_type,
        resource_id,
    )
    func_details = func_details[action_name]
    func_details = func_details if isinstance(func_details, list) else [func_details]
    results = []
    for func in func_details:
        result = None
        executed = False
        if callable(func.get("function")):
            result = func["function"](resource_id, resources, resource_type, func, stack_name)
            results.append(result)
            executed = True

        if not executed and get_client(resource, func):
            result = configure_resource_via_sdk(
                stack,
                resource_id,
                resource_type,
                func,
                action_name,
            )
            results.append(result)
            executed = True

        if "result_handler" in func and executed:
            LOG.debug(f"Executing callback method for {resource_type}:{resource_id}")
            func["result_handler"](result, resource_id, resources, resource_type)

    return (results or [None])[0]


def configure_resource_via_sdk(stack, resource_id, resource_type, func_details, action_name):
    resources = stack.resources
    stack_name = stack.stack_name

    resource = resources[resource_id]

    if resource_type == "AWS::EC2::Instance":
        if action_name == "create":
            func_details["boto_client"] = "resource"

    client = get_client(resource, func_details)
    function = getattr(client, func_details["function"])
    params = func_details.get("parameters") or (lambda params, **kwargs: params)
    defaults = func_details.get("defaults", {})
    resource_props = resource["Properties"] = resource.get("Properties", {})
    resource_props = dict(resource_props)
    resource_state = resource.get(KEY_RESOURCE_STATE, {})

    if callable(params):
        # resolve parameter map via custom function
        params = params(
            resource_props,
            stack_name=stack_name,
            resources=resources,
            resource_id=resource_id,
        )
    else:
        # it could be a list like ['param1', 'param2', {'apiCallParamName': 'cfResourcePropName'}]
        if isinstance(params, list):
            _params = {}
            for param in params:
                if isinstance(param, dict):
                    _params.update(param)
                else:
                    _params[param] = param
            params = _params

        params = dict(params)
        for param_key, prop_keys in dict(params).items():
            params.pop(param_key, None)
            if not isinstance(prop_keys, list):
                prop_keys = [prop_keys]
            for prop_key in prop_keys:
                if callable(prop_key):
                    prop_value = prop_key(
                        resource_props,
                        stack_name=stack_name,
                        resources=resources,
                        resource_id=resource_id,
                    )
                else:
                    prop_value = resource_props.get(
                        prop_key,
                        resource.get(prop_key, resource_state.get(prop_key)),
                    )
                if prop_value is not None:
                    params[param_key] = prop_value
                    break

    # assign default values if empty
    params = merge_recursive(defaults, params)

    # this is an indicator that we should skip this resource deployment, and return
    if params is None:
        return

    # convert refs
    for param_key, param_value in dict(params).items():
        if param_value is not None:
            params[param_key] = resolve_refs_recursively(stack, param_value)

    # FIXME: move this to a single place after template processing is finished
    # convert any moto account IDs (123456789012) in ARNs to our format (000000000000)
    params = fix_account_id_in_arns(params)
    # convert data types (e.g., boolean strings to bool)
    # TODO: this might not be needed anymore
    params = convert_data_types(func_details, params)
    # remove None values, as they usually raise boto3 errors
    params = remove_none_values(params)

    # invoke function
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
        LOG.warning("Error calling %s with params: %s for resource: %s", function, params, resource)
        raise e

    return result


def get_action_name_for_resource_change(res_change: str) -> str:
    return {"Add": "CREATE", "Remove": "DELETE", "Modify": "UPDATE"}.get(res_change)


# TODO: this shouldn't be called for stack parameters
def determine_resource_physical_id(resource_id, stack=None, attribute: Optional[str] = None):
    assert resource_id and isinstance(resource_id, str)

    resource = stack.resources.get(resource_id)
    if not resource:
        return
    resource_type = get_resource_type(resource)

    # determine result from resource class
    canonical_type = canonical_resource_type(resource_type)  # FIXME: remove
    resource_class = RESOURCE_MODELS.get(canonical_type)
    if resource_class:
        resource_inst = resource_class(resource)
        resource_inst.fetch_state_if_missing(stack_name=stack.stack_name, resources=stack.resources)
        result = resource_inst.get_physical_resource_id(attribute=attribute)
        if result:
            return result

    res_id = resource.get("PhysicalResourceId")
    if res_id and attribute in [None, "Ref", "PhysicalResourceId"]:
        return res_id
    result = extract_resource_attribute(
        resource_type,
        {},
        attribute or "PhysicalResourceId",
        resource_id=resource_id,
        resource=resource,
        stack=stack,
    )
    if result is not None:
        # note that value could be an empty string here (in case of Parameter values)
        return result

    LOG.info(
        'Unable to determine PhysicalResourceId for "%s" resource, ID "%s"',
        resource_type,
        resource_id,
    )


def add_default_resource_props(
    resource,
    stack_name,
    resource_name=None,
    resource_id=None,
    update=False,
    existing_resources=None,
):
    """Apply some fixes to resource props which otherwise cause deployments to fail"""

    res_type = resource["Type"]
    canonical_type = canonical_resource_type(res_type)
    resource_class = RESOURCE_MODELS.get(canonical_type)
    if resource_class is not None:
        resource_class.add_defaults(resource, stack_name)


# -----------------------
# MAIN TEMPLATE DEPLOYER
# -----------------------


class TemplateDeployer:
    def __init__(self, stack):
        self.stack = stack

    @property
    def resources(self):
        return self.stack.resources

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
        except Exception as e:
            LOG.info("Unable to create stack %s: %s", self.stack.stack_name, e)
            self.stack.set_stack_status("CREATE_FAILED")
            raise

    def apply_change_set(self, change_set: StackChangeSet):
        action = (
            "UPDATE"
            if change_set.stack.status in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            else "CREATE"
        )
        change_set.stack.set_stack_status(f"{action}_IN_PROGRESS")

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
        for key, resource in resources.items():
            resource["Properties"] = resource.get("Properties", clone_safe(resource))
            resource["ResourceType"] = resource.get("ResourceType") or resource.get("Type")
        for resource_id, resource in resources.items():
            # TODO: cache condition value in resource details on deployment and use cached value here
            if evaluate_resource_condition(self, resource):
                execute_resource_action(resource_id, self, ACTION_DELETE)
                self.stack.set_resource_status(resource_id, "DELETE_COMPLETE")
        # update status
        self.stack.set_stack_status("DELETE_COMPLETE")
        self.stack.set_time_attribute("DeletionTime")

    # ----------------------------
    # DEPENDENCY RESOLUTION UTILS
    # ----------------------------

    def is_deployable_resource(self, resource):
        resource_type = get_resource_type(resource)
        entry = get_deployment_config(resource_type)
        if entry is None and resource_type not in ["Parameter", None]:
            resource_str = dump_resource_as_json(resource)
            LOG.warning(f'Unable to deploy resource type "{resource_type}": {resource_str}')
        return bool(entry and entry.get(ACTION_CREATE))

    def is_deployed(self, resource):
        resource_status = {}
        resource_id = resource["LogicalResourceId"]
        details = retrieve_resource_details(resource_id, resource_status, stack=self.stack)
        return bool(details)

    def is_updateable(self, resource):
        """Return whether the given resource can be updated or not."""
        if not self.is_deployable_resource(resource) or not self.is_deployed(resource):
            return False
        resource_type = get_resource_type(resource)
        return (
            resource_type in UPDATEABLE_RESOURCES
            or resource_type.partition("AWS::")[-1] in UPDATEABLE_RESOURCES
        )  # TODO: second case just a fall-back for now, delete when PRO is updated

    def all_resource_dependencies_satisfied(self, resource):
        unsatisfied = self.get_unsatisfied_dependencies(resource)
        return not unsatisfied

    def get_unsatisfied_dependencies(self, resource):
        res_deps = self.get_resource_dependencies(resource)
        return self.get_unsatisfied_dependencies_for_resources(res_deps, resource)

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

    def get_resource_dependencies(self, resource):
        result = {}
        # Note: using the original, unmodified template here to preserve Ref's ...
        raw_resources = self.stack.template_original["Resources"]
        raw_resource = raw_resources[resource["LogicalResourceId"]]
        dumped = json.dumps(json_safe(raw_resource))
        for other_id, other in raw_resources.items():
            if resource != other:
                # TODO: traverse dict instead of doing string search!
                search1 = '{"Ref": "%s"}' % other_id
                search2 = '{"Fn::GetAtt": ["%s", ' % other_id
                if search1 in dumped or search2 in dumped:
                    result[other_id] = other
                if other_id in resource.get("DependsOn", []):
                    result[other_id] = other
        return result

    # -----------------
    # DEPLOYMENT UTILS
    # -----------------

    def init_resource_status(self, resources=None, stack=None, action="CREATE"):
        resources = resources or self.resources
        stack = stack or self.stack
        for resource_id, resource in resources.items():
            stack.set_resource_status(resource_id, f"{action}_IN_PROGRESS")

    def update_resource_details(self, resource_id, result, stack=None, action="CREATE"):
        stack = stack or self.stack
        # update physical resource id
        resource = stack.resources[resource_id]

        physical_id = resource.get("PhysicalResourceId")

        physical_id = physical_id or determine_resource_physical_id(resource_id, stack=stack)
        if not resource.get("PhysicalResourceId") or action == "UPDATE":
            if physical_id:
                resource["PhysicalResourceId"] = physical_id

        # set resource status
        stack.set_resource_status(resource_id, f"{action}_COMPLETE", physical_res_id=physical_id)

        return physical_id

    def get_change_config(self, action, resource, change_set_id=None):
        result = {
            "Type": "Resource",
            "ResourceChange": {
                "Action": action,
                "LogicalResourceId": resource.get("LogicalResourceId"),
                "PhysicalResourceId": resource.get("PhysicalResourceId"),
                "ResourceType": resource.get("Type"),
                # TODO ChangeSetId is only set for *nested* change sets
                # "ChangeSetId": change_set_id,
                "Scope": [],  # TODO
                "Details": [],  # TODO
            },
        }
        if action == "Modify":
            result["ResourceChange"]["Replacement"] = "False"
        return result

    def resource_config_differs(self, resource_new):
        """Return whether the given resource properties differ from the existing config (for stack updates)."""
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

    def resolve_param(
        self, logical_id: str, param_type: str, default_value: Optional[str] = None
    ) -> Optional[str]:
        if param_type == "AWS::SSM::Parameter::Value<String>":
            ssm_client = aws_stack.connect_to_service("ssm")
            param = ssm_client.get_parameter(Name=default_value)
            return param["Parameter"]["Value"]
        return None

    def apply_parameter_changes(self, old_stack, new_stack) -> None:
        parameters = {
            p["ParameterKey"]: p
            for p in old_stack.metadata["Parameters"]  # go through current parameter values
        }

        for logical_id, value in new_stack.template["Parameters"].items():
            default = value.get("Default")
            provided_param_value = parameters.get(logical_id)
            param = {
                "ParameterKey": logical_id,
                "ParameterValue": provided_param_value if default is None else default,
            }
            if default is not None:
                resolved_value = self.resolve_param(logical_id, value.get("Type"), default)
                if resolved_value is not None:
                    param["ResolvedValue"] = resolved_value

            parameters[logical_id] = param

        def _update_params(params_list: List[Dict]):
            for param in params_list:
                # make sure we preserve parameter values if UsePreviousValue=true
                if not param.get("UsePreviousValue"):
                    parameters.update({param["ParameterKey"]: param})

        _update_params(new_stack.metadata["Parameters"])
        for change_set in new_stack.change_sets:
            _update_params(change_set.metadata["Parameters"])

        # TODO: unclear/undocumented behavior in implicitly updating old_stack parameter here
        # Note: Indeed it seems that parameters from Change Sets are applied to a stack
        #   itself, and are preserved even after a change set has been deleted. However,
        #   a proper implementation would distinguish between (1) Change Sets and (2) Change
        #   Set Executions - the former are only a template for the changes to be applied,
        #   whereas the latter actually perform changes (including parameter updates).
        #   Also, (1) can be deleted, and (2) can only be rolled back (in case of errors).
        #   Once we have the distinction between (1) and (2) in place, this logic (updating
        #   the parameters of the stack itself) will become obsolete, then the parameter
        #   values can be determined by replaying the values of the sequence of (immutable)
        #   Change Set Executions.
        old_stack.metadata["Parameters"] = [v for v in parameters.values() if v]

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
        self.apply_parameter_changes(existing_stack, new_stack)

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
                LOG.debug(
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

        # apply default props before running the loop
        for resource_id, resource in new_resources.items():
            add_default_resource_props(
                resource,
                stack.stack_name,
                resource_id=resource_id,
                existing_resources=new_resources,
            )

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
                    LOG.debug(
                        'Dependencies for "%s" not yet satisfied, retrying in next loop: %s',
                        resource_id,
                        e,
                    )
                    j += 1
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
        resource = new_resources[resource_id]
        res_change = change["ResourceChange"]
        action = res_change["Action"]

        # check resource condition, if present
        if not evaluate_resource_condition(stack, resource):
            LOG.debug(
                'Skipping deployment of "%s", as resource condition evaluates to false', resource_id
            )
            return

        # resolve refs in resource details
        resolve_refs_recursively(stack, resource)

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

    def apply_change(self, change, stack):
        change_details = change["ResourceChange"]
        action = change_details["Action"]
        resource_id = change_details["LogicalResourceId"]
        resource = stack.resources[resource_id]
        is_deployed = change_details.pop("_deployed", None)
        if not evaluate_resource_condition(stack, resource):
            return

        # execute resource action
        result = None
        if action == "Add" or is_deployed is False:
            result = execute_resource_action(resource_id, self, ACTION_CREATE)
        elif action == "Remove":
            result = execute_resource_action(resource_id, self, ACTION_DELETE)
        elif action == "Modify":
            result = update_resource(resource_id, stack=stack)

        # update resource status and physical resource id
        stack_action = get_action_name_for_resource_change(action)
        self.update_resource_details(resource_id, result, stack=stack, action=stack_action)

        return result


# FIXME: resolve_refs_recursively should not be needed, the resources themselves should have those values available already
def resolve_outputs(stack) -> List[Dict]:
    result = []
    for k, details in stack.outputs.items():
        value = None
        try:
            resolve_refs_recursively(stack, details)
            value = details["Value"]
        except Exception as e:
            LOG.debug("Unable to resolve references in stack outputs: %s - %s", details, e)
        exports = details.get("Export") or {}
        export = exports.get("Name")
        export = resolve_refs_recursively(stack, export)
        description = details.get("Description")
        entry = {
            "OutputKey": k,
            "OutputValue": value,
            "Description": description,
            "ExportName": export,
        }
        result.append(entry)
    return result
