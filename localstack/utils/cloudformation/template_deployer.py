import base64
import copy
import json
import logging
import re
import traceback
from typing import Optional

import botocore

# TODO: remove
from moto.cloudformation import parsing
from moto.core import CloudFormationModel as MotoCloudFormationModel
from moto.ec2.utils import generate_route_id
from six import iteritems

from localstack.constants import FALSE_STRINGS, S3_STATIC_WEBSITE_HOSTNAME, TEST_AWS_ACCOUNT_ID
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    PLACEHOLDER_RESOURCE_NAME,
    is_none_or_empty_value,
    remove_none_values,
)
from localstack.services.cloudformation.service_models import (
    KEY_RESOURCE_STATE,
    DependencyNotYetSatisfied,
    GenericBaseModel,
)
from localstack.services.s3 import s3_listener
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.cloudformation import template_preparer
from localstack.utils.common import (
    canonical_json,
    get_all_subclasses,
    json_safe,
    md5,
    prevent_stack_overflow,
    short_uid,
    start_worker_thread,
    to_bytes,
    to_str,
)

from localstack.services.cloudformation.models import *  # noqa: F401, isort:skip

ACTION_CREATE = "create"
ACTION_DELETE = "delete"
AWS_URL_SUFFIX = "localhost"  # value is "amazonaws.com" in real AWS
IAM_POLICY_VERSION = "2012-10-17"

LOG = logging.getLogger(__name__)

# list of resource types that can be updated
# TODO: make this a property of the model classes themselves
UPDATEABLE_RESOURCES = [
    "Lambda::Function",
    "ApiGateway::Method",
    "StepFunctions::StateMachine",
    "IAM::Role",
    "EC2::Instance",
]

# list of static attribute references to be replaced in {'Fn::Sub': '...'} strings
STATIC_REFS = ["AWS::Region", "AWS::Partition", "AWS::StackName", "AWS::AccountId"]

# maps resource type string to model class
RESOURCE_MODELS = {
    model.cloudformation_type(): model for model in get_all_subclasses(GenericBaseModel)
}


class NoStackUpdates(Exception):
    """Exception indicating that no actions are to be performed in a stack update (which is not allowed)"""

    pass


def lambda_get_params():
    return lambda params, **kwargs: params


# maps resource types to functions and parameters for creation
RESOURCE_TO_FUNCTION = {}


# ----------------
# UTILITY METHODS
# ----------------


def get_secret_arn(secret_name, account_id=None):
    # TODO: create logic to create static without lookup table!
    from localstack.services.secretsmanager import secretsmanager_starter

    storage = secretsmanager_starter.SECRET_ARN_STORAGE
    key = "%s_%s" % (aws_stack.get_region(), secret_name)
    return storage.get(key) or storage.get(secret_name)


def find_stack(stack_name):
    from localstack.services.cloudformation.cloudformation_api import find_stack as api_find_stack

    return api_find_stack(stack_name)


# ---------------------
# CF TEMPLATE HANDLING
# ---------------------


def get_deployment_config(res_type):
    result = RESOURCE_TO_FUNCTION.get(res_type)
    if result is not None:
        return result
    canonical_type = canonical_resource_type(res_type)
    resource_class = RESOURCE_MODELS.get(canonical_type)
    if resource_class:
        return resource_class.get_deploy_templates()


def get_resource_type(resource):
    res_type = resource.get("ResourceType") or resource.get("Type") or ""
    parts = res_type.split("::", 1)
    if len(parts) == 1:
        return parts[0]
    return parts[1]


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
    if parts[-2] == "KinesisFirehose":
        return "firehose"
    if parts[-2] == "ResourceGroups":
        return "resource-groups"
    if parts[-2] == "CertificateManager":
        return "acm"
    return parts[1].lower()


def get_resource_name(resource):
    properties = resource.get("Properties") or {}
    name = properties.get("Name")
    if name:
        return name

    # try to extract name via resource class
    res_type = canonical_resource_type(get_resource_type(resource))
    model_class = RESOURCE_MODELS.get(res_type)
    if model_class:
        instance = model_class(resource)
        name = instance.get_resource_name()

    if not name:
        LOG.debug('Unable to extract name for resource type "%s"' % res_type)
    return name


def get_client(resource, func_config):
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
        LOG.warning('Unable to get client for "%s" API, skipping deployment: %s' % (service, e))
        return None


def describe_stack_resource(stack_name, logical_resource_id):
    client = aws_stack.connect_to_service("cloudformation")
    try:
        result = client.describe_stack_resource(
            StackName=stack_name, LogicalResourceId=logical_resource_id
        )
        return result["StackResourceDetail"]
    except Exception as e:
        LOG.warning(
            'Unable to get details for resource "%s" in CloudFormation stack "%s": %s'
            % (logical_resource_id, stack_name, e)
        )


def retrieve_resource_details(resource_id, resource_status, resources, stack_name):
    resource = resources.get(resource_id)
    resource_id = resource_status.get("PhysicalResourceId") or resource_id
    if not resource:
        resource = {}
    resource_type = get_resource_type(resource)
    resource_props = resource.get("Properties")
    if resource_props is None:
        raise Exception(
            'Unable to find properties for resource "%s": %s %s'
            % (resource_id, resource, resources)
        )
    try:
        # convert resource props to resource entity
        instance = get_resource_model_instance(resource_id, resources)
        if instance:
            state = instance.fetch_and_update_state(stack_name=stack_name, resources=resources)
            return state

        # special case for stack parameters
        if resource_type == "Parameter":
            return resource_props

        # fallback: try accessing stack.moto_resource_statuses
        stack = find_stack(stack_name)
        moto_resource = stack.moto_resource_statuses.get(resource_id)
        if moto_resource:
            return moto_resource

        # if is_deployable_resource(resource):
        LOG.warning(
            "Unexpected resource type %s when resolving references of resource %s: %s"
            % (resource_type, resource_id, resource)
        )

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
    if not list(filter(lambda marker, e=e: marker in str(e), markers)):
        LOG.warning(
            "Unexpected error retrieving details for resource type %s: Exception: %s - %s - status: %s"
            % (resource_type, e, resource, resource_status)
        )

        return False

    return True


def extract_resource_attribute(
    resource_type,
    resource_state,
    attribute,
    resource_id=None,
    resource=None,
    resources=None,
    stack_name=None,
):
    LOG.debug("Extract resource attribute: %s %s" % (resource_type, attribute))
    is_ref_attribute = attribute in ["PhysicalResourceId", "Ref"]
    is_ref_attr_or_arn = is_ref_attribute or attribute == "Arn"
    resource = resource or {}
    if not resource and resources:
        resource = resources[resource_id]

    if not resource_state:
        resource_state = retrieve_resource_details(resource_id, {}, resources, stack_name)
        if not resource_state:
            raise DependencyNotYetSatisfied(
                resource_ids=resource_id,
                message='Unable to fetch details for resource "%s" (attribute "%s")'
                % (resource_id, attribute),
            )

    if isinstance(resource_state, MotoCloudFormationModel):
        if is_ref_attribute:
            res_phys_id = getattr(resource_state, "physical_resource_id", None)
            get_res_phys_id = getattr(resource_state, "get_physical_resource_id", None)
            if not res_phys_id and get_res_phys_id:
                res_phys_id = get_res_phys_id(attribute)
            if res_phys_id:
                return res_phys_id
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
    elif resource_type == "Lambda::Function":
        func_configs = resource_state.get("Configuration") or {}
        if is_ref_attr_or_arn:
            func_arn = func_configs.get("FunctionArn")
            if func_arn:
                return resolve_refs_recursively(stack_name, func_arn, resources)
            func_name = resolve_refs_recursively(
                stack_name, func_configs.get("FunctionName"), resources
            )
            return aws_stack.lambda_function_arn(func_name)
        else:
            return func_configs.get(attribute)
    elif resource_type == "Lambda::Version":
        if resource_state.get("Version"):
            return "%s:%s" % (
                resource_state.get("FunctionArn"),
                resource_state.get("Version").split(":")[-1],
            )
    elif resource_type == "DynamoDB::Table":
        actual_attribute = "LatestStreamArn" if attribute == "StreamArn" else attribute
        value = resource_state.get("Table", {}).get(actual_attribute)
        if value:
            return value
    elif resource_type == "ApiGateway::RestApi":
        if is_ref_attribute:
            result = resource_state.get("id")
            if result:
                return result
        if attribute == "RootResourceId":
            api_id = resource_state["id"]
            resources = aws_stack.connect_to_service("apigateway").get_resources(restApiId=api_id)[
                "items"
            ]
            for res in resources:
                if res["path"] == "/" and not res.get("parentId"):
                    return res["id"]
    elif resource_type == "ApiGateway::Resource":
        if is_ref_attribute:
            return resource_state.get("id")
    elif resource_type == "ApiGateway::Deployment":
        if is_ref_attribute:
            return resource_state.get("id")
    elif resource_type == "S3::Bucket":
        if attribute == "WebsiteURL":
            bucket_name = resource_props.get("BucketName")
            return f"http://{bucket_name}.{S3_STATIC_WEBSITE_HOSTNAME}"
        if is_ref_attr_or_arn:
            bucket_name = resource_props.get("BucketName")
            bucket_name = resolve_refs_recursively(stack_name, bucket_name, resources)
            if attribute == "Arn":
                return aws_stack.s3_bucket_arn(bucket_name)
            return bucket_name
    elif resource_type == "Elasticsearch::Domain":
        if attribute == "DomainEndpoint":
            domain_status = resource_state.get("DomainStatus", {})
            result = domain_status.get("Endpoint")
            if result:
                return result
        if attribute in ["Arn", "DomainArn"]:
            domain_name = resource_props.get("DomainName") or resource_state.get("DomainName")
            return aws_stack.es_domain_arn(domain_name)
    elif resource_type == "StepFunctions::StateMachine":
        if is_ref_attr_or_arn:
            return resource_state["stateMachineArn"]
    elif resource_type == "SNS::Topic":
        if is_ref_attribute and resource_state.get("TopicArn"):
            topic_arn = resource_state.get("TopicArn")
            return resolve_refs_recursively(stack_name, topic_arn, resources)
    elif resource_type == "SQS::Queue":
        if is_ref_attr_or_arn:
            if attribute == "Arn" and resource_state.get("QueueArn"):
                return resolve_refs_recursively(
                    stack_name, resource_state.get("QueueArn"), resources
                )
            return aws_stack.get_sqs_queue_url(resource_props.get("QueueName"))
    attribute_lower = common.first_char_to_lower(attribute)
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
            LOG.debug('Unable to find model class for resource type "%s"' % resource_type)
        return
    try:
        inst = model_class(resource_name=resource_id, resource_json=resource)
        return inst.get_cfn_attribute(attribute)
    except Exception:
        pass


def resolve_ref(stack_name, ref, resources, attribute):
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
        return TEST_AWS_ACCOUNT_ID
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
        resolve_refs_recursively(stack_name, resource_props, resources)
        return determine_resource_physical_id(
            resource_id=ref,
            resources=resources,
            attribute=attribute,
            stack_name=stack_name,
        )

    if resources.get(ref):
        if isinstance(resources[ref].get(attribute), (str, int, float, bool, dict)):
            return resources[ref][attribute]

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
            'Unable to extract reference attribute "%s" from resource: %s %s'
            % (attribute, resource_new, resource)
        )
    return result


# Using a @prevent_stack_overflow decorator here to avoid infinite recursion
# in case we load stack exports that have circular dependencies (see issue 3438)
# TODO: Potentially think about a better approach in the future
@prevent_stack_overflow(match_parameters=True)
def resolve_refs_recursively(stack_name, value, resources):
    if isinstance(value, dict):
        keys_list = list(value.keys())
        stripped_fn_lower = keys_list[0].lower().split("::")[-1] if len(keys_list) == 1 else None

        # process special operators
        if keys_list == ["Ref"]:
            ref = resolve_ref(stack_name, value["Ref"], resources, attribute="Ref")
            if ref is None:
                msg = 'Unable to resolve Ref for resource "%s" (yet)' % value["Ref"]
                LOG.debug("%s - %s" % (msg, resources.get(value["Ref"]) or set(resources.keys())))
                raise DependencyNotYetSatisfied(resource_ids=value["Ref"], message=msg)
            ref = resolve_refs_recursively(stack_name, ref, resources)
            return ref

        if stripped_fn_lower == "getatt":
            attr_ref = value[keys_list[0]]
            attr_ref = attr_ref.split(".") if isinstance(attr_ref, str) else attr_ref
            return resolve_ref(stack_name, attr_ref[0], resources, attribute=attr_ref[1])

        if stripped_fn_lower == "join":
            join_values = value[keys_list[0]][1]
            join_values = [resolve_refs_recursively(stack_name, v, resources) for v in join_values]
            none_values = [v for v in join_values if v is None]
            if none_values:
                raise Exception(
                    "Cannot resolve CF fn::Join %s due to null values: %s" % (value, join_values)
                )
            return value[keys_list[0]][0].join([str(v) for v in join_values])

        if stripped_fn_lower == "sub":
            item_to_sub = value[keys_list[0]]

            attr_refs = dict([(r, {"Ref": r}) for r in STATIC_REFS])
            if not isinstance(item_to_sub, list):
                item_to_sub = [item_to_sub, {}]
            result = item_to_sub[0]
            item_to_sub[1].update(attr_refs)

            for key, val in item_to_sub[1].items():
                val = resolve_refs_recursively(stack_name, val, resources)
                result = result.replace("${%s}" % key, val)

            # resolve placeholders
            result = resolve_placeholders_in_string(
                result, stack_name=stack_name, resources=resources
            )
            return result

        if stripped_fn_lower == "findinmap":
            attr = resolve_refs_recursively(stack_name, value[keys_list[0]][1], resources)
            result = resolve_ref(stack_name, value[keys_list[0]][0], resources, attribute=attr)
            if not result:
                raise Exception(
                    "Cannot resolve fn::FindInMap: %s %s"
                    % (value[keys_list[0]], list(resources.keys()))
                )

            key = value[keys_list[0]][2]
            if not isinstance(key, str):
                key = resolve_refs_recursively(stack_name, key, resources)

            return result.get(key)

        if stripped_fn_lower == "importvalue":
            import_value_key = resolve_refs_recursively(stack_name, value[keys_list[0]], resources)
            stack = find_stack(stack_name)
            stack_export = stack.exports_map.get(import_value_key) or {}
            if not stack_export.get("Value"):
                LOG.info(
                    'Unable to find export "%s" in stack "%s", existing export names: %s'
                    % (import_value_key, stack_name, list(stack.exports_map.keys()))
                )
                return None
            return stack_export["Value"]

        if stripped_fn_lower == "if":
            condition, option1, option2 = value[keys_list[0]]
            condition = evaluate_condition(stack_name, condition, resources)
            return resolve_refs_recursively(
                stack_name, option1 if condition else option2, resources
            )

        if stripped_fn_lower == "not":
            condition = value[keys_list[0]][0]
            condition = resolve_refs_recursively(stack_name, condition, resources)
            return not condition

        if stripped_fn_lower == "equals":
            operand1, operand2 = value[keys_list[0]]
            operand1 = resolve_refs_recursively(stack_name, operand1, resources)
            operand2 = resolve_refs_recursively(stack_name, operand2, resources)
            return str(operand1) == str(operand2)

        if stripped_fn_lower == "select":
            index, values = value[keys_list[0]]
            index = resolve_refs_recursively(stack_name, index, resources)
            values = resolve_refs_recursively(stack_name, values, resources)
            return values[index]

        if stripped_fn_lower == "split":
            delimiter, string = value[keys_list[0]]
            delimiter = resolve_refs_recursively(stack_name, delimiter, resources)
            string = resolve_refs_recursively(stack_name, string, resources)
            return string.split(delimiter)

        if stripped_fn_lower == "getazs":
            region = (
                resolve_refs_recursively(stack_name, value["Fn::GetAZs"], resources)
                or aws_stack.get_region()
            )
            azs = []
            for az in ("a", "b", "c", "d"):
                azs.append("%s%s" % (region, az))

            return azs

        if stripped_fn_lower == "base64":
            value_to_encode = value[keys_list[0]]
            value_to_encode = resolve_refs_recursively(stack_name, value_to_encode, resources)
            return to_str(base64.b64encode(to_bytes(value_to_encode)))

        for key, val in dict(value).items():
            value[key] = resolve_refs_recursively(stack_name, val, resources)

    if isinstance(value, list):
        for i in range(len(value)):
            value[i] = resolve_refs_recursively(stack_name, value[i], resources)

    return value


def resolve_placeholders_in_string(result, stack_name=None, resources=None):
    def _replace(match):
        parts = match.group(1).split(".")
        if len(parts) >= 2:
            resource_name, _, attr_name = match.group(1).partition(".")
            resolved = resolve_ref(
                stack_name, resource_name.strip(), resources, attribute=attr_name.strip()
            )
            if resolved is None:
                raise DependencyNotYetSatisfied(
                    resource_ids=resource_name,
                    message="Unable to resolve attribute ref %s" % match.group(1),
                )
            return resolved
        if len(parts) == 1 and parts[0] in resources:
            resource_json = resources[parts[0]]
            result = extract_resource_attribute(
                resource_json.get("Type"),
                {},
                "Ref",
                resources=resources,
                resource_id=parts[0],
                stack_name=stack_name,
            )
            if result is None:
                raise DependencyNotYetSatisfied(
                    resource_ids=parts[0],
                    message="Unable to resolve attribute ref %s" % match.group(1),
                )
            return result
        # TODO raise exception here?
        return match.group(0)

    regex = r"\$\{([^\}]+)\}"
    result = re.sub(regex, _replace, result)
    return result


def evaluate_condition(stack_name, condition, resources):
    condition = resolve_refs_recursively(stack_name, condition, resources)
    condition = resolve_ref(stack_name, condition, resources, attribute="Ref")
    condition = resolve_refs_recursively(stack_name, condition, resources)
    return condition


def evaluate_resource_condition(resource, stack_name, resources):
    condition = resource.get("Condition")
    if condition:
        condition = evaluate_condition(stack_name, condition, resources)
        if condition is False or condition in FALSE_STRINGS or is_none_or_empty_value(condition):
            return False
    return True


def get_stack_parameter(stack_name, parameter):
    try:
        client = aws_stack.connect_to_service("cloudformation")
        stack = client.describe_stacks(StackName=stack_name)["Stacks"]
    except Exception:
        return None
    stack = stack and stack[0]
    if not stack:
        return None
    result = [p["ParameterValue"] for p in stack["Parameters"] if p["ParameterKey"] == parameter]
    return (result or [None])[0]


def update_resource(resource_id, resources, stack_name):
    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    if resource_type not in UPDATEABLE_RESOURCES:
        LOG.warning('Unable to update resource type "%s", id "%s"' % (resource_type, resource_id))
        return
    LOG.info("Updating resource %s of type %s" % (resource_id, resource_type))

    instance = get_resource_model_instance(resource_id, resources)
    if instance:
        result = instance.update_resource(resource, stack_name=stack_name, resources=resources)
        instance.fetch_and_update_state(stack_name=stack_name, resources=resources)
        return result


def get_resource_model_instance(resource_id, resources) -> GenericBaseModel:
    """Obtain a typed resource entity instance representing the given stack resource."""
    resource = resources[resource_id]
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
                if common.is_string(v, exclude_binary=True):
                    o[k] = aws_stack.fix_account_id_in_arns(v)
        elif common.is_string(o, exclude_binary=True):
            o = aws_stack.fix_account_id_in_arns(o)
        return o

    result = common.recurse_object(params, fix_ids)
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
        if _type == int:
            return int(_obj)
        return _obj

    def fix_types(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in attr_names:
                    o[k] = cast(v, types[k])
        return o

    result = common.recurse_object(params, fix_types)
    return result


# TODO remove this method
def prepare_template_body(req_data):
    return template_preparer.prepare_template_body(req_data)


def deploy_resource(resource_id, resources, stack_name):
    result = execute_resource_action(resource_id, resources, stack_name, ACTION_CREATE)
    return result


def delete_resource(resource_id, resources, stack_name):
    res = resources[resource_id]
    res_type = res.get("Type")

    if res_type == "AWS::S3::Bucket":
        s3_listener.remove_bucket_notification(res["PhysicalResourceId"])

    if res_type == "AWS::IAM::Role":
        role_name = res.get("PhysicalResourceId") or res.get("Properties", {}).get("RoleName")
        try:
            iam_client = aws_stack.connect_to_service("iam")
            rs = iam_client.list_role_policies(RoleName=role_name)
            for policy in rs["PolicyNames"]:
                iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy)

            rs = iam_client.list_instance_profiles_for_role(RoleName=role_name)
            for instance_profile in rs["InstanceProfiles"]:
                ip_name = instance_profile["InstanceProfileName"]
                iam_client.remove_role_from_instance_profile(
                    InstanceProfileName=ip_name, RoleName=role_name
                )
                # iam_client.delete_instance_profile(
                #     InstanceProfileName=ip_name
                # )

        except Exception as e:
            if "NoSuchEntity" not in str(e):
                raise

    if res_type == "AWS::EC2::VPC":
        state = res[KEY_RESOURCE_STATE]
        physical_resource_id = res["PhysicalResourceId"] or state.get("VpcId")
        res["PhysicalResourceId"] = physical_resource_id

        if state.get("VpcId"):
            ec2_client = aws_stack.connect_to_service("ec2")
            resp = ec2_client.describe_route_tables(
                Filters=[
                    {"Name": "vpc-id", "Values": [state.get("VpcId")]},
                    {"Name": "association.main", "Values": ["false"]},
                ]
            )
            for rt in resp["RouteTables"]:
                ec2_client.delete_route_table(RouteTableId=rt["RouteTableId"])

    if res_type == "AWS::EC2::Subnet":
        state = res[KEY_RESOURCE_STATE]
        physical_resource_id = res["PhysicalResourceId"] or state["SubnetId"]
        res["PhysicalResourceId"] = physical_resource_id

    if res_type == "AWS::EC2::RouteTable":
        ec2_client = aws_stack.connect_to_service("ec2")
        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"]]

        vpc_id = res.get("Properties", {}).get("VpcId")
        if vpc_id not in vpcs:
            # VPC already deleted before
            return

    return execute_resource_action(resource_id, resources, stack_name, ACTION_DELETE)


def execute_resource_action_fallback(
    action_name, resource_id, resources, stack_name, resource, resource_type
):
    # using moto as fallback for now - TODO remove in the future!
    msg = 'Action "%s" for resource type %s not yet implemented' % (
        action_name,
        resource_type,
    )
    long_type = canonical_resource_type(resource_type)
    clazz = parsing.MODEL_MAP.get(long_type)
    if not clazz:
        LOG.warning(msg)
        return
    LOG.info("%s - using fallback mechanism" % msg)
    if action_name == ACTION_CREATE:
        resource_name = get_resource_name(resource) or resource_id
        result = clazz.create_from_cloudformation_json(
            resource_name, resource, aws_stack.get_region()
        )
        return result


def execute_resource_action(resource_id, resources, stack_name, action_name):
    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    func_details = get_deployment_config(resource_type)

    if not func_details or action_name not in func_details:
        if resource_type in ["Parameter"]:
            return
        return execute_resource_action_fallback(
            action_name, resource_id, resources, stack_name, resource, resource_type
        )

    LOG.debug(
        'Running action "%s" for resource type "%s" id "%s"'
        % (action_name, resource_type, resource_id)
    )
    func_details = func_details[action_name]
    func_details = func_details if isinstance(func_details, list) else [func_details]
    results = []
    for func in func_details:
        if callable(func["function"]):
            result = func["function"](resource_id, resources, resource_type, func, stack_name)
            results.append(result)
            continue
        client = get_client(resource, func)
        if client:
            result = configure_resource_via_sdk(
                resource_id, resources, resource_type, func, stack_name, action_name
            )
            results.append(result)
    return (results or [None])[0]


def fix_resource_props_for_sdk_deployment(resource_type, resource_props):
    if resource_type == "Lambda::Function":
        # Properties will be validated by botocore before sending request to AWS
        # botocore/data/lambda/2015-03-31/service-2.json:1161 (EnvironmentVariableValue)
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-environment.html
        if "Environment" in resource_props:
            environment_variables = resource_props["Environment"].get("Variables", {})
            resource_props["Environment"]["Variables"] = {
                k: str(v) for k, v in environment_variables.items()
            }

    if resource_type == "SQS::Queue":
        # https://github.com/localstack/localstack/issues/3004
        if "ReceiveMessageWaitTimeSeconds" in resource_props:
            resource_props["ReceiveMessageWaitTimeSeconds"] = int(
                resource_props["ReceiveMessageWaitTimeSeconds"]
            )

    if resource_type == "KMS::Key":
        resource_props["KeyPolicy"] = json.dumps(resource_props.get("KeyPolicy", {}))
        resource_props["Enabled"] = resource_props.get("Enabled", True)
        resource_props["EnableKeyRotation"] = resource_props.get("EnableKeyRotation", False)
        resource_props["Description"] = resource_props.get("Description", "")


def configure_resource_via_sdk(
    resource_id, resources, resource_type, func_details, stack_name, action_name
):
    resource = resources[resource_id]

    if resource_type == "EC2::Instance":
        if action_name == "create":
            func_details["boto_client"] = "resource"

    client = get_client(resource, func_details)
    function = getattr(client, func_details["function"])
    params = func_details.get("parameters") or lambda_get_params()
    defaults = func_details.get("defaults", {})
    resource_props = resource["Properties"] = resource.get("Properties", {})
    resource_props = dict(resource_props)
    resource_state = resource.get(KEY_RESOURCE_STATE, {})

    # Validate props for each resource type
    fix_resource_props_for_sdk_deployment(resource_type, resource_props)

    if callable(params):
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
                if prop_key == PLACEHOLDER_RESOURCE_NAME:
                    params[param_key] = PLACEHOLDER_RESOURCE_NAME
                else:
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

    # replace PLACEHOLDER_RESOURCE_NAME in params
    resource_name_holder = {}

    def fix_placeholders(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if v == PLACEHOLDER_RESOURCE_NAME:
                    if "value" not in resource_name_holder:
                        resource_name_holder["value"] = get_resource_name(resource) or resource_id
                    o[k] = resource_name_holder["value"]
        return o

    common.recurse_object(params, fix_placeholders)

    # assign default values if empty
    params = common.merge_recursive(defaults, params)

    # this is an indicator that we should skip this resource deployment, and return
    if params is None:
        return

    # convert refs
    for param_key, param_value in dict(params).items():
        if param_value is not None:
            param_value = params[param_key] = resolve_refs_recursively(
                stack_name, param_value, resources
            )

    # convert any moto account IDs (123456789012) in ARNs to our format (000000000000)
    params = fix_account_id_in_arns(params)
    # convert data types (e.g., boolean strings to bool)
    params = convert_data_types(func_details, params)
    # remove None values, as they usually raise boto3 errors
    params = remove_none_values(params)

    # convert boolean strings
    #  (TODO: we should find a more reliable mechanism than this opportunistic/probabilistic approach!)
    params_before_conversion = copy.deepcopy(params)
    for param_key, param_value in dict(params).items():
        # Convert to boolean (TODO: do this recursively?)
        if str(param_value).lower() in ["true", "false"]:
            params[param_key] = str(param_value).lower() == "true"

    # invoke function
    try:
        LOG.debug(
            'Request for resource type "%s" in region %s: %s %s'
            % (resource_type, aws_stack.get_region(), func_details["function"], params)
        )
        try:
            result = function(**params)
        except botocore.exceptions.ParamValidationError as e:
            LOG.debug(f"Trying original parameters: {params_before_conversion}")
            if "type: <class 'bool'>" not in str(e):
                raise
            result = function(**params_before_conversion)
    except Exception as e:
        if action_name == "delete" and check_not_found_exception(e, resource_type, resource):
            return
        LOG.warning(
            "Error calling %s with params: %s for resource: %s" % (function, params, resource)
        )
        raise e

    return result


def get_action_name_for_resource_change(res_change):
    return {"Add": "CREATE", "Remove": "DELETE", "Modify": "UPDATE"}.get(res_change)


# TODO: this shouldn't be called for stack parameters
def determine_resource_physical_id(
    resource_id, resources=None, stack=None, attribute=None, stack_name=None
):
    resources = resources or stack.resources
    stack_name = stack_name or stack.stack_name
    resource = resources.get(resource_id, {})
    if not resource:
        return
    resource_type = resource.get("Type") or ""
    resource_type = re.sub("^AWS::", "", resource_type)
    resource_props = resource.get("Properties", {})

    # determine result from resource class
    canonical_type = canonical_resource_type(resource_type)
    resource_class = RESOURCE_MODELS.get(canonical_type)
    if resource_class:
        resource_inst = resource_class(resource)
        resource_inst.fetch_state_if_missing(stack_name=stack_name, resources=resources)
        result = resource_inst.get_physical_resource_id(attribute=attribute)
        if result:
            return result

    # TODO: put logic into resource-specific model classes!
    if resource_type == "ApiGateway::RestApi":
        result = resource_props.get("id")
        if result:
            return result
    elif resource_type == "ApiGateway::Stage":
        return resource_props.get("StageName")
    elif resource_type == "AppSync::DataSource":
        return resource_props.get("DataSourceArn")
    elif resource_type == "KinesisFirehose::DeliveryStream":
        return aws_stack.firehose_stream_arn(resource_props.get("DeliveryStreamName"))
    elif resource_type == "StepFunctions::StateMachine":
        return aws_stack.state_machine_arn(
            resource_props.get("StateMachineName")
        )  # returns ARN in AWS
    elif resource_type == "S3::Bucket":
        if attribute == "Arn":
            return aws_stack.s3_bucket_arn(resource_props.get("BucketName"))
        return resource_props.get("BucketName")  # Note: "Ref" returns bucket name in AWS
    elif resource_type == "IAM::Role":
        if attribute == "Arn":
            return aws_stack.role_arn(resource_props.get("RoleName"))
        return resource_props.get("RoleName")
    elif resource_type == "SecretsManager::Secret":
        arn = get_secret_arn(resource_props.get("Name")) or ""
        if attribute == "Arn":
            return arn
        return arn.split(":")[-1]
    elif resource_type == "IAM::Policy":
        if attribute == "Arn":
            return aws_stack.policy_arn(resource_props.get("PolicyName"))
        return resource_props.get("PolicyName")
    elif resource_type == "DynamoDB::Table":
        table_name = resource_props.get("TableName")
        if table_name:
            if attribute == "Ref":
                return table_name  # Note: "Ref" returns table name in AWS
            return table_name
    elif resource_type == "Logs::LogGroup":
        return resource_props.get("LogGroupName")

    res_id = resource.get("PhysicalResourceId")
    if res_id and attribute in [None, "Ref", "PhysicalResourceId"]:
        return res_id
    result = extract_resource_attribute(
        resource_type,
        {},
        attribute or "PhysicalResourceId",
        stack_name=stack_name,
        resource_id=resource_id,
        resource=resource,
        resources=resources,
    )
    if result is not None:
        # note that value could be an empty string here (in case of Parameter values)
        return result

    LOG.info(
        'Unable to determine PhysicalResourceId for "%s" resource, ID "%s"'
        % (resource_type, resource_id)
    )


def update_resource_details(stack, resource_id, details, action=None):
    resource = stack.resources.get(resource_id, {})
    if not resource or not details:
        return

    # TODO: we need to rethink this method - this should be encapsulated in the resource model classes.
    #   Also, instead of actively updating the PhysicalResourceId attributes below, they should be
    #   determined and returned by the resource model classes upon request.

    resource_type = resource.get("Type") or ""
    resource_type = re.sub("^AWS::", "", resource_type)
    resource_props = resource.get("Properties", {})

    if resource_type == "ApiGateway::RestApi":
        resource_props["id"] = details["id"]

    if resource_type == "KMS::Key":
        resource["PhysicalResourceId"] = details["KeyMetadata"]["KeyId"]

    if resource_type == "EC2::Instance":
        if details and isinstance(details, list) and hasattr(details[0], "id"):
            resource["PhysicalResourceId"] = details[0].id
        if isinstance(details, dict) and details.get("InstanceId"):
            resource["PhysicalResourceId"] = details["InstanceId"]

    if resource_type == "EC2::SecurityGroup":
        resource["PhysicalResourceId"] = details["GroupId"]

    if resource_type == "IAM::InstanceProfile":
        resource["PhysicalResourceId"] = details["InstanceProfile"]["InstanceProfileName"]

    if resource_type == "StepFunctions::Activity":
        resource["PhysicalResourceId"] = details["activityArn"]

    if resource_type == "ApiGateway::Model":
        resource["PhysicalResourceId"] = details["id"]

    if resource_type == "EC2::VPC":
        resource["PhysicalResourceId"] = details["Vpc"]["VpcId"]

    if resource_type == "EC2::Subnet":
        resource["PhysicalResourceId"] = details["Subnet"]["SubnetId"]

    if resource_type == "EC2::RouteTable":
        resource["PhysicalResourceId"] = details["RouteTable"]["RouteTableId"]

    if resource_type == "EC2::Route":
        resource["PhysicalResourceId"] = generate_route_id(
            resource_props["RouteTableId"],
            resource_props.get("DestinationCidrBlock", ""),
            resource_props.get("DestinationIpv6CidrBlock"),
        )

    # TODO remove!
    if isinstance(details, MotoCloudFormationModel):
        # fallback: keep track of moto resource status
        stack.moto_resource_statuses[resource_id] = details


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
    props = resource["Properties"] = resource.get("Properties", {})
    existing_resources = existing_resources or {}

    def _generate_res_name():
        return "%s-%s-%s" % (stack_name, resource_name or resource_id, short_uid())

    # TODO: move logic below into resource classes!

    if res_type == "AWS::Lambda::EventSourceMapping" and not props.get("StartingPosition"):
        props["StartingPosition"] = "LATEST"

    elif res_type == "AWS::Logs::LogGroup" and not props.get("LogGroupName") and resource_name:
        props["LogGroupName"] = resource_name

    elif res_type == "AWS::Lambda::Function" and not props.get("FunctionName"):
        # FunctionName is up to 64 characters long
        random_id_part = short_uid()
        resource_id_part = resource_id[:24]
        stack_name_part = stack_name[: 63 - 2 - (len(random_id_part) + len(resource_id_part))]
        props["FunctionName"] = f"{stack_name_part}-{resource_id_part}-{random_id_part}"

    elif res_type == "AWS::SNS::Topic" and not props.get("TopicName"):
        props["TopicName"] = "topic-%s" % short_uid()

    elif res_type == "AWS::SQS::Queue" and not props.get("QueueName"):
        props["QueueName"] = "queue-%s" % short_uid()

    elif res_type == "AWS::IAM::ManagedPolicy" and not resource.get("ManagedPolicyName"):
        resource["ManagedPolicyName"] = _generate_res_name()

    elif res_type == "AWS::ApiGateway::RestApi" and not props.get("Name"):
        props["Name"] = _generate_res_name()

    elif res_type == "AWS::ApiGateway::Stage" and not props.get("StageName"):
        props["StageName"] = "default"

    elif res_type == "AWS::ApiGateway::ApiKey" and not props.get("Name"):
        props["Name"] = _generate_res_name()

    elif res_type == "AWS::ApiGateway::UsagePlan" and not props.get("UsagePlanName"):
        props["UsagePlanName"] = _generate_res_name()

    elif res_type == "AWS::ApiGateway::Model" and not props.get("Name"):
        props["Name"] = _generate_res_name()

    elif res_type == "AWS::ApiGateway::RequestValidator" and not props.get("Name"):
        props["Name"] = _generate_res_name()

    elif res_type == "AWS::DynamoDB::Table":
        update_dynamodb_index_resource(resource)
        props["TableName"] = props.get("TableName") or _generate_res_name()

    elif res_type == "AWS::CloudWatch::Alarm":
        props["AlarmName"] = props.get("AlarmName") or _generate_res_name()

    elif res_type == "AWS::SecretsManager::Secret":
        props["Name"] = props.get("Name") or _generate_res_name()

    elif res_type == "AWS::S3::Bucket" and not props.get("BucketName"):
        existing_bucket = existing_resources.get(resource_id) or {}
        bucket_name = (
            existing_bucket.get("Properties", {}).get("BucketName") or _generate_res_name()
        )
        props["BucketName"] = s3_listener.normalize_bucket_name(bucket_name)

    elif res_type == "AWS::StepFunctions::StateMachine" and not props.get("StateMachineName"):
        props["StateMachineName"] = _generate_res_name()

    elif res_type == "AWS::CloudFormation::Stack" and not props.get("StackName"):
        props["StackName"] = _generate_res_name()

    elif res_type == "AWS::EC2::SecurityGroup":
        props["GroupName"] = props.get("GroupName") or _generate_res_name()

    elif res_type == "AWS::Redshift::Cluster":
        props["ClusterIdentifier"] = props.get("ClusterIdentifier") or _generate_res_name()

    elif res_type == "AWS::IAM::InstanceProfile":
        props["InstanceProfileName"] = props.get("InstanceProfileName") or _generate_res_name()

    elif res_type == "AWS::Logs::LogGroup":
        props["LogGroupName"] = props.get("LogGroupName") or _generate_res_name()

    elif res_type == "AWS::KMS::Key":
        tags = props["Tags"] = props.get("Tags", [])
        existing = [t for t in tags if t["Key"] == "localstack-key-id"]
        if not existing:
            # append tags, to allow us to determine in service_models.py whether this key is already deployed
            tags.append({"Key": "localstack-key-id", "Value": short_uid()})

    elif res_type == "AWS::IAM::ManagedPolicy":
        props["ManagedPolicyName"] = props.get("ManagedPolicyName") or _generate_res_name()

    # generate default names for certain resource types
    default_attrs = (("AWS::IAM::Role", "RoleName"), ("AWS::Events::Rule", "Name"))
    for entry in default_attrs:
        if res_type == entry[0] and not props.get(entry[1]):
            if not resource_id:
                resource_id = canonical_json(json_safe(props))
                resource_id = md5(resource_id)
            props[entry[1]] = "cf-%s-%s" % (stack_name, resource_id)


def update_dynamodb_index_resource(resource):
    if resource.get("Properties").get("BillingMode") == "PAY_PER_REQUEST":
        for glob_index in resource.get("Properties", {}).get("GlobalSecondaryIndexes", []):
            if not glob_index.get("ProvisionedThroughput"):
                glob_index["ProvisionedThroughput"] = {
                    "ReadCapacityUnits": 99,
                    "WriteCapacityUnits": 99,
                }


# -----------------------
# MAIN TEMPLATE DEPLOYER
# -----------------------


class TemplateDeployer(object):
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
                stack_name=self.stack.stack_name,
                initialize=True,
                action="CREATE",
            )
        except Exception as e:
            LOG.info("Unable to create stack %s: %s" % (self.stack.stack_name, e))
            self.stack.set_stack_status("CREATE_FAILED")
            raise

    def apply_change_set(self, change_set):
        action = "CREATE"
        change_set.stack.set_stack_status("%s_IN_PROGRESS" % action)
        try:
            self.apply_changes(
                change_set.stack,
                change_set,
                stack_name=change_set.stack_name,
                action=action,
            )
        except Exception as e:
            LOG.info(
                "Unable to apply change set %s: %s" % (change_set.metadata.get("ChangeSetName"), e)
            )
            change_set.metadata["Status"] = "%s_FAILED" % action
            self.stack.set_stack_status("%s_FAILED" % action)
            raise

    def update_stack(self, new_stack):
        self.stack.set_stack_status("UPDATE_IN_PROGRESS")
        # apply changes
        self.apply_changes(self.stack, new_stack, stack_name=self.stack.stack_name, action="UPDATE")

    def delete_stack(self):
        if not self.stack:
            return
        self.stack.set_stack_status("DELETE_IN_PROGRESS")
        stack_resources = list(self.stack.resources.values())
        stack_name = self.stack.stack_name
        resources = dict([(r["LogicalResourceId"], common.clone_safe(r)) for r in stack_resources])
        for key, resource in resources.items():
            resource["Properties"] = resource.get("Properties", common.clone_safe(resource))
            resource["ResourceType"] = resource.get("ResourceType") or resource.get("Type")
        for resource_id, resource in resources.items():
            # TODO: cache condition value in resource details on deployment and use cached value here
            if evaluate_resource_condition(resource, stack_name, resources):
                delete_resource(resource_id, resources, stack_name)
                self.stack.set_resource_status(resource_id, "DELETE_COMPLETE")
        # update status
        self.stack.set_stack_status("DELETE_COMPLETE")

    # ----------------------------
    # DEPENDENCY RESOLUTION UTILS
    # ----------------------------

    def is_deployable_resource(self, resource):
        resource_type = get_resource_type(resource)
        entry = get_deployment_config(resource_type)
        if entry is None and resource_type not in ["Parameter", None]:
            # fall back to moto resource creation (TODO: remove in the future)
            long_res_type = canonical_resource_type(resource_type)
            if long_res_type in parsing.MODEL_MAP:
                return True
            LOG.warning('Unable to deploy resource type "%s": %s' % (resource_type, resource))
        return bool(entry and entry.get(ACTION_CREATE))

    def is_deployed(self, resource):
        resource_status = {}
        resource_id = resource["LogicalResourceId"]
        details = retrieve_resource_details(
            resource_id, resource_status, self.resources, self.stack_name
        )
        return bool(details)

    def is_updateable(self, resource):
        """Return whether the given resource can be updated or not."""
        if not self.is_deployable_resource(resource) or not self.is_deployed(resource):
            return False
        resource_type = get_resource_type(resource)
        return resource_type in UPDATEABLE_RESOURCES

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
        for resource_id, resource in iteritems(resources):
            if self.is_deployable_resource(resource):
                if not self.is_deployed(resource):
                    LOG.debug(
                        "Dependency for resource %s not yet deployed: %s %s"
                        % (depending_resource, resource_id, resource)
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
        dumped = json.dumps(common.json_safe(raw_resource))
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

    def add_default_resource_props(self, resources=None):
        resources = resources or self.resources
        for resource_id, resource in resources.items():
            add_default_resource_props(resource, self.stack_name, resource_id=resource_id)

    def init_resource_status(self, resources=None, stack=None, action="CREATE"):
        resources = resources or self.resources
        stack = stack or self.stack
        for resource_id, resource in resources.items():
            stack.set_resource_status(resource_id, "%s_IN_PROGRESS" % action)

    def update_resource_details(self, resource_id, result, stack=None, action="CREATE"):
        stack = stack or self.stack
        # update resource state
        update_resource_details(stack, resource_id, result, action)
        # update physical resource id
        resource = stack.resources[resource_id]

        physical_id = resource.get("PhysicalResourceId")

        physical_id = physical_id or determine_resource_physical_id(resource_id, stack=stack)
        if not resource.get("PhysicalResourceId") or action == "UPDATE":
            if physical_id:
                resource["PhysicalResourceId"] = physical_id

        # set resource status
        stack.set_resource_status(resource_id, "%s_COMPLETE" % action, physical_res_id=physical_id)

        return physical_id

    def get_change_config(self, action, resource, change_set_id=None):
        return {
            "Type": "Resource",
            "ResourceChange": {
                "Action": action,
                "LogicalResourceId": resource.get("LogicalResourceId"),
                "PhysicalResourceId": resource.get("PhysicalResourceId"),
                "ResourceType": resource.get("Type"),
                "Replacement": "False",
                "ChangeSetId": change_set_id,
            },
        }

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

        parameters.update({p["ParameterKey"]: p for p in new_stack.metadata["Parameters"]})

        for change_set in new_stack.change_sets:
            parameters.update({p["ParameterKey"]: p for p in change_set.metadata["Parameters"]})

        # TODO: unclear/undocumented behavior in implicitly updating old_stack parameter here
        old_stack.metadata["Parameters"] = [v for v in parameters.values() if v]

    # TODO: fix circular import with cloudformation_api.py when importing Stack here
    def construct_changes(
        self,
        existing_stack,
        new_stack,
        initialize=False,
        change_set_id=None,
        append_to_changeset=False,
    ):
        from localstack.services.cloudformation.cloudformation_api import StackChangeSet

        old_resources = existing_stack.template["Resources"]
        new_resources = new_stack.template["Resources"]
        deletes = [val for key, val in old_resources.items() if key not in new_resources]
        adds = [val for key, val in new_resources.items() if initialize or key not in old_resources]
        modifies = [val for key, val in new_resources.items() if key in old_resources]

        changes = []
        for action, items in (("Remove", deletes), ("Add", adds), ("Modify", modifies)):
            for item in items:
                item["Properties"] = item.get("Properties", {})
                change = self.get_change_config(action, item, change_set_id=change_set_id)
                changes.append(change)

        # append changes to change set
        if append_to_changeset and isinstance(new_stack, StackChangeSet):
            new_stack.changes.extend(changes)

        return changes

    def apply_changes(
        self,
        existing_stack,
        new_stack,
        stack_name,
        change_set_id=None,
        initialize=False,
        action=None,
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

        # merge stack outputs
        existing_stack.template["Outputs"].update(new_stack.template.get("Outputs", {}))

        # start deployment loop
        return self.apply_changes_in_loop(
            changes, existing_stack, stack_name, action=action, new_stack=new_stack
        )

    def apply_changes_in_loop(self, changes, stack, stack_name, action=None, new_stack=None):
        from localstack.services.cloudformation.cloudformation_api import StackChangeSet

        def _run(*args):
            try:
                self.do_apply_changes_in_loop(changes, stack, stack_name)
                status = "%s_COMPLETE" % action
            except Exception as e:
                LOG.debug(
                    'Error applying changes for CloudFormation stack "%s": %s %s'
                    % (stack.stack_name, e, traceback.format_exc())
                )
                status = "%s_FAILED" % action
            stack.set_stack_status(status)
            if isinstance(new_stack, StackChangeSet):
                new_stack.metadata["Status"] = status
                new_stack.metadata["ExecutionStatus"] = (
                    "EXECUTE_FAILED" if "FAILED" in status else "EXECUTE_COMPLETE"
                )
                new_stack.metadata["StatusReason"] = "Deployment %s" % (
                    "failed" if "FAILED" in status else "succeeded"
                )

        # run deployment in background loop, to avoid client network timeouts
        return start_worker_thread(_run)

    def do_apply_changes_in_loop(self, changes, stack, stack_name):
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
                            'Handling "%s" for resource "%s" (%s/%s) type "%s" in loop iteration %s'
                            % (
                                action,
                                resource_id,
                                j + 1,
                                len(changes),
                                res_change["ResourceType"],
                                i + 1,
                            )
                        )
                        if not should_deploy:
                            del changes[j]
                            stack_action = get_action_name_for_resource_change(action)
                            stack.set_resource_status(resource_id, "%s_COMPLETE" % stack_action)
                            continue
                        if not self.all_resource_dependencies_satisfied(resource):
                            j += 1
                            continue
                    self.apply_change(change, stack, new_resources, stack_name=stack_name)
                    changes_done.append(change)
                    del changes[j]
                    updated = True
                except DependencyNotYetSatisfied as e:
                    LOG.debug(
                        'Dependencies for "%s" not yet satisfied, retrying in next loop: %s'
                        % (resource_id, e)
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

        return changes_done

    def prepare_should_deploy_change(self, resource_id, change, stack, new_resources):
        resource = new_resources[resource_id]
        res_change = change["ResourceChange"]
        action = res_change["Action"]

        # check resource condition, if present
        if not evaluate_resource_condition(resource, stack.stack_name, new_resources):
            LOG.debug(
                'Skipping deployment of "%s", as resource condition evaluates to false'
                % resource_id
            )
            return

        # resolve refs in resource details
        resolve_refs_recursively(stack.stack_name, resource, new_resources)

        if action in ["Add", "Modify"]:
            is_deployed = self.is_deployed(resource)
            if action == "Modify" and not is_deployed:
                action = res_change["Action"] = "Add"
            if action == "Add":
                if not self.is_deployable_resource(resource) or is_deployed:
                    return False
            if action == "Modify" and not self.is_updateable(resource):
                LOG.debug(
                    'Action "update" not yet implemented for CF resource type %s'
                    % resource.get("Type")
                )
                return False
        return True

    def apply_change(self, change, old_stack, new_resources, stack_name):
        change_details = change["ResourceChange"]
        action = change_details["Action"]
        resource_id = change_details["LogicalResourceId"]
        resource = new_resources[resource_id]
        if not evaluate_resource_condition(resource, stack_name, new_resources):
            return
        # execute resource action
        result = None
        if action == "Add":
            result = deploy_resource(resource_id, new_resources, stack_name)
        elif action == "Remove":
            result = delete_resource(resource_id, old_stack.resources, stack_name)
        elif action == "Modify":
            result = update_resource(resource_id, new_resources, stack_name)

        # update resource status and physical resource id
        stack_action = get_action_name_for_resource_change(action)
        self.update_resource_details(resource_id, result, stack=old_stack, action=stack_action)

        return result
