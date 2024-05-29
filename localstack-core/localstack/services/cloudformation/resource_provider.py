from __future__ import annotations

import copy
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from logging import Logger
from math import ceil
from typing import TYPE_CHECKING, Any, Callable, Generic, Optional, Type, TypedDict, TypeVar

import botocore
from plux import Plugin, PluginManager

from localstack import config
from localstack.aws.connect import ServiceLevelClientFactory, connect_to
from localstack.services.cloudformation import usage
from localstack.services.cloudformation.deployment_utils import (
    check_not_found_exception,
    convert_data_types,
    fix_account_id_in_arns,
    fix_boto_parameters_based_on_report,
    log_not_available_message,
    remove_none_values,
)
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.service_models import KEY_RESOURCE_STATE

PRO_RESOURCE_PROVIDERS = False
try:
    from localstack_ext.services.cloudformation.resource_provider import (
        CloudFormationResourceProviderPluginExt,
    )

    PRO_RESOURCE_PROVIDERS = True
except ImportError:
    pass

if TYPE_CHECKING:
    from localstack.services.cloudformation.engine.types import (
        FuncDetails,
        FuncDetailsValue,
        ResourceDefinition,
    )

LOG = logging.getLogger(__name__)

Properties = TypeVar("Properties")

PUBLIC_REGISTRY: dict[str, Type[ResourceProvider]] = {}

PROVIDER_DEFAULTS = {}  # TODO: remove this after removing patching in -ext


class OperationStatus(Enum):
    PENDING = auto()
    IN_PROGRESS = auto()
    SUCCESS = auto()
    FAILED = auto()


@dataclass
class ProgressEvent(Generic[Properties]):
    status: OperationStatus
    resource_model: Properties

    message: str = ""
    result: Optional[str] = None
    error_code: Optional[str] = None  # TODO: enum
    custom_context: dict = field(default_factory=dict)


class Credentials(TypedDict):
    accessKeyId: str
    secretAccessKey: str
    sessionToken: str


class ResourceProviderPayloadRequestData(TypedDict):
    logicalResourceId: str
    resourceProperties: Properties
    previousResourceProperties: Optional[Properties]
    callerCredentials: Credentials
    providerCredentials: Credentials
    systemTags: dict[str, str]
    previousSystemTags: dict[str, str]
    stackTags: dict[str, str]
    previousStackTags: dict[str, str]


class ResourceProviderPayload(TypedDict):
    callbackContext: dict
    stackId: str
    requestData: ResourceProviderPayloadRequestData
    resourceType: str
    resourceTypeVersion: str
    awsAccountId: str
    bearerToken: str
    region: str
    action: str


ResourceProperties = TypeVar("ResourceProperties")


def convert_payload(
    stack_name: str, stack_id: str, payload: ResourceProviderPayload
) -> ResourceRequest[Properties]:
    client_factory = connect_to(
        aws_access_key_id=payload["requestData"]["callerCredentials"]["accessKeyId"],
        aws_session_token=payload["requestData"]["callerCredentials"]["sessionToken"],
        aws_secret_access_key=payload["requestData"]["callerCredentials"]["secretAccessKey"],
        region_name=payload["region"],
    )
    desired_state = payload["requestData"]["resourceProperties"]
    rr = ResourceRequest(
        _original_payload=desired_state,
        aws_client_factory=client_factory,
        request_token=str(uuid.uuid4()),  # TODO: not actually a UUID
        stack_name=stack_name,
        stack_id=stack_id,
        account_id=payload["awsAccountId"],
        region_name=payload["region"],
        desired_state=desired_state,
        logical_resource_id=payload["requestData"]["logicalResourceId"],
        resource_type=payload["resourceType"],
        logger=logging.getLogger("abc"),
        custom_context=payload["callbackContext"],
        action=payload["action"],
    )

    if previous_properties := payload["requestData"].get("previousResourceProperties"):
        rr.previous_state = previous_properties

    return rr


@dataclass
class ResourceRequest(Generic[Properties]):
    _original_payload: Properties

    aws_client_factory: ServiceLevelClientFactory
    request_token: str
    stack_name: str
    stack_id: str
    account_id: str
    region_name: str
    action: str

    desired_state: Properties

    logical_resource_id: str
    resource_type: str

    logger: Logger

    custom_context: dict = field(default_factory=dict)

    previous_state: Optional[Properties] = None
    previous_tags: Optional[dict[str, str]] = None
    tags: dict[str, str] = field(default_factory=dict)


class CloudFormationResourceProviderPlugin(Plugin):
    """
    Base class for resource provider plugins.
    """

    namespace = "localstack.cloudformation.resource_providers"


class ResourceProvider(Generic[Properties]):
    """
    This provides a base class onto which service-specific resource providers are built.
    """

    def create(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        raise NotImplementedError

    def update(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        raise NotImplementedError

    def delete(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        raise NotImplementedError


# legacy helpers
def get_resource_type(resource: dict) -> str:
    """this is currently overwritten in PRO to add support for custom resources"""
    if isinstance(resource, str):
        raise ValueError(f"Invalid argument: {resource}")
    try:
        resource_type: str = resource["Type"]

        if resource_type.startswith("Custom::"):
            return "AWS::CloudFormation::CustomResource"
        return resource_type
    except Exception:
        LOG.warning(
            "Failed to retrieve resource type %s",
            resource.get("Type"),
            exc_info=LOG.isEnabledFor(logging.DEBUG),
        )


def invoke_function(
    account_id: str,
    region_name: str,
    function: Callable,
    params: dict,
    resource_type: str,
    func_details: FuncDetails,
    action_name: str,
    resource: Any,
) -> Any:
    try:
        LOG.debug(
            'Request for resource type "%s" in account %s region %s: %s %s',
            resource_type,
            account_id,
            region_name,
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
            LOG.debug("Report: %s", report)
            converted_params = fix_boto_parameters_based_on_report(params, report)
            LOG.debug("Original parameters:  %s", params)
            LOG.debug("Converted parameters: %s", converted_params)

            result = function(**converted_params)
    except Exception as e:
        if action_name == "Remove" and check_not_found_exception(e, resource_type, resource):
            return
        log_method = LOG.warning
        if config.CFN_VERBOSE_ERRORS:
            log_method = LOG.exception
        log_method("Error calling %s with params: %s for resource: %s", function, params, resource)
        raise e

    return result


def get_service_name(resource):
    res_type = resource["Type"]
    parts = res_type.split("::")
    if len(parts) == 1:
        return None
    if "Cognito::IdentityPool" in res_type:
        return "cognito-identity"
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
    if "ElasticLoadBalancing::" in res_type:
        return "elb"
    if "ElasticLoadBalancingV2::" in res_type:
        return "elbv2"
    if "ApplicationAutoScaling::" in res_type:
        return "application-autoscaling"
    if "MSK::" in res_type:
        return "kafka"
    if "Timestream::" in res_type:
        return "timestream-write"
    return parts[1].lower()


def resolve_resource_parameters(
    account_id_: str,
    region_name_: str,
    stack_name: str,
    resource_definition: ResourceDefinition,
    resources: dict[str, ResourceDefinition],
    resource_id: str,
    func_details: FuncDetailsValue,
) -> dict | None:
    params = func_details.get("parameters") or (
        lambda account_id, region_name, properties, logical_resource_id, *args, **kwargs: properties
    )
    resource_props = resource_definition["Properties"] = resource_definition.get("Properties", {})
    resource_props = dict(resource_props)
    resource_state = resource_definition.get(KEY_RESOURCE_STATE, {})
    last_deployed_state = resource_definition.get("_last_deployed_state", {})

    if callable(params):
        # resolve parameter map via custom function
        params = params(
            account_id_, region_name_, resource_props, resource_id, resource_definition, stack_name
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
        # TODO(srw): mutably mapping params :(
        for param_key, prop_keys in dict(params).items():
            params.pop(param_key, None)
            if not isinstance(prop_keys, list):
                prop_keys = [prop_keys]
            for prop_key in prop_keys:
                if callable(prop_key):
                    prop_value = prop_key(
                        account_id_,
                        region_name_,
                        resource_props,
                        resource_id,
                        resource_definition,
                        stack_name,
                    )
                else:
                    prop_value = resource_props.get(
                        prop_key,
                        resource_definition.get(
                            prop_key,
                            resource_state.get(prop_key, last_deployed_state.get(prop_key)),
                        ),
                    )
                if prop_value is not None:
                    params[param_key] = prop_value
                    break

    # this is an indicator that we should skip this resource deployment, and return
    if params is None:
        return

    # FIXME: move this to a single place after template processing is finished
    # convert any moto account IDs (123456789012) in ARNs to our format (000000000000)
    params = fix_account_id_in_arns(params, account_id_)
    # convert data types (e.g., boolean strings to bool)
    # TODO: this might not be needed anymore
    params = convert_data_types(func_details.get("types", {}), params)
    # remove None values, as they usually raise boto3 errors
    params = remove_none_values(params)

    return params


class NoResourceProvider(Exception):
    pass


def resolve_json_pointer(resource_props: Properties, primary_id_path: str) -> str:
    primary_id_path = primary_id_path.replace("/properties", "")
    parts = [p for p in primary_id_path.split("/") if p]

    resolved_part = resource_props.copy()
    for i in range(len(parts)):
        part = parts[i]
        resolved_part = resolved_part.get(part)
        if i == len(parts) - 1:
            # last part
            return resolved_part

    raise Exception(f"Resource properties is missing field: {part}")


class ResourceProviderExecutor:
    """
    Point of abstraction between our integration with generic base models, and the new providers.
    """

    def __init__(
        self,
        *,
        stack_name: str,
        stack_id: str,
    ):
        self.stack_name = stack_name
        self.stack_id = stack_id

    def deploy_loop(
        self,
        resource: dict,
        raw_payload: ResourceProviderPayload,
        max_timeout: int = config.CFN_PER_RESOURCE_TIMEOUT,
        sleep_time: float = 5,
    ) -> ProgressEvent[Properties]:
        payload = copy.deepcopy(raw_payload)

        max_iterations = max(ceil(max_timeout / sleep_time), 2)

        for current_iteration in range(max_iterations):
            resource_type = get_resource_type(
                {"Type": raw_payload["resourceType"]}
            )  # TODO: simplify signature of get_resource_type to just take the type
            try:
                resource_provider = self.load_resource_provider(resource_type)

                resource["SpecifiedProperties"] = raw_payload["requestData"]["resourceProperties"]

                event = self.execute_action(resource_provider, payload)

                match event.status:
                    case OperationStatus.FAILED:
                        return event
                    case OperationStatus.SUCCESS:
                        if not hasattr(resource_provider, "SCHEMA"):
                            raise Exception(
                                "A ResourceProvider should always have a SCHEMA property defined."
                            )
                        resource_type_schema = resource_provider.SCHEMA
                        physical_resource_id = (
                            self.extract_physical_resource_id_from_model_with_schema(
                                event.resource_model,
                                raw_payload["resourceType"],
                                resource_type_schema,
                            )
                        )

                        resource["PhysicalResourceId"] = physical_resource_id
                        resource["Properties"] = event.resource_model
                        resource["_last_deployed_state"] = copy.deepcopy(event.resource_model)
                        return event
                    case OperationStatus.IN_PROGRESS:
                        # update the shared state
                        context = {**payload["callbackContext"], **event.custom_context}
                        payload["callbackContext"] = context
                        payload["requestData"]["resourceProperties"] = event.resource_model

                        if current_iteration == 0:
                            time.sleep(0)
                        else:
                            time.sleep(sleep_time)
                    case OperationStatus.PENDING:
                        # come back to this resource in another iteration
                        return event
                    case invalid_status:
                        raise ValueError(
                            f"Invalid OperationStatus ({invalid_status}) returned for resource {raw_payload['requestData']['logicalResourceId']} (type {raw_payload['resourceType']})"
                        )

            except NoResourceProvider:
                log_not_available_message(
                    raw_payload["resourceType"],
                    f"No resource provider found for \"{raw_payload['resourceType']}\"",
                )

                usage.missing_resource_types.record(raw_payload["resourceType"])

                if config.CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES:
                    # TODO: figure out a better way to handle non-implemented here?
                    return ProgressEvent(OperationStatus.SUCCESS, resource_model={})
                else:
                    raise  # re-raise here if explicitly enabled

        else:
            raise TimeoutError(
                f"Resource deployment for resource {raw_payload['requestData']['logicalResourceId']} (type {raw_payload['resourceType']}) timed out."
            )

    def execute_action(
        self, resource_provider: ResourceProvider, raw_payload: ResourceProviderPayload
    ) -> ProgressEvent[Properties]:
        change_type = raw_payload["action"]
        request = convert_payload(
            stack_name=self.stack_name, stack_id=self.stack_id, payload=raw_payload
        )

        match change_type:
            case "Add":
                # replicate previous event emitting behaviour
                usage.resource_type.record(request.resource_type)

                return resource_provider.create(request)
            case "Dynamic" | "Modify":
                try:
                    return resource_provider.update(request)
                except NotImplementedError:
                    LOG.warning(
                        'Unable to update resource type "%s", id "%s"',
                        request.resource_type,
                        request.logical_resource_id,
                    )
                    if request.previous_state is None:
                        # this is an issue with our update detection. We should never be in this state.
                        request.action = "Add"
                        return resource_provider.create(request)

                    return ProgressEvent(
                        status=OperationStatus.SUCCESS, resource_model=request.previous_state
                    )
                except Exception as e:
                    # FIXME: this fallback should be removed after fixing updates in general (order/dependenies)
                    # catch-all for any exception that looks like a not found exception
                    if check_not_found_exception(e, request.resource_type, request.desired_state):
                        return ProgressEvent(
                            status=OperationStatus.SUCCESS, resource_model=request.previous_state
                        )

                    return ProgressEvent(
                        status=OperationStatus.FAILED,
                        resource_model={},
                        message=f"Failed to delete resource with id {request.logical_resource_id} of type {request.resource_type}",
                    )
            case "Remove":
                try:
                    return resource_provider.delete(request)
                except Exception as e:
                    # catch-all for any exception that looks like a not found exception
                    if check_not_found_exception(e, request.resource_type, request.desired_state):
                        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})

                    return ProgressEvent(
                        status=OperationStatus.FAILED,
                        resource_model={},
                        message=f"Failed to delete resource with id {request.logical_resource_id} of type {request.resource_type}",
                    )
            case _:
                raise NotImplementedError(change_type)  # TODO: change error type

    def load_resource_provider(self, resource_type: str) -> ResourceProvider:
        # TODO: unify namespace of plugins

        # 1. try to load pro resource provider
        # prioritise pro resource providers
        if PRO_RESOURCE_PROVIDERS:
            try:
                plugin = pro_plugin_manager.load(resource_type)
                return plugin.factory()
            except ValueError:
                # could not find a plugin for that name
                pass
            except Exception:
                LOG.warning(
                    "Failed to load PRO resource type %s as a ResourceProvider.",
                    resource_type,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )

        # 2. try to load community resource provider
        try:
            plugin = plugin_manager.load(resource_type)
            return plugin.factory()
        except ValueError:
            # could not find a plugin for that name
            pass
        except Exception:
            if config.CFN_VERBOSE_ERRORS:
                LOG.warning(
                    "Failed to load community resource type %s as a ResourceProvider.",
                    resource_type,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )

        raise NoResourceProvider

    def extract_physical_resource_id_from_model_with_schema(
        self, resource_model: Properties, resource_type: str, resource_type_schema: dict
    ) -> str:
        if resource_type in PHYSICAL_RESOURCE_ID_SPECIAL_CASES:
            primary_id_path = PHYSICAL_RESOURCE_ID_SPECIAL_CASES[resource_type]

            if "<" in primary_id_path:
                # composite quirk, e.g. something like MyRef|MyName
                # try to extract parts
                physical_resource_id = primary_id_path
                find_results = re.findall("<([^>]+)>", primary_id_path)
                for found_part in find_results:
                    resolved_part = resolve_json_pointer(resource_model, found_part)
                    physical_resource_id = physical_resource_id.replace(
                        f"<{found_part}>", resolved_part
                    )
            else:
                physical_resource_id = resolve_json_pointer(resource_model, primary_id_path)
        else:
            primary_id_paths = resource_type_schema["primaryIdentifier"]
            if len(primary_id_paths) > 1:
                # TODO: auto-merge. Verify logic here with AWS
                physical_resource_id = "-".join(
                    [resolve_json_pointer(resource_model, pip) for pip in primary_id_paths]
                )
            else:
                physical_resource_id = resolve_json_pointer(resource_model, primary_id_paths[0])

        return physical_resource_id


plugin_manager = PluginManager(CloudFormationResourceProviderPlugin.namespace)
if PRO_RESOURCE_PROVIDERS:
    pro_plugin_manager = PluginManager(CloudFormationResourceProviderPluginExt.namespace)
