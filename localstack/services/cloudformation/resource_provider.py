from __future__ import annotations

import copy
import inspect
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from logging import Logger
from typing import TYPE_CHECKING, Any, Callable, Generic, Optional, Type, TypedDict, TypeVar

import botocore
from botocore.exceptions import UnknownServiceError
from plugin import Plugin, PluginManager

from localstack import config
from localstack.aws.connect import ServiceLevelClientFactory, connect_to
from localstack.services.cloudformation import usage
from localstack.services.cloudformation.deployment_utils import (
    convert_data_types,
    fix_account_id_in_arns,
    fix_boto_parameters_based_on_report,
    remove_none_values,
)
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.service_models import KEY_RESOURCE_STATE, GenericBaseModel
from localstack.utils.aws import aws_stack

if TYPE_CHECKING:
    from localstack.services.cloudformation.engine.types import (
        FuncDetails,
        FuncDetailsValue,
        ResourceDefinition,
    )

LOG = logging.getLogger(__name__)

Properties = TypeVar("Properties")

PUBLIC_REGISTRY: dict[str, Type[ResourceProvider]] = {}

# by default we use the GenericBaseModel (the legacy model), unless the resource is listed below
# add your new provider here when you want it to be the default
PROVIDER_DEFAULTS = {
    # "AWS::IAM::User": "GenericBaseModel",
    # "AWS::SSM::Parameter": "GenericBaseModel",
    # "AWS::OpenSearchService::Domain": "GenericBaseModel",
}


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
    return ResourceRequest[Properties](
        _original_payload=desired_state,
        aws_client_factory=client_factory,
        request_token=str(uuid.uuid4()),  # TODO: not actually a UUID
        stack_name=stack_name,
        stack_id=stack_id,
        account_id="000000000000",
        region_name=payload["region"],
        desired_state=desired_state,
        logical_resource_id=payload["requestData"]["logicalResourceId"],
        logger=logging.getLogger("abc"),
        custom_context=payload["callbackContext"],
        action=payload["action"],
    )


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
    except Exception as e:
        print(e)


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
            "Unexpected error processing resource type %s: Exception: %s - %s - status: %s",
            resource_type,
            str(e),
            resource,
            resource_status,
        )
        if config.CFN_VERBOSE_ERRORS:
            raise e
        else:
            return False

    return True


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
        if action_name == "Remove" and check_not_found_exception(e, resource_type, resource):
            return
        log_method = getattr(LOG, "warning")
        if config.CFN_VERBOSE_ERRORS:
            log_method = getattr(LOG, "exception")
        log_method("Error calling %s with params: %s for resource: %s", function, params, resource)
        raise e

    return result


def get_service_name(resource):
    res_type = resource["Type"]
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


def resolve_resource_parameters(
    stack_name: str,
    resource_definition: ResourceDefinition,
    resources: dict[str, ResourceDefinition],
    resource_id: str,
    func_details: FuncDetailsValue,
) -> dict | None:
    params = func_details.get("parameters") or (
        lambda properties, logical_resource_id, *args, **kwargs: properties
    )
    resource_props = resource_definition["Properties"] = resource_definition.get("Properties", {})
    resource_props = dict(resource_props)
    resource_state = resource_definition.get(KEY_RESOURCE_STATE, {})

    if callable(params):
        # resolve parameter map via custom function
        sig = inspect.signature(params)
        if "logical_resource_id" in sig.parameters:
            params = params(resource_props, resource_id, resource_definition, stack_name)
        else:
            raise NotImplementedError(func_details)
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
        # TODO(srw): mutably mapping params :(
        for param_key, prop_keys in dict(params).items():
            params.pop(param_key, None)
            if not isinstance(prop_keys, list):
                prop_keys = [prop_keys]
            for prop_key in prop_keys:
                if callable(prop_key):
                    sig = inspect.signature(prop_key)
                    if "logical_resource_id" in sig.parameters:
                        prop_value = prop_key(
                            resource_props,
                            resource_id,
                            resource_definition,
                            stack_name,
                        )
                    else:
                        raise NotImplementedError
                        prop_value = prop_key(
                            resource_props,
                            stack_name=stack_name,
                            resources=resources,
                            resource_id=resource_id,
                        )
                else:
                    prop_value = resource_props.get(
                        prop_key,
                        resource_definition.get(prop_key, resource_state.get(prop_key)),
                    )
                if prop_value is not None:
                    params[param_key] = prop_value
                    break

    # this is an indicator that we should skip this resource deployment, and return
    if params is None:
        return

    # FIXME: move this to a single place after template processing is finished
    # convert any moto account IDs (123456789012) in ARNs to our format (000000000000)
    params = fix_account_id_in_arns(params)
    # convert data types (e.g., boolean strings to bool)
    # TODO: this might not be needed anymore
    params = convert_data_types(func_details.get("types", {}), params)
    # remove None values, as they usually raise boto3 errors
    params = remove_none_values(params)

    return params


LEGACY_ACTION_MAP = {
    "Add": "create",
    "Remove": "delete",
    # TODO: modify
}


class LegacyResourceProvider(ResourceProvider):
    """
    Adapter around a legacy base model to conform to the new API
    """

    def __init__(
        self, resource_type: str, resource_provider_cls: Type[GenericBaseModel], resources: dict
    ):
        super().__init__()

        self.resource_type = resource_type
        self.resource_provider_cls = resource_provider_cls
        self.all_resources = resources

    def create(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        return self.create_or_delete(request)

    def update(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        physical_resource_id = self.all_resources[request.logical_resource_id]["PhysicalResourceId"]
        resource_provider = self.resource_provider_cls(
            # TODO: other top level keys
            resource_json={
                "Type": self.resource_type,
                "Properties": request.desired_state,
                "PhysicalResourceId": physical_resource_id,
                "LogicalResourceId": request.logical_resource_id,
            },
            region_name=request.region_name,
        )
        if not resource_provider.is_updatable():
            LOG.warning(
                'Unable to update resource type "%s", id "%s"',
                self.resource_type,
                request.logical_resource_id,
            )
            # TODO: should not really claim the update was successful, but the
            #   API does not really let us signal this in any other way.
            return ProgressEvent(
                status=OperationStatus.SUCCESS, resource_model=request.desired_state
            )

        LOG.info("Updating resource %s of type %s", request.logical_resource_id, self.resource_type)

        resource_provider.update_resource(
            self.all_resources[request.logical_resource_id],
            stack_name=request.stack_name,
            resources=self.all_resources,
        )
        resource_provider.fetch_and_update_state(
            stack_name=request.stack_name, resources=self.all_resources
        )
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=self.all_resources[request.logical_resource_id]["Properties"],
        )

    def delete(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        return self.create_or_delete(request)

    def create_or_delete(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        resource_provider = self.resource_provider_cls(
            # TODO: other top level keys
            resource_json={
                "Type": self.resource_type,
                "Properties": request.desired_state,
                "PhysicalResourceId": self.all_resources[request.logical_resource_id].get(
                    "PhysicalResourceId"
                ),
            },
            region_name=request.region_name,
        )
        # TODO: only really necessary for the create and update operation
        resource_provider.add_defaults(
            self.all_resources[request.logical_resource_id], request.stack_name
        )

        func_details = resource_provider.get_deploy_templates()
        # TODO: be less strict about the return value of func_details
        LOG.debug(
            'Running action "%s" for resource type "%s" id "%s"',
            request.action,
            self.resource_type,
            request.logical_resource_id,
        )

        func_details = func_details.get(LEGACY_ACTION_MAP[request.action])
        if not func_details:
            LOG.debug(
                "No resource handler for %s action on resource type %s available. Skipping.",
                request.action,
                self.resource_type,
            )
            return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})
        func_details = func_details if isinstance(func_details, list) else [func_details]
        results = []
        # TODO: other top level keys
        resource = self.all_resources[request.logical_resource_id]

        for func in func_details:
            result = None
            executed = False
            # TODO(srw) 3 - callable function
            if callable(func.get("function")):
                sig = inspect.signature(func["function"])
                if "logical_resource_id" in sig.parameters:
                    result = func["function"](
                        request.logical_resource_id, resource, request.stack_name
                    )
                else:
                    result = func["function"](
                        request.logical_resource_id,
                        self.all_resources,
                        self.resource_type,
                        func,
                        request.stack_name,
                    )
                results.append(result)
                executed = True
            elif not executed:
                service = get_service_name(resource)
                try:
                    client = connect_to.get_client(service)
                    if client:
                        # get the method on that function
                        function = getattr(client, func["function"])

                        # unify the resource parameters
                        params = resolve_resource_parameters(
                            request.stack_name,
                            resource,
                            self.all_resources,
                            request.logical_resource_id,
                            func,
                        )
                        if params is None:
                            result = None
                        else:
                            result = invoke_function(
                                function,
                                params,
                                self.resource_type,
                                func,
                                request.action,
                                resource,
                            )
                        results.append(result)
                        executed = True
                except UnknownServiceError:
                    # e.g. CDK has resources but is not a valid service
                    return ProgressEvent(
                        status=OperationStatus.SUCCESS, resource_model=resource["Properties"]
                    )
            if "result_handler" in func and executed:
                LOG.debug(
                    f"Executing callback method for {self.resource_type}:{request.logical_resource_id}"
                )
                result_handler = func["result_handler"]
                sig = inspect.signature(result_handler)
                if "logical_resource_id" in sig.parameters:
                    result_handler(
                        result,
                        request.logical_resource_id,
                        self.all_resources[request.logical_resource_id],
                    )
                else:
                    result_handler(
                        result, request.logical_resource_id, self.all_resources, self.resource_type
                    )

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=resource["Properties"])


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
        provider_config: dict[str, str],
        # FIXME: legacy
        resources: dict[str, dict],
        legacy_base_models: dict[str, Type[GenericBaseModel]],
    ):
        self.stack_name = stack_name
        self.stack_id = stack_id
        self.provider_config = provider_config
        self.resources = resources
        self.legacy_base_models = legacy_base_models

    def deploy_loop(
        self, raw_payload: ResourceProviderPayload, max_iterations: int = 30, sleep_time: float = 5
    ) -> ProgressEvent[Properties]:
        payload = copy.deepcopy(raw_payload)

        for current_iteration in range(max_iterations):
            resource_type = get_resource_type(
                {"Type": raw_payload["resourceType"]}
            )  # TODO: simplify signature of get_resource_type to just take the type
            resource_provider = self.load_resource_provider(resource_type)
            event = self.execute_action(resource_provider, payload)

            if event.status == OperationStatus.SUCCESS:
                logical_resource_id = raw_payload["requestData"]["logicalResourceId"]
                resource = self.resources[logical_resource_id]
                if "PhysicalResourceId" not in resource:
                    # branch for non-legacy providers
                    # TODO: move out of if? (physical res id can be set earlier possibly)
                    if isinstance(resource_provider, LegacyResourceProvider):
                        raise Exception(
                            "A GenericBaseModel should always have a PhysicalResourceId set after deployment"
                        )

                    if not hasattr(resource_provider, "SCHEMA"):
                        raise Exception(
                            "A ResourceProvider should always have a SCHEMA property defined."
                        )

                    resource_type_schema = resource_provider.SCHEMA
                    physical_resource_id = self.extract_physical_resource_id_from_model_with_schema(
                        event.resource_model, raw_payload["resourceType"], resource_type_schema
                    )

                    resource["PhysicalResourceId"] = physical_resource_id
                    resource["Properties"] = event.resource_model
                return event

            # update the shared state
            context = {**payload["callbackContext"], **event.custom_context}
            payload["callbackContext"] = context
            payload["requestData"]["resourceProperties"] = event.resource_model

            if current_iteration == 0:
                time.sleep(0)
            else:
                time.sleep(sleep_time)
        else:
            raise TimeoutError("Could not perform deploy loop action")

    def execute_action(
        self, resource_provider: ResourceProvider, raw_payload: ResourceProviderPayload
    ) -> ProgressEvent[Properties]:
        change_type = raw_payload["action"]
        request = convert_payload(
            stack_name=self.stack_name, stack_id=self.stack_id, payload=raw_payload
        )

        match change_type:
            case "Add":
                return resource_provider.create(request)
            case "Dynamic" | "Modify":
                return resource_provider.update(request)
            case "Remove":
                return resource_provider.delete(request)
            case _:
                raise NotImplementedError(change_type)

    def should_use_legacy_provider(self, resource_type: str) -> bool:
        # any config overwrites take precedence over the default list
        PROVIDER_CONFIG = {**PROVIDER_DEFAULTS, **self.provider_config}
        if resource_type in PROVIDER_CONFIG:
            return PROVIDER_CONFIG[resource_type] == "GenericBaseModel"

        return True

    def load_resource_provider(self, resource_type: str) -> ResourceProvider:
        # by default look up GenericBaseModel
        if self.should_use_legacy_provider(resource_type):
            return self._load_legacy_resource_provider(resource_type)

        try:
            plugin = plugin_manager.load(resource_type)
            return plugin.factory()
        except Exception:
            LOG.warning(
                "Failed to load resource type as a ResourceProvider.",
                resource_type,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            raise NoResourceProvider

    def _load_legacy_resource_provider(self, resource_type: str) -> LegacyResourceProvider:
        if resource_type in self.legacy_base_models:
            return LegacyResourceProvider(
                resource_type=resource_type,
                resource_provider_cls=self.legacy_base_models[resource_type],
                resources=self.resources,
            )
        else:
            usage.missing_resource_types.record(resource_type)
            raise NoResourceProvider

    def extract_physical_resource_id_from_model_with_schema(
        self, resource_model: Properties, resource_type: str, resource_type_schema: dict
    ) -> str:
        if resource_type in PHYSICAL_RESOURCE_ID_SPECIAL_CASES:
            primary_id_path = PHYSICAL_RESOURCE_ID_SPECIAL_CASES[resource_type]
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
