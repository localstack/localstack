from __future__ import annotations

import copy
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
    check_not_found_exception,
    convert_data_types,
    fix_account_id_in_arns,
    fix_boto_parameters_based_on_report,
    log_not_available_message,
    remove_none_values,
)
from localstack.services.cloudformation.engine.quirks import PHYSICAL_RESOURCE_ID_SPECIAL_CASES
from localstack.services.cloudformation.service_models import KEY_RESOURCE_STATE, GenericBaseModel

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
    "AWS::SQS::Queue": "ResourceProvider",
    "AWS::SQS::QueuePolicy": "ResourceProvider",
    "AWS::IAM::User": "ResourceProvider",
    "AWS::IAM::Role": "ResourceProvider",
    "AWS::IAM::Group": "ResourceProvider",
    "AWS::IAM::ManagedPolicy": "ResourceProvider",
    "AWS::IAM::AccessKey": "ResourceProvider",
    "AWS::IAM::Policy": "ResourceProvider",
    "AWS::IAM::InstanceProfile": "ResourceProvider",
    "AWS::IAM::ServiceLinkedRole": "ResourceProvider",
    "AWS::OpenSearchService::Domain": "ResourceProvider",
    "AWS::Lambda::Alias": "ResourceProvider",
    "AWS::Scheduler::Schedule": "ResourceProvider",
    "AWS::Scheduler::ScheduleGroup": "ResourceProvider",
    "AWS::Route53::HealthCheck": "ResourceProvider",
    "AWS::Route53::RecordSet": "ResourceProvider",
    "AWS::SNS::Topic": "ResourceProvider",
    "AWS::Kinesis::Stream": "ResourceProvider",
    "AWS::Kinesis::StreamConsumer": "ResourceProvider",
    "AWS::KinesisFirehose::DeliveryStream": "ResourceProvider",
    "AWS::DynamoDB::Table": "ResourceProvider",
    "AWS::CloudWatch::Alarm": "ResourceProvider",
    "AWS::CloudWatch::CompositeAlarm": "ResourceProvider",
    # "AWS::ECR::Repository": "ResourceProvider",  # FIXME: add full -ext provider & override logic for -ext
    "AWS::KMS::Key": "ResourceProvider",
    "AWS::KMS::Alias": "ResourceProvider",
    "AWS::ElasticBeanstalk::Application": "ResourceProvider",
    "AWS::ElasticBeanstalk::ApplicationVersion": "ResourceProvider",
    "AWS::ElasticBeanstalk::Environment": "ResourceProvider",
    "AWS::ElasticBeanstalk::ConfigurationTemplate": "ResourceProvider",
    "AWS::CertificateManager::Certificate": "ResourceProvider",
    "AWS::EKS::Nodegroup": "ResourceProvider",
    "AWS::Redshift::Cluster": "ResourceProvider",
    "AWS::S3::BucketPolicy": "ResourceProvider",
    "AWS::S3::Bucket": "ResourceProvider",
    "AWS::Events::Connection": "ResourceProvider",
    "AWS::Events::EventBus": "ResourceProvider",
    "AWS::Events::Rule": "ResourceProvider",
    "AWS::Events::EventBusPolicy": "ResourceProvider",
    "AWS::ApiGateway::GatewayResponse": "ResourceProvider",
    "AWS::ApiGateway::RequestValidator": "ResourceProvider",
    "AWS::ApiGateway::RestApi": "ResourceProvider",
    "AWS::ApiGateway::Deployment": "ResourceProvider",
    "AWS::ApiGateway::Resource": "ResourceProvider",
    "AWS::ApiGateway::Method": "ResourceProvider",
    "AWS::ApiGateway::Stage": "ResourceProvider",
    "AWS::ApiGateway::UsagePlan": "ResourceProvider",
    "AWS::ApiGateway::ApiKey": "ResourceProvider",
    "AWS::ApiGateway::UsagePlanKey": "ResourceProvider",
    "AWS::ApiGateway::DomainName": "ResourceProvider",
    "AWS::ApiGateway::BasePathMapping": "ResourceProvider",
    "AWS::ApiGateway::Model": "ResourceProvider",
    "AWS::ApiGateway::Account": "ResourceProvider",
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
                # just a temporary workaround, technically we're setting _state_ here to _last_deployed_state
                "_state_": request.previous_state,
                # "_last_deployed_state": request
                "PhysicalResourceId": physical_resource_id,
                "LogicalResourceId": request.logical_resource_id,
            },
            account_id=request.account_id,
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
                status=OperationStatus.SUCCESS,
                resource_model={**request.previous_state, **request.desired_state},
            )

        LOG.info("Updating resource %s of type %s", request.logical_resource_id, self.resource_type)

        resource_provider.update_resource(
            self.all_resources[request.logical_resource_id],
            stack_name=request.stack_name,
            resources=self.all_resources,
        )

        # incredibly hacky :|
        resource_provider.resource_json["PhysicalResourceId"] = self.all_resources[
            request.logical_resource_id
        ]["PhysicalResourceId"]
        resource_provider.fetch_and_update_state(
            stack_name=request.stack_name, resources=self.all_resources
        )
        self.all_resources[request.logical_resource_id][
            "_state_"
        ] = resource_provider.resource_json["_state_"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=resource_provider.props,
        )

    def delete(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        return self.create_or_delete(request)

    def create_or_delete(self, request: ResourceRequest[Properties]) -> ProgressEvent[Properties]:
        resource_provider = self.resource_provider_cls(
            account_id=request.account_id,
            region_name=request.region_name,
            # TODO: other top level keys
            resource_json={
                "Type": self.resource_type,
                "Properties": request.desired_state,
                "PhysicalResourceId": self.all_resources[request.logical_resource_id].get(
                    "PhysicalResourceId"
                ),
                "_state_": request.previous_state,
                "LogicalResourceId": request.logical_resource_id,
            },
        )
        # TODO: only really necessary for the create and update operation
        resource_provider.add_defaults(
            self.all_resources[request.logical_resource_id], request.stack_name
        )
        # for some reason add_defaults doesn't even change the values in the resource provider...
        # incredibly hacky again but should take care of the defaults
        resource_provider.resource_json["Properties"] = self.all_resources[
            request.logical_resource_id
        ]["Properties"]
        resource_provider.properties = self.all_resources[request.logical_resource_id]["Properties"]

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
            # TODO: raise here and see where we are missing handlers
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
                result = func["function"](
                    request.account_id,
                    request.region_name,
                    request.logical_resource_id,
                    resource,
                    request.stack_name,
                )

                results.append(result)
                executed = True
            elif not executed:
                service = get_service_name(resource)
                try:
                    client = request.aws_client_factory.get_client(service=service)
                    if client:
                        # get the method on that function
                        function = getattr(client, func["function"])

                        # unify the resource parameters
                        params = resolve_resource_parameters(
                            request.account_id,
                            request.region_name,
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
                                request.account_id,
                                request.region_name,
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
                result_handler(
                    request.account_id,
                    request.region_name,
                    result,
                    request.logical_resource_id,
                    self.all_resources[request.logical_resource_id],
                )

        if request.action.lower() == "add":
            resource_provider.resource_json["PhysicalResourceId"] = self.all_resources[
                request.logical_resource_id
            ]["PhysicalResourceId"]

            # incredibly hacky :|
            resource_provider.fetch_and_update_state(
                stack_name=request.stack_name, resources=self.all_resources
            )
            self.all_resources[request.logical_resource_id][
                "_state_"
            ] = resource_provider.resource_json["_state_"]

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=resource_provider.props)


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
            try:
                resource_provider = self.load_resource_provider(resource_type)

                logical_resource_id = raw_payload["requestData"]["logicalResourceId"]
                resource = self.resources[logical_resource_id]

                resource["SpecifiedProperties"] = raw_payload["requestData"]["resourceProperties"]

                event = self.execute_action(resource_provider, payload)

                if event.status == OperationStatus.FAILED:
                    return event

                if event.status == OperationStatus.SUCCESS:
                    if not isinstance(resource_provider, LegacyResourceProvider):
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

                # update the shared state
                context = {**payload["callbackContext"], **event.custom_context}
                payload["callbackContext"] = context
                payload["requestData"]["resourceProperties"] = event.resource_model

                if current_iteration == 0:
                    time.sleep(0)
                else:
                    time.sleep(sleep_time)

            except NoResourceProvider:
                log_not_available_message(
                    raw_payload["resourceType"],
                    f"No resource provider found for \"{raw_payload['resourceType']}\"",
                )

                if config.CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES:
                    # TODO: figure out a better way to handle non-implemented here?
                    return ProgressEvent(OperationStatus.SUCCESS, resource_model={})
                else:
                    raise  # re-raise here if explicitly enabled

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
                try:
                    return resource_provider.update(request)
                except NotImplementedError:
                    LOG.warning(
                        'Unable to update resource type "%s", id "%s"',
                        request.resource_type,
                        request.logical_resource_id,
                    )
                    return ProgressEvent(
                        status=OperationStatus.SUCCESS, resource_model=request.previous_state
                    )
            case "Remove":
                return resource_provider.delete(request)
            case _:
                raise NotImplementedError(change_type)  # TODO: change error type

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
                "Failed to load resource type %s as a ResourceProvider.",
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
