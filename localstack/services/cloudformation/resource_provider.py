from __future__ import annotations

import copy
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from logging import Logger
from platform import processor
from typing import Generic, Optional, Type, TypedDict, TypeVar

from localstack.aws.connect import ServiceLevelClientFactory, connect_to

Properties = TypeVar("Properties")

PRIVATE_REGISTRY: dict[str, Type[ResourceProvider]] = {}
PUBLIC_REGISTRY: dict[str, Type[ResourceProvider]] = {}


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

    desired_state: Properties

    logical_resource_id: str

    logger: Logger

    custom_context: dict = field(default_factory=dict)

    previous_state: Optional[Properties] = None
    previous_tags: Optional[dict[str, str]] = None
    tags: dict[str, str] = field(default_factory=dict)


def register_resource_provider(cls):
    """
    Automatically register the resource provider in the private registry.
    """
    global PRIVATE_REGISTRY
    if provider_type := getattr(cls, "TYPE", None):
        PRIVATE_REGISTRY[provider_type] = cls
    return cls


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


class ResourceProviderExecutor:
    """
    Point of abstraction between our integration with generic base models, and the new providers.
    """

    def __init__(self, stack_name: str, stack_id: str):
        self.stack_name = stack_name
        self.stack_id = stack_id

    def deploy_loop(
        self, raw_payload: ResourceProviderPayload, max_iterations: int = 30, sleep_time: float = 5
    ) -> ProgressEvent[Properties]:
        payload = copy.deepcopy(raw_payload)
        for _ in range(max_iterations):
            event = self.execute_action(payload)
            if event.status == OperationStatus.SUCCESS:
                # TODO: validate physical_resource_id is not None
                return event

            # update the shared state
            context = {**payload["callbackContext"], **event.custom_context}
            payload["callbackContext"] = context
            payload["requestData"]["resourceProperties"] = event.resource_model

            time.sleep(sleep_time)
        else:
            raise TimeoutError("Could not perform deploy loop action")

    def execute_action(self, raw_payload: ResourceProviderPayload) -> ProgressEvent[Properties]:
        # lookup provider in private registry
        # TODO: delegate to a concrete subclass
        resource_type = raw_payload["resourceType"]
        provider_class = (
            PRIVATE_REGISTRY.get(resource_type)
            or PUBLIC_REGISTRY.get(resource_type)
            or LegacyModelProvider
        )
        if not provider_class:
            raise NotImplementedError("No provider class found")
        change_type = raw_payload["action"]
        request = convert_payload(
            stack_name=self.stack_name, stack_id=self.stack_id, payload=raw_payload
        )

        provider = provider_class()
        match change_type:
            case "Add":
                return provider.create(request)
            case "Dynamic" | "Modify":
                return provider.update(request)
            case "Remove":
                return provider.delete(request)
            case _:
                raise NotImplementedError(change_type)


class LegacyModelProvider(ResourceProvider[Properties]):
    def create(self, request: ResourceRequest[Properties]) -> ProgressEvent:
        raise NotImplementedError
        if request.desired_state.TopicArn:
            fn_state = request.aws_client_factory.awslambda.get_function(
                FunctionName=request.desired_state.TopicName
            )
            if fn_state["Configuration"]["State"] == "Active":
                return ProgressEvent("CREATE_COMPLETE", state={"Arn": "asdfasdfsf"})

        # do something (initate resource creation)
        return ProgressEvent("IN_PROGRESS", state={"TopicArn": "asdfasdfsf"})
        topic = SNSTopic(request.desired_state.copy(), request.region_name)
        topic.get_deploy_templates()
        create = topic.get_deploy_templates()["create"]

        action = build_deployment_action(create)
        result = action(resources, resource_id, stack_name)
        primary_id = get_primary_id_from_result(result)
        result_handler(result)  # only identify and set the ID

        # TODO: how and when do we break out of this loop?
        # find max duration and wait time somewhat equivalent to current setup
        while True:
            if topic.fetch_state(primary_id):
                break

        return ProgressEvent("CREATE_COMPLETE", state=topic.props)

        # 1. add defaults (GenericBaseModel.add_defaults(resource, stack_name))
        # (2. deploy )
        # 3. add read-only & primary id (happens in the create call + result_handler + fetch_state(!))
        # ???????? time passed
        # 4. CREATE_COMPLETE

        # 0. Assign physical resource id / ARN
        # 1. GetTopicAttributes
        # 2. if exists:
        #      raise error
        #    else:
        # 3.   CreateTopic
        # 4. GetTopicAttributes
        request.logger.info("Starting to create topic")

        create_response = self.client.sns.create_topic(Name=desiredState.TopicName)
        return ProgressEvent("IN_PROGRESS", state={"TopicName": "a", "TopicArn": "b"})

    def update(self):
        ...

    def delete(self):
        # 1. DeleteTopic
        ...

    # cloud control
    def read(self):
        ...

    def list(self):
        ...
