import sys
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

MaxResults = int
NextToken = str
PageSize = int
Qos = int
Retain = bool
ShadowName = str
ThingName = str
Topic = str
errorMessage = str


class ConflictException(ServiceException):
    message: Optional[errorMessage]


class InternalFailureException(ServiceException):
    message: Optional[errorMessage]


class InvalidRequestException(ServiceException):
    message: Optional[errorMessage]


class MethodNotAllowedException(ServiceException):
    message: Optional[errorMessage]


class RequestEntityTooLargeException(ServiceException):
    message: Optional[errorMessage]


class ResourceNotFoundException(ServiceException):
    message: Optional[errorMessage]


class ServiceUnavailableException(ServiceException):
    message: Optional[errorMessage]


class ThrottlingException(ServiceException):
    message: Optional[errorMessage]


class UnauthorizedException(ServiceException):
    message: Optional[errorMessage]


class UnsupportedDocumentEncodingException(ServiceException):
    message: Optional[errorMessage]


class DeleteThingShadowRequest(ServiceRequest):
    thingName: ThingName
    shadowName: Optional[ShadowName]


JsonDocument = bytes


class DeleteThingShadowResponse(TypedDict, total=False):
    payload: JsonDocument


class GetRetainedMessageRequest(ServiceRequest):
    topic: Topic


Timestamp = int
Payload = bytes


class GetRetainedMessageResponse(TypedDict, total=False):
    topic: Optional[Topic]
    payload: Optional[Payload]
    qos: Optional[Qos]
    lastModifiedTime: Optional[Timestamp]


class GetThingShadowRequest(ServiceRequest):
    thingName: ThingName
    shadowName: Optional[ShadowName]


class GetThingShadowResponse(TypedDict, total=False):
    payload: Optional[JsonDocument]


class ListNamedShadowsForThingRequest(ServiceRequest):
    thingName: ThingName
    nextToken: Optional[NextToken]
    pageSize: Optional[PageSize]


NamedShadowList = List[ShadowName]


class ListNamedShadowsForThingResponse(TypedDict, total=False):
    results: Optional[NamedShadowList]
    nextToken: Optional[NextToken]
    timestamp: Optional[Timestamp]


class ListRetainedMessagesRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


PayloadSize = int


class RetainedMessageSummary(TypedDict, total=False):
    topic: Optional[Topic]
    payloadSize: Optional[PayloadSize]
    qos: Optional[Qos]
    lastModifiedTime: Optional[Timestamp]


RetainedMessageList = List[RetainedMessageSummary]


class ListRetainedMessagesResponse(TypedDict, total=False):
    retainedTopics: Optional[RetainedMessageList]
    nextToken: Optional[NextToken]


class PublishRequest(ServiceRequest):
    topic: Topic
    qos: Optional[Qos]
    retain: Optional[Retain]
    payload: Optional[Payload]


class UpdateThingShadowRequest(ServiceRequest):
    thingName: ThingName
    shadowName: Optional[ShadowName]
    payload: JsonDocument


class UpdateThingShadowResponse(TypedDict, total=False):
    payload: Optional[JsonDocument]


class IotDataApi:

    service = "iot-data"
    version = "2015-05-28"

    @handler("DeleteThingShadow")
    def delete_thing_shadow(
        self, context: RequestContext, thing_name: ThingName, shadow_name: ShadowName = None
    ) -> DeleteThingShadowResponse:
        raise NotImplementedError

    @handler("GetRetainedMessage")
    def get_retained_message(
        self, context: RequestContext, topic: Topic
    ) -> GetRetainedMessageResponse:
        raise NotImplementedError

    @handler("GetThingShadow")
    def get_thing_shadow(
        self, context: RequestContext, thing_name: ThingName, shadow_name: ShadowName = None
    ) -> GetThingShadowResponse:
        raise NotImplementedError

    @handler("ListNamedShadowsForThing")
    def list_named_shadows_for_thing(
        self,
        context: RequestContext,
        thing_name: ThingName,
        next_token: NextToken = None,
        page_size: PageSize = None,
    ) -> ListNamedShadowsForThingResponse:
        raise NotImplementedError

    @handler("ListRetainedMessages")
    def list_retained_messages(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListRetainedMessagesResponse:
        raise NotImplementedError

    @handler("Publish")
    def publish(
        self,
        context: RequestContext,
        topic: Topic,
        qos: Qos = None,
        retain: Retain = None,
        payload: Payload = None,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateThingShadow")
    def update_thing_shadow(
        self,
        context: RequestContext,
        thing_name: ThingName,
        payload: JsonDocument,
        shadow_name: ShadowName = None,
    ) -> UpdateThingShadowResponse:
        raise NotImplementedError
