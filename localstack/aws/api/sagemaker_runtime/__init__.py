import sys
from typing import Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

CustomAttributesHeader = str
EndpointName = str
Header = str
InferenceId = str
InputLocationHeader = str
LogStreamArn = str
Message = str
RequestTTLSecondsHeader = int
StatusCode = int
TargetContainerHostnameHeader = str
TargetModelHeader = str
TargetVariantHeader = str


class InternalDependencyException(ServiceException):
    Message: Optional[Message]


class InternalFailure(ServiceException):
    Message: Optional[Message]


class ModelError(ServiceException):
    Message: Optional[Message]
    OriginalStatusCode: Optional[StatusCode]
    OriginalMessage: Optional[Message]
    LogStreamArn: Optional[LogStreamArn]


class ModelNotReadyException(ServiceException):
    Message: Optional[Message]


class ServiceUnavailable(ServiceException):
    Message: Optional[Message]


class ValidationError(ServiceException):
    Message: Optional[Message]


BodyBlob = bytes


class InvokeEndpointAsyncInput(ServiceRequest):
    EndpointName: EndpointName
    ContentType: Optional[Header]
    Accept: Optional[Header]
    CustomAttributes: Optional[CustomAttributesHeader]
    InferenceId: Optional[InferenceId]
    InputLocation: InputLocationHeader
    RequestTTLSeconds: Optional[RequestTTLSecondsHeader]


class InvokeEndpointAsyncOutput(TypedDict, total=False):
    InferenceId: Optional[Header]
    OutputLocation: Optional[Header]


class InvokeEndpointInput(ServiceRequest):
    EndpointName: EndpointName
    Body: BodyBlob
    ContentType: Optional[Header]
    Accept: Optional[Header]
    CustomAttributes: Optional[CustomAttributesHeader]
    TargetModel: Optional[TargetModelHeader]
    TargetVariant: Optional[TargetVariantHeader]
    TargetContainerHostname: Optional[TargetContainerHostnameHeader]
    InferenceId: Optional[InferenceId]


class InvokeEndpointOutput(TypedDict, total=False):
    Body: BodyBlob
    ContentType: Optional[Header]
    InvokedProductionVariant: Optional[Header]
    CustomAttributes: Optional[CustomAttributesHeader]


class SagemakerRuntimeApi:

    service = "sagemaker-runtime"
    version = "2017-05-13"

    @handler("InvokeEndpoint")
    def invoke_endpoint(
        self,
        context: RequestContext,
        endpoint_name: EndpointName,
        body: BodyBlob,
        content_type: Header = None,
        accept: Header = None,
        custom_attributes: CustomAttributesHeader = None,
        target_model: TargetModelHeader = None,
        target_variant: TargetVariantHeader = None,
        target_container_hostname: TargetContainerHostnameHeader = None,
        inference_id: InferenceId = None,
    ) -> InvokeEndpointOutput:
        raise NotImplementedError

    @handler("InvokeEndpointAsync")
    def invoke_endpoint_async(
        self,
        context: RequestContext,
        endpoint_name: EndpointName,
        input_location: InputLocationHeader,
        content_type: Header = None,
        accept: Header = None,
        custom_attributes: CustomAttributesHeader = None,
        inference_id: InferenceId = None,
        request_ttl_seconds: RequestTTLSecondsHeader = None,
    ) -> InvokeEndpointAsyncOutput:
        raise NotImplementedError
