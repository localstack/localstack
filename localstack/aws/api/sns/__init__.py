import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AmazonResourceName = str
Iso2CountryCode = str
MaxItems = int
MaxItemsListOriginationNumbers = int
OTPCode = str
PhoneNumber = str
PhoneNumberString = str
String = str
TagKey = str
TagValue = str
account = str
action = str
attributeName = str
attributeValue = str
authenticateOnUnsubscribe = str
boolean = bool
delegate = str
endpoint = str
label = str
message = str
messageId = str
messageStructure = str
nextToken = str
protocol = str
string = str
subject = str
subscriptionARN = str
token = str
topicARN = str
topicName = str


class LanguageCodeString(str):
    en_US = "en-US"
    en_GB = "en-GB"
    es_419 = "es-419"
    es_ES = "es-ES"
    de_DE = "de-DE"
    fr_CA = "fr-CA"
    fr_FR = "fr-FR"
    it_IT = "it-IT"
    ja_JP = "ja-JP"
    pt_BR = "pt-BR"
    kr_KR = "kr-KR"
    zh_CN = "zh-CN"
    zh_TW = "zh-TW"


class NumberCapability(str):
    SMS = "SMS"
    MMS = "MMS"
    VOICE = "VOICE"


class RouteType(str):
    Transactional = "Transactional"
    Promotional = "Promotional"
    Premium = "Premium"


class SMSSandboxPhoneNumberVerificationStatus(str):
    Pending = "Pending"
    Verified = "Verified"


class AuthorizationErrorException(ServiceException):
    code: str = "AuthorizationError"
    sender_fault: bool = True
    status_code: int = 403


class BatchEntryIdsNotDistinctException(ServiceException):
    code: str = "BatchEntryIdsNotDistinct"
    sender_fault: bool = True
    status_code: int = 400


class BatchRequestTooLongException(ServiceException):
    code: str = "BatchRequestTooLong"
    sender_fault: bool = True
    status_code: int = 400


class ConcurrentAccessException(ServiceException):
    code: str = "ConcurrentAccess"
    sender_fault: bool = True
    status_code: int = 400


class EmptyBatchRequestException(ServiceException):
    code: str = "EmptyBatchRequest"
    sender_fault: bool = True
    status_code: int = 400


class EndpointDisabledException(ServiceException):
    code: str = "EndpointDisabled"
    sender_fault: bool = True
    status_code: int = 400


class FilterPolicyLimitExceededException(ServiceException):
    code: str = "FilterPolicyLimitExceeded"
    sender_fault: bool = True
    status_code: int = 403


class InternalErrorException(ServiceException):
    code: str = "InternalError"
    sender_fault: bool = False
    status_code: int = 500


class InvalidBatchEntryIdException(ServiceException):
    code: str = "InvalidBatchEntryId"
    sender_fault: bool = True
    status_code: int = 400


class InvalidParameterException(ServiceException):
    code: str = "InvalidParameter"
    sender_fault: bool = True
    status_code: int = 400


class InvalidParameterValueException(ServiceException):
    code: str = "ParameterValueInvalid"
    sender_fault: bool = True
    status_code: int = 400


class InvalidSecurityException(ServiceException):
    code: str = "InvalidSecurity"
    sender_fault: bool = True
    status_code: int = 403


class KMSAccessDeniedException(ServiceException):
    code: str = "KMSAccessDenied"
    sender_fault: bool = True
    status_code: int = 400


class KMSDisabledException(ServiceException):
    code: str = "KMSDisabled"
    sender_fault: bool = True
    status_code: int = 400


class KMSInvalidStateException(ServiceException):
    code: str = "KMSInvalidState"
    sender_fault: bool = True
    status_code: int = 400


class KMSNotFoundException(ServiceException):
    code: str = "KMSNotFound"
    sender_fault: bool = True
    status_code: int = 400


class KMSOptInRequired(ServiceException):
    code: str = "KMSOptInRequired"
    sender_fault: bool = True
    status_code: int = 403


class KMSThrottlingException(ServiceException):
    code: str = "KMSThrottling"
    sender_fault: bool = True
    status_code: int = 400


class NotFoundException(ServiceException):
    code: str = "NotFound"
    sender_fault: bool = True
    status_code: int = 404


class OptedOutException(ServiceException):
    code: str = "OptedOut"
    sender_fault: bool = True
    status_code: int = 400


class PlatformApplicationDisabledException(ServiceException):
    code: str = "PlatformApplicationDisabled"
    sender_fault: bool = True
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFound"
    sender_fault: bool = True
    status_code: int = 404


class StaleTagException(ServiceException):
    code: str = "StaleTag"
    sender_fault: bool = True
    status_code: int = 400


class SubscriptionLimitExceededException(ServiceException):
    code: str = "SubscriptionLimitExceeded"
    sender_fault: bool = True
    status_code: int = 403


class TagLimitExceededException(ServiceException):
    code: str = "TagLimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class TagPolicyException(ServiceException):
    code: str = "TagPolicy"
    sender_fault: bool = True
    status_code: int = 400


class ThrottledException(ServiceException):
    code: str = "Throttled"
    sender_fault: bool = True
    status_code: int = 429


class TooManyEntriesInBatchRequestException(ServiceException):
    code: str = "TooManyEntriesInBatchRequest"
    sender_fault: bool = True
    status_code: int = 400


class TopicLimitExceededException(ServiceException):
    code: str = "TopicLimitExceeded"
    sender_fault: bool = True
    status_code: int = 403


class UserErrorException(ServiceException):
    code: str = "UserError"
    sender_fault: bool = True
    status_code: int = 400


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400


class VerificationException(ServiceException):
    code: str = "VerificationException"
    sender_fault: bool = False
    status_code: int = 400
    Status: string


ActionsList = List[action]
DelegatesList = List[delegate]


class AddPermissionInput(ServiceRequest):
    TopicArn: topicARN
    Label: label
    AWSAccountId: DelegatesList
    ActionName: ActionsList


class BatchResultErrorEntry(TypedDict, total=False):
    Id: String
    Code: String
    Message: Optional[String]
    SenderFault: boolean


BatchResultErrorEntryList = List[BatchResultErrorEntry]
Binary = bytes


class CheckIfPhoneNumberIsOptedOutInput(ServiceRequest):
    phoneNumber: PhoneNumber


class CheckIfPhoneNumberIsOptedOutResponse(TypedDict, total=False):
    isOptedOut: Optional[boolean]


class ConfirmSubscriptionInput(ServiceRequest):
    TopicArn: topicARN
    Token: token
    AuthenticateOnUnsubscribe: Optional[authenticateOnUnsubscribe]


class ConfirmSubscriptionResponse(TypedDict, total=False):
    SubscriptionArn: Optional[subscriptionARN]


class CreateEndpointResponse(TypedDict, total=False):
    EndpointArn: Optional[String]


MapStringToString = Dict[String, String]


class CreatePlatformApplicationInput(ServiceRequest):
    Name: String
    Platform: String
    Attributes: MapStringToString


class CreatePlatformApplicationResponse(TypedDict, total=False):
    PlatformApplicationArn: Optional[String]


class CreatePlatformEndpointInput(ServiceRequest):
    PlatformApplicationArn: String
    Token: String
    CustomUserData: Optional[String]
    Attributes: Optional[MapStringToString]


class CreateSMSSandboxPhoneNumberInput(ServiceRequest):
    PhoneNumber: PhoneNumberString
    LanguageCode: Optional[LanguageCodeString]


class CreateSMSSandboxPhoneNumberResult(TypedDict, total=False):
    pass


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]
TopicAttributesMap = Dict[attributeName, attributeValue]


class CreateTopicInput(ServiceRequest):
    Name: topicName
    Attributes: Optional[TopicAttributesMap]
    Tags: Optional[TagList]
    DataProtectionPolicy: Optional[attributeValue]


class CreateTopicResponse(TypedDict, total=False):
    TopicArn: Optional[topicARN]


class DeleteEndpointInput(ServiceRequest):
    EndpointArn: String


class DeletePlatformApplicationInput(ServiceRequest):
    PlatformApplicationArn: String


class DeleteSMSSandboxPhoneNumberInput(ServiceRequest):
    PhoneNumber: PhoneNumberString


class DeleteSMSSandboxPhoneNumberResult(TypedDict, total=False):
    pass


class DeleteTopicInput(ServiceRequest):
    TopicArn: topicARN


class Endpoint(TypedDict, total=False):
    EndpointArn: Optional[String]
    Attributes: Optional[MapStringToString]


class GetDataProtectionPolicyInput(ServiceRequest):
    ResourceArn: topicARN


class GetDataProtectionPolicyResponse(TypedDict, total=False):
    DataProtectionPolicy: Optional[attributeValue]


class GetEndpointAttributesInput(ServiceRequest):
    EndpointArn: String


class GetEndpointAttributesResponse(TypedDict, total=False):
    Attributes: Optional[MapStringToString]


class GetPlatformApplicationAttributesInput(ServiceRequest):
    PlatformApplicationArn: String


class GetPlatformApplicationAttributesResponse(TypedDict, total=False):
    Attributes: Optional[MapStringToString]


ListString = List[String]


class GetSMSAttributesInput(ServiceRequest):
    attributes: Optional[ListString]


class GetSMSAttributesResponse(TypedDict, total=False):
    attributes: Optional[MapStringToString]


class GetSMSSandboxAccountStatusInput(ServiceRequest):
    pass


class GetSMSSandboxAccountStatusResult(TypedDict, total=False):
    IsInSandbox: boolean


class GetSubscriptionAttributesInput(ServiceRequest):
    SubscriptionArn: subscriptionARN


SubscriptionAttributesMap = Dict[attributeName, attributeValue]


class GetSubscriptionAttributesResponse(TypedDict, total=False):
    Attributes: Optional[SubscriptionAttributesMap]


class GetTopicAttributesInput(ServiceRequest):
    TopicArn: topicARN


class GetTopicAttributesResponse(TypedDict, total=False):
    Attributes: Optional[TopicAttributesMap]


class ListEndpointsByPlatformApplicationInput(ServiceRequest):
    PlatformApplicationArn: String
    NextToken: Optional[String]


ListOfEndpoints = List[Endpoint]


class ListEndpointsByPlatformApplicationResponse(TypedDict, total=False):
    Endpoints: Optional[ListOfEndpoints]
    NextToken: Optional[String]


class PlatformApplication(TypedDict, total=False):
    PlatformApplicationArn: Optional[String]
    Attributes: Optional[MapStringToString]


ListOfPlatformApplications = List[PlatformApplication]


class ListOriginationNumbersRequest(ServiceRequest):
    NextToken: Optional[nextToken]
    MaxResults: Optional[MaxItemsListOriginationNumbers]


NumberCapabilityList = List[NumberCapability]
Timestamp = datetime


class PhoneNumberInformation(TypedDict, total=False):
    CreatedAt: Optional[Timestamp]
    PhoneNumber: Optional[String]
    Status: Optional[String]
    Iso2CountryCode: Optional[Iso2CountryCode]
    RouteType: Optional[RouteType]
    NumberCapabilities: Optional[NumberCapabilityList]


PhoneNumberInformationList = List[PhoneNumberInformation]


class ListOriginationNumbersResult(TypedDict, total=False):
    NextToken: Optional[nextToken]
    PhoneNumbers: Optional[PhoneNumberInformationList]


class ListPhoneNumbersOptedOutInput(ServiceRequest):
    nextToken: Optional[string]


PhoneNumberList = List[PhoneNumber]


class ListPhoneNumbersOptedOutResponse(TypedDict, total=False):
    phoneNumbers: Optional[PhoneNumberList]
    nextToken: Optional[string]


class ListPlatformApplicationsInput(ServiceRequest):
    NextToken: Optional[String]


class ListPlatformApplicationsResponse(TypedDict, total=False):
    PlatformApplications: Optional[ListOfPlatformApplications]
    NextToken: Optional[String]


class ListSMSSandboxPhoneNumbersInput(ServiceRequest):
    NextToken: Optional[nextToken]
    MaxResults: Optional[MaxItems]


class SMSSandboxPhoneNumber(TypedDict, total=False):
    PhoneNumber: Optional[PhoneNumberString]
    Status: Optional[SMSSandboxPhoneNumberVerificationStatus]


SMSSandboxPhoneNumberList = List[SMSSandboxPhoneNumber]


class ListSMSSandboxPhoneNumbersResult(TypedDict, total=False):
    PhoneNumbers: SMSSandboxPhoneNumberList
    NextToken: Optional[string]


class ListSubscriptionsByTopicInput(ServiceRequest):
    TopicArn: topicARN
    NextToken: Optional[nextToken]


class Subscription(TypedDict, total=False):
    SubscriptionArn: Optional[subscriptionARN]
    Owner: Optional[account]
    Protocol: Optional[protocol]
    Endpoint: Optional[endpoint]
    TopicArn: Optional[topicARN]


SubscriptionsList = List[Subscription]


class ListSubscriptionsByTopicResponse(TypedDict, total=False):
    Subscriptions: Optional[SubscriptionsList]
    NextToken: Optional[nextToken]


class ListSubscriptionsInput(ServiceRequest):
    NextToken: Optional[nextToken]


class ListSubscriptionsResponse(TypedDict, total=False):
    Subscriptions: Optional[SubscriptionsList]
    NextToken: Optional[nextToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[TagList]


class ListTopicsInput(ServiceRequest):
    NextToken: Optional[nextToken]


class Topic(TypedDict, total=False):
    TopicArn: Optional[topicARN]


TopicsList = List[Topic]


class ListTopicsResponse(TypedDict, total=False):
    Topics: Optional[TopicsList]
    NextToken: Optional[nextToken]


class MessageAttributeValue(TypedDict, total=False):
    DataType: String
    StringValue: Optional[String]
    BinaryValue: Optional[Binary]


MessageAttributeMap = Dict[String, MessageAttributeValue]


class OptInPhoneNumberInput(ServiceRequest):
    phoneNumber: PhoneNumber


class OptInPhoneNumberResponse(TypedDict, total=False):
    pass


class PublishBatchRequestEntry(TypedDict, total=False):
    Id: String
    Message: message
    Subject: Optional[subject]
    MessageStructure: Optional[messageStructure]
    MessageAttributes: Optional[MessageAttributeMap]
    MessageDeduplicationId: Optional[String]
    MessageGroupId: Optional[String]


PublishBatchRequestEntryList = List[PublishBatchRequestEntry]


class PublishBatchInput(ServiceRequest):
    TopicArn: topicARN
    PublishBatchRequestEntries: PublishBatchRequestEntryList


class PublishBatchResultEntry(TypedDict, total=False):
    Id: Optional[String]
    MessageId: Optional[messageId]
    SequenceNumber: Optional[String]


PublishBatchResultEntryList = List[PublishBatchResultEntry]


class PublishBatchResponse(TypedDict, total=False):
    Successful: Optional[PublishBatchResultEntryList]
    Failed: Optional[BatchResultErrorEntryList]


class PublishInput(ServiceRequest):
    TopicArn: Optional[topicARN]
    TargetArn: Optional[String]
    PhoneNumber: Optional[String]
    Message: message
    Subject: Optional[subject]
    MessageStructure: Optional[messageStructure]
    MessageAttributes: Optional[MessageAttributeMap]
    MessageDeduplicationId: Optional[String]
    MessageGroupId: Optional[String]


class PublishResponse(TypedDict, total=False):
    MessageId: Optional[messageId]
    SequenceNumber: Optional[String]


class PutDataProtectionPolicyInput(ServiceRequest):
    ResourceArn: topicARN
    DataProtectionPolicy: attributeValue


class RemovePermissionInput(ServiceRequest):
    TopicArn: topicARN
    Label: label


class SetEndpointAttributesInput(ServiceRequest):
    EndpointArn: String
    Attributes: MapStringToString


class SetPlatformApplicationAttributesInput(ServiceRequest):
    PlatformApplicationArn: String
    Attributes: MapStringToString


class SetSMSAttributesInput(ServiceRequest):
    attributes: MapStringToString


class SetSMSAttributesResponse(TypedDict, total=False):
    pass


class SetSubscriptionAttributesInput(ServiceRequest):
    SubscriptionArn: subscriptionARN
    AttributeName: attributeName
    AttributeValue: Optional[attributeValue]


class SetTopicAttributesInput(ServiceRequest):
    TopicArn: topicARN
    AttributeName: attributeName
    AttributeValue: Optional[attributeValue]


class SubscribeInput(ServiceRequest):
    TopicArn: topicARN
    Protocol: protocol
    Endpoint: Optional[endpoint]
    Attributes: Optional[SubscriptionAttributesMap]
    ReturnSubscriptionArn: Optional[boolean]


class SubscribeResponse(TypedDict, total=False):
    SubscriptionArn: Optional[subscriptionARN]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UnsubscribeInput(ServiceRequest):
    SubscriptionArn: subscriptionARN


class UntagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class VerifySMSSandboxPhoneNumberInput(ServiceRequest):
    PhoneNumber: PhoneNumberString
    OneTimePassword: OTPCode


class VerifySMSSandboxPhoneNumberResult(TypedDict, total=False):
    pass


class SnsApi:

    service = "sns"
    version = "2010-03-31"

    @handler("AddPermission")
    def add_permission(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        label: label,
        aws_account_id: DelegatesList,
        action_name: ActionsList,
    ) -> None:
        raise NotImplementedError

    @handler("CheckIfPhoneNumberIsOptedOut")
    def check_if_phone_number_is_opted_out(
        self, context: RequestContext, phone_number: PhoneNumber
    ) -> CheckIfPhoneNumberIsOptedOutResponse:
        raise NotImplementedError

    @handler("ConfirmSubscription")
    def confirm_subscription(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        token: token,
        authenticate_on_unsubscribe: authenticateOnUnsubscribe = None,
    ) -> ConfirmSubscriptionResponse:
        raise NotImplementedError

    @handler("CreatePlatformApplication")
    def create_platform_application(
        self, context: RequestContext, name: String, platform: String, attributes: MapStringToString
    ) -> CreatePlatformApplicationResponse:
        raise NotImplementedError

    @handler("CreatePlatformEndpoint")
    def create_platform_endpoint(
        self,
        context: RequestContext,
        platform_application_arn: String,
        token: String,
        custom_user_data: String = None,
        attributes: MapStringToString = None,
    ) -> CreateEndpointResponse:
        raise NotImplementedError

    @handler("CreateSMSSandboxPhoneNumber")
    def create_sms_sandbox_phone_number(
        self,
        context: RequestContext,
        phone_number: PhoneNumberString,
        language_code: LanguageCodeString = None,
    ) -> CreateSMSSandboxPhoneNumberResult:
        raise NotImplementedError

    @handler("CreateTopic")
    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap = None,
        tags: TagList = None,
        data_protection_policy: attributeValue = None,
    ) -> CreateTopicResponse:
        raise NotImplementedError

    @handler("DeleteEndpoint")
    def delete_endpoint(self, context: RequestContext, endpoint_arn: String) -> None:
        raise NotImplementedError

    @handler("DeletePlatformApplication")
    def delete_platform_application(
        self, context: RequestContext, platform_application_arn: String
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSMSSandboxPhoneNumber")
    def delete_sms_sandbox_phone_number(
        self, context: RequestContext, phone_number: PhoneNumberString
    ) -> DeleteSMSSandboxPhoneNumberResult:
        raise NotImplementedError

    @handler("DeleteTopic")
    def delete_topic(self, context: RequestContext, topic_arn: topicARN) -> None:
        raise NotImplementedError

    @handler("GetDataProtectionPolicy")
    def get_data_protection_policy(
        self, context: RequestContext, resource_arn: topicARN
    ) -> GetDataProtectionPolicyResponse:
        raise NotImplementedError

    @handler("GetEndpointAttributes")
    def get_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String
    ) -> GetEndpointAttributesResponse:
        raise NotImplementedError

    @handler("GetPlatformApplicationAttributes")
    def get_platform_application_attributes(
        self, context: RequestContext, platform_application_arn: String
    ) -> GetPlatformApplicationAttributesResponse:
        raise NotImplementedError

    @handler("GetSMSAttributes")
    def get_sms_attributes(
        self, context: RequestContext, attributes: ListString = None
    ) -> GetSMSAttributesResponse:
        raise NotImplementedError

    @handler("GetSMSSandboxAccountStatus")
    def get_sms_sandbox_account_status(
        self,
        context: RequestContext,
    ) -> GetSMSSandboxAccountStatusResult:
        raise NotImplementedError

    @handler("GetSubscriptionAttributes")
    def get_subscription_attributes(
        self, context: RequestContext, subscription_arn: subscriptionARN
    ) -> GetSubscriptionAttributesResponse:
        raise NotImplementedError

    @handler("GetTopicAttributes")
    def get_topic_attributes(
        self, context: RequestContext, topic_arn: topicARN
    ) -> GetTopicAttributesResponse:
        raise NotImplementedError

    @handler("ListEndpointsByPlatformApplication")
    def list_endpoints_by_platform_application(
        self, context: RequestContext, platform_application_arn: String, next_token: String = None
    ) -> ListEndpointsByPlatformApplicationResponse:
        raise NotImplementedError

    @handler("ListOriginationNumbers")
    def list_origination_numbers(
        self,
        context: RequestContext,
        next_token: nextToken = None,
        max_results: MaxItemsListOriginationNumbers = None,
    ) -> ListOriginationNumbersResult:
        raise NotImplementedError

    @handler("ListPhoneNumbersOptedOut")
    def list_phone_numbers_opted_out(
        self, context: RequestContext, next_token: string = None
    ) -> ListPhoneNumbersOptedOutResponse:
        raise NotImplementedError

    @handler("ListPlatformApplications")
    def list_platform_applications(
        self, context: RequestContext, next_token: String = None
    ) -> ListPlatformApplicationsResponse:
        raise NotImplementedError

    @handler("ListSMSSandboxPhoneNumbers")
    def list_sms_sandbox_phone_numbers(
        self, context: RequestContext, next_token: nextToken = None, max_results: MaxItems = None
    ) -> ListSMSSandboxPhoneNumbersResult:
        raise NotImplementedError

    @handler("ListSubscriptions")
    def list_subscriptions(
        self, context: RequestContext, next_token: nextToken = None
    ) -> ListSubscriptionsResponse:
        raise NotImplementedError

    @handler("ListSubscriptionsByTopic")
    def list_subscriptions_by_topic(
        self, context: RequestContext, topic_arn: topicARN, next_token: nextToken = None
    ) -> ListSubscriptionsByTopicResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListTopics")
    def list_topics(
        self, context: RequestContext, next_token: nextToken = None
    ) -> ListTopicsResponse:
        raise NotImplementedError

    @handler("OptInPhoneNumber")
    def opt_in_phone_number(
        self, context: RequestContext, phone_number: PhoneNumber
    ) -> OptInPhoneNumberResponse:
        raise NotImplementedError

    @handler("Publish")
    def publish(
        self,
        context: RequestContext,
        message: message,
        topic_arn: topicARN = None,
        target_arn: String = None,
        phone_number: String = None,
        subject: subject = None,
        message_structure: messageStructure = None,
        message_attributes: MessageAttributeMap = None,
        message_deduplication_id: String = None,
        message_group_id: String = None,
    ) -> PublishResponse:
        raise NotImplementedError

    @handler("PublishBatch")
    def publish_batch(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        publish_batch_request_entries: PublishBatchRequestEntryList,
    ) -> PublishBatchResponse:
        raise NotImplementedError

    @handler("PutDataProtectionPolicy")
    def put_data_protection_policy(
        self,
        context: RequestContext,
        resource_arn: topicARN,
        data_protection_policy: attributeValue,
    ) -> None:
        raise NotImplementedError

    @handler("RemovePermission")
    def remove_permission(self, context: RequestContext, topic_arn: topicARN, label: label) -> None:
        raise NotImplementedError

    @handler("SetEndpointAttributes")
    def set_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String, attributes: MapStringToString
    ) -> None:
        raise NotImplementedError

    @handler("SetPlatformApplicationAttributes")
    def set_platform_application_attributes(
        self,
        context: RequestContext,
        platform_application_arn: String,
        attributes: MapStringToString,
    ) -> None:
        raise NotImplementedError

    @handler("SetSMSAttributes")
    def set_sms_attributes(
        self, context: RequestContext, attributes: MapStringToString
    ) -> SetSMSAttributesResponse:
        raise NotImplementedError

    @handler("SetSubscriptionAttributes")
    def set_subscription_attributes(
        self,
        context: RequestContext,
        subscription_arn: subscriptionARN,
        attribute_name: attributeName,
        attribute_value: attributeValue = None,
    ) -> None:
        raise NotImplementedError

    @handler("SetTopicAttributes")
    def set_topic_attributes(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        attribute_name: attributeName,
        attribute_value: attributeValue = None,
    ) -> None:
        raise NotImplementedError

    @handler("Subscribe")
    def subscribe(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        protocol: protocol,
        endpoint: endpoint = None,
        attributes: SubscriptionAttributesMap = None,
        return_subscription_arn: boolean = None,
    ) -> SubscribeResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("Unsubscribe")
    def unsubscribe(self, context: RequestContext, subscription_arn: subscriptionARN) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("VerifySMSSandboxPhoneNumber")
    def verify_sms_sandbox_phone_number(
        self, context: RequestContext, phone_number: PhoneNumberString, one_time_password: OTPCode
    ) -> VerifySMSSandboxPhoneNumberResult:
        raise NotImplementedError
