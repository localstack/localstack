from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Address = str
AmazonResourceName = str
BounceMessage = str
BounceSmtpReplyCode = str
BounceStatusCode = str
Charset = str
Cidr = str
ConfigurationSetName = str
ConnectInstanceArn = str
CustomRedirectDomain = str
DefaultDimensionValue = str
DiagnosticCode = str
DimensionName = str
Domain = str
DsnStatus = str
Enabled = bool
Error = str
EventDestinationName = str
Explanation = str
ExtensionFieldName = str
ExtensionFieldValue = str
FailureRedirectionURL = str
FromAddress = str
HeaderName = str
HeaderValue = str
HtmlPart = str
IAMRoleARN = str
Identity = str
MailFromDomainName = str
Max24HourSend = float
MaxItems = int
MaxResults = int
MaxSendRate = float
MessageData = str
MessageId = str
MessageTagName = str
MessageTagValue = str
NextToken = str
NotificationTopic = str
Policy = str
PolicyName = str
ReceiptFilterName = str
ReceiptRuleName = str
ReceiptRuleSetName = str
Recipient = str
RemoteMta = str
RenderedTemplate = str
ReportingMta = str
RuleOrRuleSetName = str
S3BucketName = str
S3KeyPrefix = str
SentLast24Hours = float
Subject = str
SubjectPart = str
SuccessRedirectionURL = str
TemplateContent = str
TemplateData = str
TemplateName = str
TextPart = str
VerificationToken = str


class BehaviorOnMXFailure(StrEnum):
    UseDefaultValue = "UseDefaultValue"
    RejectMessage = "RejectMessage"


class BounceType(StrEnum):
    DoesNotExist = "DoesNotExist"
    MessageTooLarge = "MessageTooLarge"
    ExceededQuota = "ExceededQuota"
    ContentRejected = "ContentRejected"
    Undefined = "Undefined"
    TemporaryFailure = "TemporaryFailure"


class BulkEmailStatus(StrEnum):
    Success = "Success"
    MessageRejected = "MessageRejected"
    MailFromDomainNotVerified = "MailFromDomainNotVerified"
    ConfigurationSetDoesNotExist = "ConfigurationSetDoesNotExist"
    TemplateDoesNotExist = "TemplateDoesNotExist"
    AccountSuspended = "AccountSuspended"
    AccountThrottled = "AccountThrottled"
    AccountDailyQuotaExceeded = "AccountDailyQuotaExceeded"
    InvalidSendingPoolName = "InvalidSendingPoolName"
    AccountSendingPaused = "AccountSendingPaused"
    ConfigurationSetSendingPaused = "ConfigurationSetSendingPaused"
    InvalidParameterValue = "InvalidParameterValue"
    TransientFailure = "TransientFailure"
    Failed = "Failed"


class ConfigurationSetAttribute(StrEnum):
    eventDestinations = "eventDestinations"
    trackingOptions = "trackingOptions"
    deliveryOptions = "deliveryOptions"
    reputationOptions = "reputationOptions"


class CustomMailFromStatus(StrEnum):
    Pending = "Pending"
    Success = "Success"
    Failed = "Failed"
    TemporaryFailure = "TemporaryFailure"


class DimensionValueSource(StrEnum):
    messageTag = "messageTag"
    emailHeader = "emailHeader"
    linkTag = "linkTag"


class DsnAction(StrEnum):
    failed = "failed"
    delayed = "delayed"
    delivered = "delivered"
    relayed = "relayed"
    expanded = "expanded"


class EventType(StrEnum):
    send = "send"
    reject = "reject"
    bounce = "bounce"
    complaint = "complaint"
    delivery = "delivery"
    open = "open"
    click = "click"
    renderingFailure = "renderingFailure"


class IdentityType(StrEnum):
    EmailAddress = "EmailAddress"
    Domain = "Domain"


class InvocationType(StrEnum):
    Event = "Event"
    RequestResponse = "RequestResponse"


class NotificationType(StrEnum):
    Bounce = "Bounce"
    Complaint = "Complaint"
    Delivery = "Delivery"


class ReceiptFilterPolicy(StrEnum):
    Block = "Block"
    Allow = "Allow"


class SNSActionEncoding(StrEnum):
    UTF_8 = "UTF-8"
    Base64 = "Base64"


class StopScope(StrEnum):
    RuleSet = "RuleSet"


class TlsPolicy(StrEnum):
    Require = "Require"
    Optional_ = "Optional"


class VerificationStatus(StrEnum):
    Pending = "Pending"
    Success = "Success"
    Failed = "Failed"
    TemporaryFailure = "TemporaryFailure"
    NotStarted = "NotStarted"


class AccountSendingPausedException(ServiceException):
    code: str = "AccountSendingPausedException"
    sender_fault: bool = True
    status_code: int = 400


class AlreadyExistsException(ServiceException):
    code: str = "AlreadyExists"
    sender_fault: bool = True
    status_code: int = 400
    Name: Optional[RuleOrRuleSetName]


class CannotDeleteException(ServiceException):
    code: str = "CannotDelete"
    sender_fault: bool = True
    status_code: int = 400
    Name: Optional[RuleOrRuleSetName]


class ConfigurationSetAlreadyExistsException(ServiceException):
    code: str = "ConfigurationSetAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]


class ConfigurationSetDoesNotExistException(ServiceException):
    code: str = "ConfigurationSetDoesNotExist"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]


class ConfigurationSetSendingPausedException(ServiceException):
    code: str = "ConfigurationSetSendingPausedException"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]


class CustomVerificationEmailInvalidContentException(ServiceException):
    code: str = "CustomVerificationEmailInvalidContent"
    sender_fault: bool = True
    status_code: int = 400


class CustomVerificationEmailTemplateAlreadyExistsException(ServiceException):
    code: str = "CustomVerificationEmailTemplateAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400
    CustomVerificationEmailTemplateName: Optional[TemplateName]


class CustomVerificationEmailTemplateDoesNotExistException(ServiceException):
    code: str = "CustomVerificationEmailTemplateDoesNotExist"
    sender_fault: bool = True
    status_code: int = 400
    CustomVerificationEmailTemplateName: Optional[TemplateName]


class EventDestinationAlreadyExistsException(ServiceException):
    code: str = "EventDestinationAlreadyExists"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class EventDestinationDoesNotExistException(ServiceException):
    code: str = "EventDestinationDoesNotExist"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class FromEmailAddressNotVerifiedException(ServiceException):
    code: str = "FromEmailAddressNotVerified"
    sender_fault: bool = True
    status_code: int = 400
    FromEmailAddress: Optional[FromAddress]


class InvalidCloudWatchDestinationException(ServiceException):
    code: str = "InvalidCloudWatchDestination"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class InvalidConfigurationSetException(ServiceException):
    code: str = "InvalidConfigurationSet"
    sender_fault: bool = True
    status_code: int = 400


class InvalidDeliveryOptionsException(ServiceException):
    code: str = "InvalidDeliveryOptions"
    sender_fault: bool = True
    status_code: int = 400


class InvalidFirehoseDestinationException(ServiceException):
    code: str = "InvalidFirehoseDestination"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class InvalidLambdaFunctionException(ServiceException):
    code: str = "InvalidLambdaFunction"
    sender_fault: bool = True
    status_code: int = 400
    FunctionArn: Optional[AmazonResourceName]


class InvalidPolicyException(ServiceException):
    code: str = "InvalidPolicy"
    sender_fault: bool = True
    status_code: int = 400


class InvalidRenderingParameterException(ServiceException):
    code: str = "InvalidRenderingParameter"
    sender_fault: bool = True
    status_code: int = 400
    TemplateName: Optional[TemplateName]


class InvalidS3ConfigurationException(ServiceException):
    code: str = "InvalidS3Configuration"
    sender_fault: bool = True
    status_code: int = 400
    Bucket: Optional[S3BucketName]


class InvalidSNSDestinationException(ServiceException):
    code: str = "InvalidSNSDestination"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class InvalidSnsTopicException(ServiceException):
    code: str = "InvalidSnsTopic"
    sender_fault: bool = True
    status_code: int = 400
    Topic: Optional[AmazonResourceName]


class InvalidTemplateException(ServiceException):
    code: str = "InvalidTemplate"
    sender_fault: bool = True
    status_code: int = 400
    TemplateName: Optional[TemplateName]


class InvalidTrackingOptionsException(ServiceException):
    code: str = "InvalidTrackingOptions"
    sender_fault: bool = True
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceeded"
    sender_fault: bool = True
    status_code: int = 400


class MailFromDomainNotVerifiedException(ServiceException):
    code: str = "MailFromDomainNotVerifiedException"
    sender_fault: bool = True
    status_code: int = 400


class MessageRejected(ServiceException):
    code: str = "MessageRejected"
    sender_fault: bool = True
    status_code: int = 400


class MissingRenderingAttributeException(ServiceException):
    code: str = "MissingRenderingAttribute"
    sender_fault: bool = True
    status_code: int = 400
    TemplateName: Optional[TemplateName]


class ProductionAccessNotGrantedException(ServiceException):
    code: str = "ProductionAccessNotGranted"
    sender_fault: bool = True
    status_code: int = 400


class RuleDoesNotExistException(ServiceException):
    code: str = "RuleDoesNotExist"
    sender_fault: bool = True
    status_code: int = 400
    Name: Optional[RuleOrRuleSetName]


class RuleSetDoesNotExistException(ServiceException):
    code: str = "RuleSetDoesNotExist"
    sender_fault: bool = True
    status_code: int = 400
    Name: Optional[RuleOrRuleSetName]


class TemplateDoesNotExistException(ServiceException):
    code: str = "TemplateDoesNotExist"
    sender_fault: bool = True
    status_code: int = 400
    TemplateName: Optional[TemplateName]


class TrackingOptionsAlreadyExistsException(ServiceException):
    code: str = "TrackingOptionsAlreadyExistsException"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]


class TrackingOptionsDoesNotExistException(ServiceException):
    code: str = "TrackingOptionsDoesNotExistException"
    sender_fault: bool = True
    status_code: int = 400
    ConfigurationSetName: Optional[ConfigurationSetName]


class AddHeaderAction(TypedDict, total=False):
    HeaderName: HeaderName
    HeaderValue: HeaderValue


AddressList = List[Address]
ArrivalDate = datetime


class Content(TypedDict, total=False):
    Data: MessageData
    Charset: Optional[Charset]


class Body(TypedDict, total=False):
    Text: Optional[Content]
    Html: Optional[Content]


class BounceAction(TypedDict, total=False):
    TopicArn: Optional[AmazonResourceName]
    SmtpReplyCode: BounceSmtpReplyCode
    StatusCode: Optional[BounceStatusCode]
    Message: BounceMessage
    Sender: Address


class ExtensionField(TypedDict, total=False):
    Name: ExtensionFieldName
    Value: ExtensionFieldValue


ExtensionFieldList = List[ExtensionField]
LastAttemptDate = datetime


class RecipientDsnFields(TypedDict, total=False):
    FinalRecipient: Optional[Address]
    Action: DsnAction
    RemoteMta: Optional[RemoteMta]
    Status: DsnStatus
    DiagnosticCode: Optional[DiagnosticCode]
    LastAttemptDate: Optional[LastAttemptDate]
    ExtensionFields: Optional[ExtensionFieldList]


class BouncedRecipientInfo(TypedDict, total=False):
    Recipient: Address
    RecipientArn: Optional[AmazonResourceName]
    BounceType: Optional[BounceType]
    RecipientDsnFields: Optional[RecipientDsnFields]


BouncedRecipientInfoList = List[BouncedRecipientInfo]


class MessageTag(TypedDict, total=False):
    Name: MessageTagName
    Value: MessageTagValue


MessageTagList = List[MessageTag]


class Destination(TypedDict, total=False):
    ToAddresses: Optional[AddressList]
    CcAddresses: Optional[AddressList]
    BccAddresses: Optional[AddressList]


class BulkEmailDestination(TypedDict, total=False):
    Destination: Destination
    ReplacementTags: Optional[MessageTagList]
    ReplacementTemplateData: Optional[TemplateData]


BulkEmailDestinationList = List[BulkEmailDestination]


class BulkEmailDestinationStatus(TypedDict, total=False):
    Status: Optional[BulkEmailStatus]
    Error: Optional[Error]
    MessageId: Optional[MessageId]


BulkEmailDestinationStatusList = List[BulkEmailDestinationStatus]


class CloneReceiptRuleSetRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName
    OriginalRuleSetName: ReceiptRuleSetName


class CloneReceiptRuleSetResponse(TypedDict, total=False):
    pass


class CloudWatchDimensionConfiguration(TypedDict, total=False):
    DimensionName: DimensionName
    DimensionValueSource: DimensionValueSource
    DefaultDimensionValue: DefaultDimensionValue


CloudWatchDimensionConfigurations = List[CloudWatchDimensionConfiguration]


class CloudWatchDestination(TypedDict, total=False):
    DimensionConfigurations: CloudWatchDimensionConfigurations


class ConfigurationSet(TypedDict, total=False):
    Name: ConfigurationSetName


ConfigurationSetAttributeList = List[ConfigurationSetAttribute]
ConfigurationSets = List[ConfigurationSet]


class ConnectAction(TypedDict, total=False):
    InstanceARN: ConnectInstanceArn
    IAMRoleARN: IAMRoleARN


Counter = int


class SNSDestination(TypedDict, total=False):
    TopicARN: AmazonResourceName


class KinesisFirehoseDestination(TypedDict, total=False):
    IAMRoleARN: AmazonResourceName
    DeliveryStreamARN: AmazonResourceName


EventTypes = List[EventType]


class EventDestination(TypedDict, total=False):
    Name: EventDestinationName
    Enabled: Optional[Enabled]
    MatchingEventTypes: EventTypes
    KinesisFirehoseDestination: Optional[KinesisFirehoseDestination]
    CloudWatchDestination: Optional[CloudWatchDestination]
    SNSDestination: Optional[SNSDestination]


class CreateConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestination: EventDestination


class CreateConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass


class CreateConfigurationSetRequest(ServiceRequest):
    ConfigurationSet: ConfigurationSet


class CreateConfigurationSetResponse(TypedDict, total=False):
    pass


class TrackingOptions(TypedDict, total=False):
    CustomRedirectDomain: Optional[CustomRedirectDomain]


class CreateConfigurationSetTrackingOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    TrackingOptions: TrackingOptions


class CreateConfigurationSetTrackingOptionsResponse(TypedDict, total=False):
    pass


class CreateCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: TemplateName
    FromEmailAddress: FromAddress
    TemplateSubject: Subject
    TemplateContent: TemplateContent
    SuccessRedirectionURL: SuccessRedirectionURL
    FailureRedirectionURL: FailureRedirectionURL


class ReceiptIpFilter(TypedDict, total=False):
    Policy: ReceiptFilterPolicy
    Cidr: Cidr


class ReceiptFilter(TypedDict, total=False):
    Name: ReceiptFilterName
    IpFilter: ReceiptIpFilter


class CreateReceiptFilterRequest(ServiceRequest):
    Filter: ReceiptFilter


class CreateReceiptFilterResponse(TypedDict, total=False):
    pass


class SNSAction(TypedDict, total=False):
    TopicArn: AmazonResourceName
    Encoding: Optional[SNSActionEncoding]


class StopAction(TypedDict, total=False):
    Scope: StopScope
    TopicArn: Optional[AmazonResourceName]


class LambdaAction(TypedDict, total=False):
    TopicArn: Optional[AmazonResourceName]
    FunctionArn: AmazonResourceName
    InvocationType: Optional[InvocationType]


class WorkmailAction(TypedDict, total=False):
    TopicArn: Optional[AmazonResourceName]
    OrganizationArn: AmazonResourceName


class S3Action(TypedDict, total=False):
    TopicArn: Optional[AmazonResourceName]
    BucketName: S3BucketName
    ObjectKeyPrefix: Optional[S3KeyPrefix]
    KmsKeyArn: Optional[AmazonResourceName]
    IamRoleArn: Optional[IAMRoleARN]


class ReceiptAction(TypedDict, total=False):
    S3Action: Optional[S3Action]
    BounceAction: Optional[BounceAction]
    WorkmailAction: Optional[WorkmailAction]
    LambdaAction: Optional[LambdaAction]
    StopAction: Optional[StopAction]
    AddHeaderAction: Optional[AddHeaderAction]
    SNSAction: Optional[SNSAction]
    ConnectAction: Optional[ConnectAction]


ReceiptActionsList = List[ReceiptAction]
RecipientsList = List[Recipient]


class ReceiptRule(TypedDict, total=False):
    Name: ReceiptRuleName
    Enabled: Optional[Enabled]
    TlsPolicy: Optional[TlsPolicy]
    Recipients: Optional[RecipientsList]
    Actions: Optional[ReceiptActionsList]
    ScanEnabled: Optional[Enabled]


class CreateReceiptRuleRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName
    After: Optional[ReceiptRuleName]
    Rule: ReceiptRule


class CreateReceiptRuleResponse(TypedDict, total=False):
    pass


class CreateReceiptRuleSetRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName


class CreateReceiptRuleSetResponse(TypedDict, total=False):
    pass


class Template(TypedDict, total=False):
    TemplateName: TemplateName
    SubjectPart: Optional[SubjectPart]
    TextPart: Optional[TextPart]
    HtmlPart: Optional[HtmlPart]


class CreateTemplateRequest(ServiceRequest):
    Template: Template


class CreateTemplateResponse(TypedDict, total=False):
    pass


class CustomVerificationEmailTemplate(TypedDict, total=False):
    TemplateName: Optional[TemplateName]
    FromEmailAddress: Optional[FromAddress]
    TemplateSubject: Optional[Subject]
    SuccessRedirectionURL: Optional[SuccessRedirectionURL]
    FailureRedirectionURL: Optional[FailureRedirectionURL]


CustomVerificationEmailTemplates = List[CustomVerificationEmailTemplate]


class DeleteConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestinationName: EventDestinationName


class DeleteConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass


class DeleteConfigurationSetRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName


class DeleteConfigurationSetResponse(TypedDict, total=False):
    pass


class DeleteConfigurationSetTrackingOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName


class DeleteConfigurationSetTrackingOptionsResponse(TypedDict, total=False):
    pass


class DeleteCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: TemplateName


class DeleteIdentityPolicyRequest(ServiceRequest):
    Identity: Identity
    PolicyName: PolicyName


class DeleteIdentityPolicyResponse(TypedDict, total=False):
    pass


class DeleteIdentityRequest(ServiceRequest):
    Identity: Identity


class DeleteIdentityResponse(TypedDict, total=False):
    pass


class DeleteReceiptFilterRequest(ServiceRequest):
    FilterName: ReceiptFilterName


class DeleteReceiptFilterResponse(TypedDict, total=False):
    pass


class DeleteReceiptRuleRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName
    RuleName: ReceiptRuleName


class DeleteReceiptRuleResponse(TypedDict, total=False):
    pass


class DeleteReceiptRuleSetRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName


class DeleteReceiptRuleSetResponse(TypedDict, total=False):
    pass


class DeleteTemplateRequest(ServiceRequest):
    TemplateName: TemplateName


class DeleteTemplateResponse(TypedDict, total=False):
    pass


class DeleteVerifiedEmailAddressRequest(ServiceRequest):
    EmailAddress: Address


class DeliveryOptions(TypedDict, total=False):
    TlsPolicy: Optional[TlsPolicy]


class DescribeActiveReceiptRuleSetRequest(ServiceRequest):
    pass


ReceiptRulesList = List[ReceiptRule]
Timestamp = datetime


class ReceiptRuleSetMetadata(TypedDict, total=False):
    Name: Optional[ReceiptRuleSetName]
    CreatedTimestamp: Optional[Timestamp]


class DescribeActiveReceiptRuleSetResponse(TypedDict, total=False):
    Metadata: Optional[ReceiptRuleSetMetadata]
    Rules: Optional[ReceiptRulesList]


class DescribeConfigurationSetRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    ConfigurationSetAttributeNames: Optional[ConfigurationSetAttributeList]


LastFreshStart = datetime


class ReputationOptions(TypedDict, total=False):
    SendingEnabled: Optional[Enabled]
    ReputationMetricsEnabled: Optional[Enabled]
    LastFreshStart: Optional[LastFreshStart]


EventDestinations = List[EventDestination]


class DescribeConfigurationSetResponse(TypedDict, total=False):
    ConfigurationSet: Optional[ConfigurationSet]
    EventDestinations: Optional[EventDestinations]
    TrackingOptions: Optional[TrackingOptions]
    DeliveryOptions: Optional[DeliveryOptions]
    ReputationOptions: Optional[ReputationOptions]


class DescribeReceiptRuleRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName
    RuleName: ReceiptRuleName


class DescribeReceiptRuleResponse(TypedDict, total=False):
    Rule: Optional[ReceiptRule]


class DescribeReceiptRuleSetRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName


class DescribeReceiptRuleSetResponse(TypedDict, total=False):
    Metadata: Optional[ReceiptRuleSetMetadata]
    Rules: Optional[ReceiptRulesList]


VerificationTokenList = List[VerificationToken]


class IdentityDkimAttributes(TypedDict, total=False):
    DkimEnabled: Enabled
    DkimVerificationStatus: VerificationStatus
    DkimTokens: Optional[VerificationTokenList]


DkimAttributes = Dict[Identity, IdentityDkimAttributes]


class GetAccountSendingEnabledResponse(TypedDict, total=False):
    Enabled: Optional[Enabled]


class GetCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: TemplateName


class GetCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    TemplateName: Optional[TemplateName]
    FromEmailAddress: Optional[FromAddress]
    TemplateSubject: Optional[Subject]
    TemplateContent: Optional[TemplateContent]
    SuccessRedirectionURL: Optional[SuccessRedirectionURL]
    FailureRedirectionURL: Optional[FailureRedirectionURL]


IdentityList = List[Identity]


class GetIdentityDkimAttributesRequest(ServiceRequest):
    Identities: IdentityList


class GetIdentityDkimAttributesResponse(TypedDict, total=False):
    DkimAttributes: DkimAttributes


class GetIdentityMailFromDomainAttributesRequest(ServiceRequest):
    Identities: IdentityList


class IdentityMailFromDomainAttributes(TypedDict, total=False):
    MailFromDomain: MailFromDomainName
    MailFromDomainStatus: CustomMailFromStatus
    BehaviorOnMXFailure: BehaviorOnMXFailure


MailFromDomainAttributes = Dict[Identity, IdentityMailFromDomainAttributes]


class GetIdentityMailFromDomainAttributesResponse(TypedDict, total=False):
    MailFromDomainAttributes: MailFromDomainAttributes


class GetIdentityNotificationAttributesRequest(ServiceRequest):
    Identities: IdentityList


class IdentityNotificationAttributes(TypedDict, total=False):
    BounceTopic: NotificationTopic
    ComplaintTopic: NotificationTopic
    DeliveryTopic: NotificationTopic
    ForwardingEnabled: Enabled
    HeadersInBounceNotificationsEnabled: Optional[Enabled]
    HeadersInComplaintNotificationsEnabled: Optional[Enabled]
    HeadersInDeliveryNotificationsEnabled: Optional[Enabled]


NotificationAttributes = Dict[Identity, IdentityNotificationAttributes]


class GetIdentityNotificationAttributesResponse(TypedDict, total=False):
    NotificationAttributes: NotificationAttributes


PolicyNameList = List[PolicyName]


class GetIdentityPoliciesRequest(ServiceRequest):
    Identity: Identity
    PolicyNames: PolicyNameList


PolicyMap = Dict[PolicyName, Policy]


class GetIdentityPoliciesResponse(TypedDict, total=False):
    Policies: PolicyMap


class GetIdentityVerificationAttributesRequest(ServiceRequest):
    Identities: IdentityList


class IdentityVerificationAttributes(TypedDict, total=False):
    VerificationStatus: VerificationStatus
    VerificationToken: Optional[VerificationToken]


VerificationAttributes = Dict[Identity, IdentityVerificationAttributes]


class GetIdentityVerificationAttributesResponse(TypedDict, total=False):
    VerificationAttributes: VerificationAttributes


class GetSendQuotaResponse(TypedDict, total=False):
    Max24HourSend: Optional[Max24HourSend]
    MaxSendRate: Optional[MaxSendRate]
    SentLast24Hours: Optional[SentLast24Hours]


class SendDataPoint(TypedDict, total=False):
    Timestamp: Optional[Timestamp]
    DeliveryAttempts: Optional[Counter]
    Bounces: Optional[Counter]
    Complaints: Optional[Counter]
    Rejects: Optional[Counter]


SendDataPointList = List[SendDataPoint]


class GetSendStatisticsResponse(TypedDict, total=False):
    SendDataPoints: Optional[SendDataPointList]


class GetTemplateRequest(ServiceRequest):
    TemplateName: TemplateName


class GetTemplateResponse(TypedDict, total=False):
    Template: Optional[Template]


class ListConfigurationSetsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxItems: Optional[MaxItems]


class ListConfigurationSetsResponse(TypedDict, total=False):
    ConfigurationSets: Optional[ConfigurationSets]
    NextToken: Optional[NextToken]


class ListCustomVerificationEmailTemplatesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListCustomVerificationEmailTemplatesResponse(TypedDict, total=False):
    CustomVerificationEmailTemplates: Optional[CustomVerificationEmailTemplates]
    NextToken: Optional[NextToken]


class ListIdentitiesRequest(ServiceRequest):
    IdentityType: Optional[IdentityType]
    NextToken: Optional[NextToken]
    MaxItems: Optional[MaxItems]


class ListIdentitiesResponse(TypedDict, total=False):
    Identities: IdentityList
    NextToken: Optional[NextToken]


class ListIdentityPoliciesRequest(ServiceRequest):
    Identity: Identity


class ListIdentityPoliciesResponse(TypedDict, total=False):
    PolicyNames: PolicyNameList


class ListReceiptFiltersRequest(ServiceRequest):
    pass


ReceiptFilterList = List[ReceiptFilter]


class ListReceiptFiltersResponse(TypedDict, total=False):
    Filters: Optional[ReceiptFilterList]


class ListReceiptRuleSetsRequest(ServiceRequest):
    NextToken: Optional[NextToken]


ReceiptRuleSetsLists = List[ReceiptRuleSetMetadata]


class ListReceiptRuleSetsResponse(TypedDict, total=False):
    RuleSets: Optional[ReceiptRuleSetsLists]
    NextToken: Optional[NextToken]


class ListTemplatesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxItems: Optional[MaxItems]


class TemplateMetadata(TypedDict, total=False):
    Name: Optional[TemplateName]
    CreatedTimestamp: Optional[Timestamp]


TemplateMetadataList = List[TemplateMetadata]


class ListTemplatesResponse(TypedDict, total=False):
    TemplatesMetadata: Optional[TemplateMetadataList]
    NextToken: Optional[NextToken]


class ListVerifiedEmailAddressesResponse(TypedDict, total=False):
    VerifiedEmailAddresses: Optional[AddressList]


class Message(TypedDict, total=False):
    Subject: Content
    Body: Body


class MessageDsn(TypedDict, total=False):
    ReportingMta: ReportingMta
    ArrivalDate: Optional[ArrivalDate]
    ExtensionFields: Optional[ExtensionFieldList]


class PutConfigurationSetDeliveryOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    DeliveryOptions: Optional[DeliveryOptions]


class PutConfigurationSetDeliveryOptionsResponse(TypedDict, total=False):
    pass


class PutIdentityPolicyRequest(ServiceRequest):
    Identity: Identity
    PolicyName: PolicyName
    Policy: Policy


class PutIdentityPolicyResponse(TypedDict, total=False):
    pass


RawMessageData = bytes


class RawMessage(TypedDict, total=False):
    Data: RawMessageData


ReceiptRuleNamesList = List[ReceiptRuleName]


class ReorderReceiptRuleSetRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName
    RuleNames: ReceiptRuleNamesList


class ReorderReceiptRuleSetResponse(TypedDict, total=False):
    pass


class SendBounceRequest(ServiceRequest):
    OriginalMessageId: MessageId
    BounceSender: Address
    Explanation: Optional[Explanation]
    MessageDsn: Optional[MessageDsn]
    BouncedRecipientInfoList: BouncedRecipientInfoList
    BounceSenderArn: Optional[AmazonResourceName]


class SendBounceResponse(TypedDict, total=False):
    MessageId: Optional[MessageId]


class SendBulkTemplatedEmailRequest(ServiceRequest):
    Source: Address
    SourceArn: Optional[AmazonResourceName]
    ReplyToAddresses: Optional[AddressList]
    ReturnPath: Optional[Address]
    ReturnPathArn: Optional[AmazonResourceName]
    ConfigurationSetName: Optional[ConfigurationSetName]
    DefaultTags: Optional[MessageTagList]
    Template: TemplateName
    TemplateArn: Optional[AmazonResourceName]
    DefaultTemplateData: TemplateData
    Destinations: BulkEmailDestinationList


class SendBulkTemplatedEmailResponse(TypedDict, total=False):
    Status: BulkEmailDestinationStatusList


class SendCustomVerificationEmailRequest(ServiceRequest):
    EmailAddress: Address
    TemplateName: TemplateName
    ConfigurationSetName: Optional[ConfigurationSetName]


class SendCustomVerificationEmailResponse(TypedDict, total=False):
    MessageId: Optional[MessageId]


class SendEmailRequest(ServiceRequest):
    Source: Address
    Destination: Destination
    Message: Message
    ReplyToAddresses: Optional[AddressList]
    ReturnPath: Optional[Address]
    SourceArn: Optional[AmazonResourceName]
    ReturnPathArn: Optional[AmazonResourceName]
    Tags: Optional[MessageTagList]
    ConfigurationSetName: Optional[ConfigurationSetName]


class SendEmailResponse(TypedDict, total=False):
    MessageId: MessageId


class SendRawEmailRequest(ServiceRequest):
    Source: Optional[Address]
    Destinations: Optional[AddressList]
    RawMessage: RawMessage
    FromArn: Optional[AmazonResourceName]
    SourceArn: Optional[AmazonResourceName]
    ReturnPathArn: Optional[AmazonResourceName]
    Tags: Optional[MessageTagList]
    ConfigurationSetName: Optional[ConfigurationSetName]


class SendRawEmailResponse(TypedDict, total=False):
    MessageId: MessageId


class SendTemplatedEmailRequest(ServiceRequest):
    Source: Address
    Destination: Destination
    ReplyToAddresses: Optional[AddressList]
    ReturnPath: Optional[Address]
    SourceArn: Optional[AmazonResourceName]
    ReturnPathArn: Optional[AmazonResourceName]
    Tags: Optional[MessageTagList]
    ConfigurationSetName: Optional[ConfigurationSetName]
    Template: TemplateName
    TemplateArn: Optional[AmazonResourceName]
    TemplateData: TemplateData


class SendTemplatedEmailResponse(TypedDict, total=False):
    MessageId: MessageId


class SetActiveReceiptRuleSetRequest(ServiceRequest):
    RuleSetName: Optional[ReceiptRuleSetName]


class SetActiveReceiptRuleSetResponse(TypedDict, total=False):
    pass


class SetIdentityDkimEnabledRequest(ServiceRequest):
    Identity: Identity
    DkimEnabled: Enabled


class SetIdentityDkimEnabledResponse(TypedDict, total=False):
    pass


class SetIdentityFeedbackForwardingEnabledRequest(ServiceRequest):
    Identity: Identity
    ForwardingEnabled: Enabled


class SetIdentityFeedbackForwardingEnabledResponse(TypedDict, total=False):
    pass


class SetIdentityHeadersInNotificationsEnabledRequest(ServiceRequest):
    Identity: Identity
    NotificationType: NotificationType
    Enabled: Enabled


class SetIdentityHeadersInNotificationsEnabledResponse(TypedDict, total=False):
    pass


class SetIdentityMailFromDomainRequest(ServiceRequest):
    Identity: Identity
    MailFromDomain: Optional[MailFromDomainName]
    BehaviorOnMXFailure: Optional[BehaviorOnMXFailure]


class SetIdentityMailFromDomainResponse(TypedDict, total=False):
    pass


class SetIdentityNotificationTopicRequest(ServiceRequest):
    Identity: Identity
    NotificationType: NotificationType
    SnsTopic: Optional[NotificationTopic]


class SetIdentityNotificationTopicResponse(TypedDict, total=False):
    pass


class SetReceiptRulePositionRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName
    RuleName: ReceiptRuleName
    After: Optional[ReceiptRuleName]


class SetReceiptRulePositionResponse(TypedDict, total=False):
    pass


class TestRenderTemplateRequest(ServiceRequest):
    TemplateName: TemplateName
    TemplateData: TemplateData


class TestRenderTemplateResponse(TypedDict, total=False):
    RenderedTemplate: Optional[RenderedTemplate]


class UpdateAccountSendingEnabledRequest(ServiceRequest):
    Enabled: Optional[Enabled]


class UpdateConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestination: EventDestination


class UpdateConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass


class UpdateConfigurationSetReputationMetricsEnabledRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    Enabled: Enabled


class UpdateConfigurationSetSendingEnabledRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    Enabled: Enabled


class UpdateConfigurationSetTrackingOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    TrackingOptions: TrackingOptions


class UpdateConfigurationSetTrackingOptionsResponse(TypedDict, total=False):
    pass


class UpdateCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: TemplateName
    FromEmailAddress: Optional[FromAddress]
    TemplateSubject: Optional[Subject]
    TemplateContent: Optional[TemplateContent]
    SuccessRedirectionURL: Optional[SuccessRedirectionURL]
    FailureRedirectionURL: Optional[FailureRedirectionURL]


class UpdateReceiptRuleRequest(ServiceRequest):
    RuleSetName: ReceiptRuleSetName
    Rule: ReceiptRule


class UpdateReceiptRuleResponse(TypedDict, total=False):
    pass


class UpdateTemplateRequest(ServiceRequest):
    Template: Template


class UpdateTemplateResponse(TypedDict, total=False):
    pass


class VerifyDomainDkimRequest(ServiceRequest):
    Domain: Domain


class VerifyDomainDkimResponse(TypedDict, total=False):
    DkimTokens: VerificationTokenList


class VerifyDomainIdentityRequest(ServiceRequest):
    Domain: Domain


class VerifyDomainIdentityResponse(TypedDict, total=False):
    VerificationToken: VerificationToken


class VerifyEmailAddressRequest(ServiceRequest):
    EmailAddress: Address


class VerifyEmailIdentityRequest(ServiceRequest):
    EmailAddress: Address


class VerifyEmailIdentityResponse(TypedDict, total=False):
    pass


class SesApi:
    service = "ses"
    version = "2010-12-01"

    @handler("CloneReceiptRuleSet")
    def clone_receipt_rule_set(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        original_rule_set_name: ReceiptRuleSetName,
        **kwargs,
    ) -> CloneReceiptRuleSetResponse:
        raise NotImplementedError

    @handler("CreateConfigurationSet")
    def create_configuration_set(
        self, context: RequestContext, configuration_set: ConfigurationSet, **kwargs
    ) -> CreateConfigurationSetResponse:
        raise NotImplementedError

    @handler("CreateConfigurationSetEventDestination")
    def create_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination: EventDestination,
        **kwargs,
    ) -> CreateConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("CreateConfigurationSetTrackingOptions")
    def create_configuration_set_tracking_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        tracking_options: TrackingOptions,
        **kwargs,
    ) -> CreateConfigurationSetTrackingOptionsResponse:
        raise NotImplementedError

    @handler("CreateCustomVerificationEmailTemplate")
    def create_custom_verification_email_template(
        self,
        context: RequestContext,
        template_name: TemplateName,
        from_email_address: FromAddress,
        template_subject: Subject,
        template_content: TemplateContent,
        success_redirection_url: SuccessRedirectionURL,
        failure_redirection_url: FailureRedirectionURL,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateReceiptFilter")
    def create_receipt_filter(
        self, context: RequestContext, filter: ReceiptFilter, **kwargs
    ) -> CreateReceiptFilterResponse:
        raise NotImplementedError

    @handler("CreateReceiptRule")
    def create_receipt_rule(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule: ReceiptRule,
        after: ReceiptRuleName | None = None,
        **kwargs,
    ) -> CreateReceiptRuleResponse:
        raise NotImplementedError

    @handler("CreateReceiptRuleSet")
    def create_receipt_rule_set(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName, **kwargs
    ) -> CreateReceiptRuleSetResponse:
        raise NotImplementedError

    @handler("CreateTemplate")
    def create_template(
        self, context: RequestContext, template: Template, **kwargs
    ) -> CreateTemplateResponse:
        raise NotImplementedError

    @handler("DeleteConfigurationSet")
    def delete_configuration_set(
        self, context: RequestContext, configuration_set_name: ConfigurationSetName, **kwargs
    ) -> DeleteConfigurationSetResponse:
        raise NotImplementedError

    @handler("DeleteConfigurationSetEventDestination")
    def delete_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination_name: EventDestinationName,
        **kwargs,
    ) -> DeleteConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("DeleteConfigurationSetTrackingOptions")
    def delete_configuration_set_tracking_options(
        self, context: RequestContext, configuration_set_name: ConfigurationSetName, **kwargs
    ) -> DeleteConfigurationSetTrackingOptionsResponse:
        raise NotImplementedError

    @handler("DeleteCustomVerificationEmailTemplate")
    def delete_custom_verification_email_template(
        self, context: RequestContext, template_name: TemplateName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteIdentity")
    def delete_identity(
        self, context: RequestContext, identity: Identity, **kwargs
    ) -> DeleteIdentityResponse:
        raise NotImplementedError

    @handler("DeleteIdentityPolicy")
    def delete_identity_policy(
        self, context: RequestContext, identity: Identity, policy_name: PolicyName, **kwargs
    ) -> DeleteIdentityPolicyResponse:
        raise NotImplementedError

    @handler("DeleteReceiptFilter")
    def delete_receipt_filter(
        self, context: RequestContext, filter_name: ReceiptFilterName, **kwargs
    ) -> DeleteReceiptFilterResponse:
        raise NotImplementedError

    @handler("DeleteReceiptRule")
    def delete_receipt_rule(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule_name: ReceiptRuleName,
        **kwargs,
    ) -> DeleteReceiptRuleResponse:
        raise NotImplementedError

    @handler("DeleteReceiptRuleSet")
    def delete_receipt_rule_set(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName, **kwargs
    ) -> DeleteReceiptRuleSetResponse:
        raise NotImplementedError

    @handler("DeleteTemplate")
    def delete_template(
        self, context: RequestContext, template_name: TemplateName, **kwargs
    ) -> DeleteTemplateResponse:
        raise NotImplementedError

    @handler("DeleteVerifiedEmailAddress")
    def delete_verified_email_address(
        self, context: RequestContext, email_address: Address, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DescribeActiveReceiptRuleSet")
    def describe_active_receipt_rule_set(
        self, context: RequestContext, **kwargs
    ) -> DescribeActiveReceiptRuleSetResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationSet")
    def describe_configuration_set(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        configuration_set_attribute_names: ConfigurationSetAttributeList | None = None,
        **kwargs,
    ) -> DescribeConfigurationSetResponse:
        raise NotImplementedError

    @handler("DescribeReceiptRule")
    def describe_receipt_rule(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule_name: ReceiptRuleName,
        **kwargs,
    ) -> DescribeReceiptRuleResponse:
        raise NotImplementedError

    @handler("DescribeReceiptRuleSet")
    def describe_receipt_rule_set(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName, **kwargs
    ) -> DescribeReceiptRuleSetResponse:
        raise NotImplementedError

    @handler("GetAccountSendingEnabled")
    def get_account_sending_enabled(
        self, context: RequestContext, **kwargs
    ) -> GetAccountSendingEnabledResponse:
        raise NotImplementedError

    @handler("GetCustomVerificationEmailTemplate")
    def get_custom_verification_email_template(
        self, context: RequestContext, template_name: TemplateName, **kwargs
    ) -> GetCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("GetIdentityDkimAttributes")
    def get_identity_dkim_attributes(
        self, context: RequestContext, identities: IdentityList, **kwargs
    ) -> GetIdentityDkimAttributesResponse:
        raise NotImplementedError

    @handler("GetIdentityMailFromDomainAttributes")
    def get_identity_mail_from_domain_attributes(
        self, context: RequestContext, identities: IdentityList, **kwargs
    ) -> GetIdentityMailFromDomainAttributesResponse:
        raise NotImplementedError

    @handler("GetIdentityNotificationAttributes")
    def get_identity_notification_attributes(
        self, context: RequestContext, identities: IdentityList, **kwargs
    ) -> GetIdentityNotificationAttributesResponse:
        raise NotImplementedError

    @handler("GetIdentityPolicies")
    def get_identity_policies(
        self, context: RequestContext, identity: Identity, policy_names: PolicyNameList, **kwargs
    ) -> GetIdentityPoliciesResponse:
        raise NotImplementedError

    @handler("GetIdentityVerificationAttributes")
    def get_identity_verification_attributes(
        self, context: RequestContext, identities: IdentityList, **kwargs
    ) -> GetIdentityVerificationAttributesResponse:
        raise NotImplementedError

    @handler("GetSendQuota")
    def get_send_quota(self, context: RequestContext, **kwargs) -> GetSendQuotaResponse:
        raise NotImplementedError

    @handler("GetSendStatistics")
    def get_send_statistics(self, context: RequestContext, **kwargs) -> GetSendStatisticsResponse:
        raise NotImplementedError

    @handler("GetTemplate")
    def get_template(
        self, context: RequestContext, template_name: TemplateName, **kwargs
    ) -> GetTemplateResponse:
        raise NotImplementedError

    @handler("ListConfigurationSets")
    def list_configuration_sets(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_items: MaxItems | None = None,
        **kwargs,
    ) -> ListConfigurationSetsResponse:
        raise NotImplementedError

    @handler("ListCustomVerificationEmailTemplates")
    def list_custom_verification_email_templates(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_results: MaxResults | None = None,
        **kwargs,
    ) -> ListCustomVerificationEmailTemplatesResponse:
        raise NotImplementedError

    @handler("ListIdentities")
    def list_identities(
        self,
        context: RequestContext,
        identity_type: IdentityType | None = None,
        next_token: NextToken | None = None,
        max_items: MaxItems | None = None,
        **kwargs,
    ) -> ListIdentitiesResponse:
        raise NotImplementedError

    @handler("ListIdentityPolicies")
    def list_identity_policies(
        self, context: RequestContext, identity: Identity, **kwargs
    ) -> ListIdentityPoliciesResponse:
        raise NotImplementedError

    @handler("ListReceiptFilters")
    def list_receipt_filters(self, context: RequestContext, **kwargs) -> ListReceiptFiltersResponse:
        raise NotImplementedError

    @handler("ListReceiptRuleSets")
    def list_receipt_rule_sets(
        self, context: RequestContext, next_token: NextToken | None = None, **kwargs
    ) -> ListReceiptRuleSetsResponse:
        raise NotImplementedError

    @handler("ListTemplates")
    def list_templates(
        self,
        context: RequestContext,
        next_token: NextToken | None = None,
        max_items: MaxItems | None = None,
        **kwargs,
    ) -> ListTemplatesResponse:
        raise NotImplementedError

    @handler("ListVerifiedEmailAddresses")
    def list_verified_email_addresses(
        self, context: RequestContext, **kwargs
    ) -> ListVerifiedEmailAddressesResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetDeliveryOptions")
    def put_configuration_set_delivery_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        delivery_options: DeliveryOptions | None = None,
        **kwargs,
    ) -> PutConfigurationSetDeliveryOptionsResponse:
        raise NotImplementedError

    @handler("PutIdentityPolicy")
    def put_identity_policy(
        self,
        context: RequestContext,
        identity: Identity,
        policy_name: PolicyName,
        policy: Policy,
        **kwargs,
    ) -> PutIdentityPolicyResponse:
        raise NotImplementedError

    @handler("ReorderReceiptRuleSet")
    def reorder_receipt_rule_set(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule_names: ReceiptRuleNamesList,
        **kwargs,
    ) -> ReorderReceiptRuleSetResponse:
        raise NotImplementedError

    @handler("SendBounce")
    def send_bounce(
        self,
        context: RequestContext,
        original_message_id: MessageId,
        bounce_sender: Address,
        bounced_recipient_info_list: BouncedRecipientInfoList,
        explanation: Explanation | None = None,
        message_dsn: MessageDsn | None = None,
        bounce_sender_arn: AmazonResourceName | None = None,
        **kwargs,
    ) -> SendBounceResponse:
        raise NotImplementedError

    @handler("SendBulkTemplatedEmail")
    def send_bulk_templated_email(
        self,
        context: RequestContext,
        source: Address,
        template: TemplateName,
        default_template_data: TemplateData,
        destinations: BulkEmailDestinationList,
        source_arn: AmazonResourceName | None = None,
        reply_to_addresses: AddressList | None = None,
        return_path: Address | None = None,
        return_path_arn: AmazonResourceName | None = None,
        configuration_set_name: ConfigurationSetName | None = None,
        default_tags: MessageTagList | None = None,
        template_arn: AmazonResourceName | None = None,
        **kwargs,
    ) -> SendBulkTemplatedEmailResponse:
        raise NotImplementedError

    @handler("SendCustomVerificationEmail")
    def send_custom_verification_email(
        self,
        context: RequestContext,
        email_address: Address,
        template_name: TemplateName,
        configuration_set_name: ConfigurationSetName | None = None,
        **kwargs,
    ) -> SendCustomVerificationEmailResponse:
        raise NotImplementedError

    @handler("SendEmail")
    def send_email(
        self,
        context: RequestContext,
        source: Address,
        destination: Destination,
        message: Message,
        reply_to_addresses: AddressList | None = None,
        return_path: Address | None = None,
        source_arn: AmazonResourceName | None = None,
        return_path_arn: AmazonResourceName | None = None,
        tags: MessageTagList | None = None,
        configuration_set_name: ConfigurationSetName | None = None,
        **kwargs,
    ) -> SendEmailResponse:
        raise NotImplementedError

    @handler("SendRawEmail")
    def send_raw_email(
        self,
        context: RequestContext,
        raw_message: RawMessage,
        source: Address | None = None,
        destinations: AddressList | None = None,
        from_arn: AmazonResourceName | None = None,
        source_arn: AmazonResourceName | None = None,
        return_path_arn: AmazonResourceName | None = None,
        tags: MessageTagList | None = None,
        configuration_set_name: ConfigurationSetName | None = None,
        **kwargs,
    ) -> SendRawEmailResponse:
        raise NotImplementedError

    @handler("SendTemplatedEmail")
    def send_templated_email(
        self,
        context: RequestContext,
        source: Address,
        destination: Destination,
        template: TemplateName,
        template_data: TemplateData,
        reply_to_addresses: AddressList | None = None,
        return_path: Address | None = None,
        source_arn: AmazonResourceName | None = None,
        return_path_arn: AmazonResourceName | None = None,
        tags: MessageTagList | None = None,
        configuration_set_name: ConfigurationSetName | None = None,
        template_arn: AmazonResourceName | None = None,
        **kwargs,
    ) -> SendTemplatedEmailResponse:
        raise NotImplementedError

    @handler("SetActiveReceiptRuleSet")
    def set_active_receipt_rule_set(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName | None = None, **kwargs
    ) -> SetActiveReceiptRuleSetResponse:
        raise NotImplementedError

    @handler("SetIdentityDkimEnabled")
    def set_identity_dkim_enabled(
        self, context: RequestContext, identity: Identity, dkim_enabled: Enabled, **kwargs
    ) -> SetIdentityDkimEnabledResponse:
        raise NotImplementedError

    @handler("SetIdentityFeedbackForwardingEnabled")
    def set_identity_feedback_forwarding_enabled(
        self, context: RequestContext, identity: Identity, forwarding_enabled: Enabled, **kwargs
    ) -> SetIdentityFeedbackForwardingEnabledResponse:
        raise NotImplementedError

    @handler("SetIdentityHeadersInNotificationsEnabled")
    def set_identity_headers_in_notifications_enabled(
        self,
        context: RequestContext,
        identity: Identity,
        notification_type: NotificationType,
        enabled: Enabled,
        **kwargs,
    ) -> SetIdentityHeadersInNotificationsEnabledResponse:
        raise NotImplementedError

    @handler("SetIdentityMailFromDomain")
    def set_identity_mail_from_domain(
        self,
        context: RequestContext,
        identity: Identity,
        mail_from_domain: MailFromDomainName | None = None,
        behavior_on_mx_failure: BehaviorOnMXFailure | None = None,
        **kwargs,
    ) -> SetIdentityMailFromDomainResponse:
        raise NotImplementedError

    @handler("SetIdentityNotificationTopic")
    def set_identity_notification_topic(
        self,
        context: RequestContext,
        identity: Identity,
        notification_type: NotificationType,
        sns_topic: NotificationTopic | None = None,
        **kwargs,
    ) -> SetIdentityNotificationTopicResponse:
        raise NotImplementedError

    @handler("SetReceiptRulePosition")
    def set_receipt_rule_position(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule_name: ReceiptRuleName,
        after: ReceiptRuleName | None = None,
        **kwargs,
    ) -> SetReceiptRulePositionResponse:
        raise NotImplementedError

    @handler("TestRenderTemplate")
    def test_render_template(
        self,
        context: RequestContext,
        template_name: TemplateName,
        template_data: TemplateData,
        **kwargs,
    ) -> TestRenderTemplateResponse:
        raise NotImplementedError

    @handler("UpdateAccountSendingEnabled")
    def update_account_sending_enabled(
        self, context: RequestContext, enabled: Enabled | None = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UpdateConfigurationSetEventDestination")
    def update_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination: EventDestination,
        **kwargs,
    ) -> UpdateConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("UpdateConfigurationSetReputationMetricsEnabled")
    def update_configuration_set_reputation_metrics_enabled(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        enabled: Enabled,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateConfigurationSetSendingEnabled")
    def update_configuration_set_sending_enabled(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        enabled: Enabled,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateConfigurationSetTrackingOptions")
    def update_configuration_set_tracking_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        tracking_options: TrackingOptions,
        **kwargs,
    ) -> UpdateConfigurationSetTrackingOptionsResponse:
        raise NotImplementedError

    @handler("UpdateCustomVerificationEmailTemplate")
    def update_custom_verification_email_template(
        self,
        context: RequestContext,
        template_name: TemplateName,
        from_email_address: FromAddress | None = None,
        template_subject: Subject | None = None,
        template_content: TemplateContent | None = None,
        success_redirection_url: SuccessRedirectionURL | None = None,
        failure_redirection_url: FailureRedirectionURL | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UpdateReceiptRule")
    def update_receipt_rule(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule: ReceiptRule,
        **kwargs,
    ) -> UpdateReceiptRuleResponse:
        raise NotImplementedError

    @handler("UpdateTemplate")
    def update_template(
        self, context: RequestContext, template: Template, **kwargs
    ) -> UpdateTemplateResponse:
        raise NotImplementedError

    @handler("VerifyDomainDkim")
    def verify_domain_dkim(
        self, context: RequestContext, domain: Domain, **kwargs
    ) -> VerifyDomainDkimResponse:
        raise NotImplementedError

    @handler("VerifyDomainIdentity")
    def verify_domain_identity(
        self, context: RequestContext, domain: Domain, **kwargs
    ) -> VerifyDomainIdentityResponse:
        raise NotImplementedError

    @handler("VerifyEmailAddress")
    def verify_email_address(
        self, context: RequestContext, email_address: Address, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("VerifyEmailIdentity")
    def verify_email_identity(
        self, context: RequestContext, email_address: Address, **kwargs
    ) -> VerifyEmailIdentityResponse:
        raise NotImplementedError
