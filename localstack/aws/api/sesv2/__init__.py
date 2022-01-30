import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AdditionalContactEmailAddress = str
AmazonResourceName = str
AttributesData = str
BlacklistItemName = str
BlacklistingDescription = str
CampaignId = str
CaseId = str
Charset = str
ConfigurationSetName = str
ContactListName = str
CustomRedirectDomain = str
DefaultDimensionValue = str
DeliverabilityTestSubject = str
Description = str
DimensionName = str
DisplayName = str
DnsToken = str
Domain = str
EmailAddress = str
EmailTemplateData = str
EmailTemplateHtml = str
EmailTemplateName = str
EmailTemplateSubject = str
EmailTemplateText = str
Enabled = bool
EnabledWrapper = bool
ErrorMessage = str
Esp = str
EventDestinationName = str
FailedRecordsCount = int
FailedRecordsS3Url = str
FailureRedirectionURL = str
FeedbackId = str
GeneralEnforcementStatus = str
Identity = str
ImageUrl = str
Ip = str
IspName = str
JobId = str
MailFromDomainName = str
Max24HourSend = float
MaxItems = int
MaxSendRate = float
MessageContent = str
MessageData = str
MessageTagName = str
MessageTagValue = str
NextToken = str
OutboundMessageId = str
Percentage = float
Percentage100Wrapper = int
Policy = str
PolicyName = str
PoolName = str
PrivateKey = str
ProcessedRecordsCount = int
RblName = str
RenderedEmailTemplate = str
ReportId = str
ReportName = str
S3Url = str
Selector = str
SendingPoolName = str
SentLast24Hours = float
Subject = str
SuccessRedirectionURL = str
TagKey = str
TagValue = str
TemplateContent = str
TopicName = str
UnsubscribeAll = bool
UseCaseDescription = str
UseDefaultIfPreferenceUnavailable = bool
WebsiteURL = str


class BehaviorOnMxFailure(str):
    USE_DEFAULT_VALUE = "USE_DEFAULT_VALUE"
    REJECT_MESSAGE = "REJECT_MESSAGE"


class BulkEmailStatus(str):
    SUCCESS = "SUCCESS"
    MESSAGE_REJECTED = "MESSAGE_REJECTED"
    MAIL_FROM_DOMAIN_NOT_VERIFIED = "MAIL_FROM_DOMAIN_NOT_VERIFIED"
    CONFIGURATION_SET_NOT_FOUND = "CONFIGURATION_SET_NOT_FOUND"
    TEMPLATE_NOT_FOUND = "TEMPLATE_NOT_FOUND"
    ACCOUNT_SUSPENDED = "ACCOUNT_SUSPENDED"
    ACCOUNT_THROTTLED = "ACCOUNT_THROTTLED"
    ACCOUNT_DAILY_QUOTA_EXCEEDED = "ACCOUNT_DAILY_QUOTA_EXCEEDED"
    INVALID_SENDING_POOL_NAME = "INVALID_SENDING_POOL_NAME"
    ACCOUNT_SENDING_PAUSED = "ACCOUNT_SENDING_PAUSED"
    CONFIGURATION_SET_SENDING_PAUSED = "CONFIGURATION_SET_SENDING_PAUSED"
    INVALID_PARAMETER = "INVALID_PARAMETER"
    TRANSIENT_FAILURE = "TRANSIENT_FAILURE"
    FAILED = "FAILED"


class ContactLanguage(str):
    EN = "EN"
    JA = "JA"


class ContactListImportAction(str):
    DELETE = "DELETE"
    PUT = "PUT"


class DataFormat(str):
    CSV = "CSV"
    JSON = "JSON"


class DeliverabilityDashboardAccountStatus(str):
    ACTIVE = "ACTIVE"
    PENDING_EXPIRATION = "PENDING_EXPIRATION"
    DISABLED = "DISABLED"


class DeliverabilityTestStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class DimensionValueSource(str):
    MESSAGE_TAG = "MESSAGE_TAG"
    EMAIL_HEADER = "EMAIL_HEADER"
    LINK_TAG = "LINK_TAG"


class DkimSigningAttributesOrigin(str):
    AWS_SES = "AWS_SES"
    EXTERNAL = "EXTERNAL"


class DkimSigningKeyLength(str):
    RSA_1024_BIT = "RSA_1024_BIT"
    RSA_2048_BIT = "RSA_2048_BIT"


class DkimStatus(str):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TEMPORARY_FAILURE = "TEMPORARY_FAILURE"
    NOT_STARTED = "NOT_STARTED"


class EventType(str):
    SEND = "SEND"
    REJECT = "REJECT"
    BOUNCE = "BOUNCE"
    COMPLAINT = "COMPLAINT"
    DELIVERY = "DELIVERY"
    OPEN = "OPEN"
    CLICK = "CLICK"
    RENDERING_FAILURE = "RENDERING_FAILURE"
    DELIVERY_DELAY = "DELIVERY_DELAY"
    SUBSCRIPTION = "SUBSCRIPTION"


class IdentityType(str):
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    DOMAIN = "DOMAIN"
    MANAGED_DOMAIN = "MANAGED_DOMAIN"


class ImportDestinationType(str):
    SUPPRESSION_LIST = "SUPPRESSION_LIST"
    CONTACT_LIST = "CONTACT_LIST"


class JobStatus(str):
    CREATED = "CREATED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class MailFromDomainStatus(str):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TEMPORARY_FAILURE = "TEMPORARY_FAILURE"


class MailType(str):
    MARKETING = "MARKETING"
    TRANSACTIONAL = "TRANSACTIONAL"


class ReviewStatus(str):
    PENDING = "PENDING"
    FAILED = "FAILED"
    GRANTED = "GRANTED"
    DENIED = "DENIED"


class SubscriptionStatus(str):
    OPT_IN = "OPT_IN"
    OPT_OUT = "OPT_OUT"


class SuppressionListImportAction(str):
    DELETE = "DELETE"
    PUT = "PUT"


class SuppressionListReason(str):
    BOUNCE = "BOUNCE"
    COMPLAINT = "COMPLAINT"


class TlsPolicy(str):
    REQUIRE = "REQUIRE"
    OPTIONAL = "OPTIONAL"


class WarmupStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    DONE = "DONE"


class AccountSuspendedException(ServiceException):
    pass


class AlreadyExistsException(ServiceException):
    pass


class BadRequestException(ServiceException):
    pass


class ConcurrentModificationException(ServiceException):
    pass


class ConflictException(ServiceException):
    pass


class InvalidNextTokenException(ServiceException):
    pass


class LimitExceededException(ServiceException):
    pass


class MailFromDomainNotVerifiedException(ServiceException):
    pass


class MessageRejected(ServiceException):
    pass


class NotFoundException(ServiceException):
    pass


class SendingPausedException(ServiceException):
    pass


class TooManyRequestsException(ServiceException):
    pass


class ReviewDetails(TypedDict, total=False):
    Status: Optional[ReviewStatus]
    CaseId: Optional[CaseId]


AdditionalContactEmailAddresses = List[AdditionalContactEmailAddress]


class AccountDetails(TypedDict, total=False):
    MailType: Optional[MailType]
    WebsiteURL: Optional[WebsiteURL]
    ContactLanguage: Optional[ContactLanguage]
    UseCaseDescription: Optional[UseCaseDescription]
    AdditionalContactEmailAddresses: Optional[AdditionalContactEmailAddresses]
    ReviewDetails: Optional[ReviewDetails]


Timestamp = datetime


class BlacklistEntry(TypedDict, total=False):
    RblName: Optional[RblName]
    ListingTime: Optional[Timestamp]
    Description: Optional[BlacklistingDescription]


BlacklistEntries = List[BlacklistEntry]
BlacklistItemNames = List[BlacklistItemName]
BlacklistReport = Dict[BlacklistItemName, BlacklistEntries]


class Content(TypedDict, total=False):
    Data: MessageData
    Charset: Optional[Charset]


class Body(TypedDict, total=False):
    Text: Optional[Content]
    Html: Optional[Content]


class Template(TypedDict, total=False):
    TemplateName: Optional[EmailTemplateName]
    TemplateArn: Optional[AmazonResourceName]
    TemplateData: Optional[EmailTemplateData]


class BulkEmailContent(TypedDict, total=False):
    Template: Optional[Template]


class ReplacementTemplate(TypedDict, total=False):
    ReplacementTemplateData: Optional[EmailTemplateData]


class ReplacementEmailContent(TypedDict, total=False):
    ReplacementTemplate: Optional[ReplacementTemplate]


class MessageTag(TypedDict, total=False):
    Name: MessageTagName
    Value: MessageTagValue


MessageTagList = List[MessageTag]
EmailAddressList = List[EmailAddress]


class Destination(TypedDict, total=False):
    ToAddresses: Optional[EmailAddressList]
    CcAddresses: Optional[EmailAddressList]
    BccAddresses: Optional[EmailAddressList]


class BulkEmailEntry(TypedDict, total=False):
    Destination: Destination
    ReplacementTags: Optional[MessageTagList]
    ReplacementEmailContent: Optional[ReplacementEmailContent]


BulkEmailEntryList = List[BulkEmailEntry]


class BulkEmailEntryResult(TypedDict, total=False):
    Status: Optional[BulkEmailStatus]
    Error: Optional[ErrorMessage]
    MessageId: Optional[OutboundMessageId]


BulkEmailEntryResultList = List[BulkEmailEntryResult]


class CloudWatchDimensionConfiguration(TypedDict, total=False):
    DimensionName: DimensionName
    DimensionValueSource: DimensionValueSource
    DefaultDimensionValue: DefaultDimensionValue


CloudWatchDimensionConfigurations = List[CloudWatchDimensionConfiguration]


class CloudWatchDestination(TypedDict, total=False):
    DimensionConfigurations: CloudWatchDimensionConfigurations


ConfigurationSetNameList = List[ConfigurationSetName]


class TopicPreference(TypedDict, total=False):
    TopicName: TopicName
    SubscriptionStatus: SubscriptionStatus


TopicPreferenceList = List[TopicPreference]


class Contact(TypedDict, total=False):
    EmailAddress: Optional[EmailAddress]
    TopicPreferences: Optional[TopicPreferenceList]
    TopicDefaultPreferences: Optional[TopicPreferenceList]
    UnsubscribeAll: Optional[UnsubscribeAll]
    LastUpdatedTimestamp: Optional[Timestamp]


class ContactList(TypedDict, total=False):
    ContactListName: Optional[ContactListName]
    LastUpdatedTimestamp: Optional[Timestamp]


class ContactListDestination(TypedDict, total=False):
    ContactListName: ContactListName
    ContactListImportAction: ContactListImportAction


class PinpointDestination(TypedDict, total=False):
    ApplicationArn: Optional[AmazonResourceName]


class SnsDestination(TypedDict, total=False):
    TopicArn: AmazonResourceName


class KinesisFirehoseDestination(TypedDict, total=False):
    IamRoleArn: AmazonResourceName
    DeliveryStreamArn: AmazonResourceName


EventTypes = List[EventType]


class EventDestinationDefinition(TypedDict, total=False):
    Enabled: Optional[Enabled]
    MatchingEventTypes: Optional[EventTypes]
    KinesisFirehoseDestination: Optional[KinesisFirehoseDestination]
    CloudWatchDestination: Optional[CloudWatchDestination]
    SnsDestination: Optional[SnsDestination]
    PinpointDestination: Optional[PinpointDestination]


class CreateConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestinationName: EventDestinationName
    EventDestination: EventDestinationDefinition


class CreateConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass


SuppressionListReasons = List[SuppressionListReason]


class SuppressionOptions(TypedDict, total=False):
    SuppressedReasons: Optional[SuppressionListReasons]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class SendingOptions(TypedDict, total=False):
    SendingEnabled: Optional[Enabled]


LastFreshStart = datetime


class ReputationOptions(TypedDict, total=False):
    ReputationMetricsEnabled: Optional[Enabled]
    LastFreshStart: Optional[LastFreshStart]


class DeliveryOptions(TypedDict, total=False):
    TlsPolicy: Optional[TlsPolicy]
    SendingPoolName: Optional[PoolName]


class TrackingOptions(TypedDict, total=False):
    CustomRedirectDomain: CustomRedirectDomain


class CreateConfigurationSetRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    TrackingOptions: Optional[TrackingOptions]
    DeliveryOptions: Optional[DeliveryOptions]
    ReputationOptions: Optional[ReputationOptions]
    SendingOptions: Optional[SendingOptions]
    Tags: Optional[TagList]
    SuppressionOptions: Optional[SuppressionOptions]


class CreateConfigurationSetResponse(TypedDict, total=False):
    pass


class Topic(TypedDict, total=False):
    TopicName: TopicName
    DisplayName: DisplayName
    Description: Optional[Description]
    DefaultSubscriptionStatus: SubscriptionStatus


Topics = List[Topic]


class CreateContactListRequest(ServiceRequest):
    ContactListName: ContactListName
    Topics: Optional[Topics]
    Description: Optional[Description]
    Tags: Optional[TagList]


class CreateContactListResponse(TypedDict, total=False):
    pass


class CreateContactRequest(ServiceRequest):
    ContactListName: ContactListName
    EmailAddress: EmailAddress
    TopicPreferences: Optional[TopicPreferenceList]
    UnsubscribeAll: Optional[UnsubscribeAll]
    AttributesData: Optional[AttributesData]


class CreateContactResponse(TypedDict, total=False):
    pass


class CreateCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    FromEmailAddress: EmailAddress
    TemplateSubject: EmailTemplateSubject
    TemplateContent: TemplateContent
    SuccessRedirectionURL: SuccessRedirectionURL
    FailureRedirectionURL: FailureRedirectionURL


class CreateCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    pass


class CreateDedicatedIpPoolRequest(ServiceRequest):
    PoolName: PoolName
    Tags: Optional[TagList]


class CreateDedicatedIpPoolResponse(TypedDict, total=False):
    pass


RawMessageData = bytes


class RawMessage(TypedDict, total=False):
    Data: RawMessageData


class Message(TypedDict, total=False):
    Subject: Content
    Body: Body


class EmailContent(TypedDict, total=False):
    Simple: Optional[Message]
    Raw: Optional[RawMessage]
    Template: Optional[Template]


class CreateDeliverabilityTestReportRequest(ServiceRequest):
    ReportName: Optional[ReportName]
    FromEmailAddress: EmailAddress
    Content: EmailContent
    Tags: Optional[TagList]


class CreateDeliverabilityTestReportResponse(TypedDict, total=False):
    ReportId: ReportId
    DeliverabilityTestStatus: DeliverabilityTestStatus


class CreateEmailIdentityPolicyRequest(ServiceRequest):
    EmailIdentity: Identity
    PolicyName: PolicyName
    Policy: Policy


class CreateEmailIdentityPolicyResponse(TypedDict, total=False):
    pass


class DkimSigningAttributes(TypedDict, total=False):
    DomainSigningSelector: Optional[Selector]
    DomainSigningPrivateKey: Optional[PrivateKey]
    NextSigningKeyLength: Optional[DkimSigningKeyLength]


class CreateEmailIdentityRequest(ServiceRequest):
    EmailIdentity: Identity
    Tags: Optional[TagList]
    DkimSigningAttributes: Optional[DkimSigningAttributes]
    ConfigurationSetName: Optional[ConfigurationSetName]


DnsTokenList = List[DnsToken]


class DkimAttributes(TypedDict, total=False):
    SigningEnabled: Optional[Enabled]
    Status: Optional[DkimStatus]
    Tokens: Optional[DnsTokenList]
    SigningAttributesOrigin: Optional[DkimSigningAttributesOrigin]
    NextSigningKeyLength: Optional[DkimSigningKeyLength]
    CurrentSigningKeyLength: Optional[DkimSigningKeyLength]
    LastKeyGenerationTimestamp: Optional[Timestamp]


class CreateEmailIdentityResponse(TypedDict, total=False):
    IdentityType: Optional[IdentityType]
    VerifiedForSendingStatus: Optional[Enabled]
    DkimAttributes: Optional[DkimAttributes]


class EmailTemplateContent(TypedDict, total=False):
    Subject: Optional[EmailTemplateSubject]
    Text: Optional[EmailTemplateText]
    Html: Optional[EmailTemplateHtml]


class CreateEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    TemplateContent: EmailTemplateContent


class CreateEmailTemplateResponse(TypedDict, total=False):
    pass


class ImportDataSource(TypedDict, total=False):
    S3Url: S3Url
    DataFormat: DataFormat


class SuppressionListDestination(TypedDict, total=False):
    SuppressionListImportAction: SuppressionListImportAction


class ImportDestination(TypedDict, total=False):
    SuppressionListDestination: Optional[SuppressionListDestination]
    ContactListDestination: Optional[ContactListDestination]


class CreateImportJobRequest(ServiceRequest):
    ImportDestination: ImportDestination
    ImportDataSource: ImportDataSource


class CreateImportJobResponse(TypedDict, total=False):
    JobId: Optional[JobId]


class CustomVerificationEmailTemplateMetadata(TypedDict, total=False):
    TemplateName: Optional[EmailTemplateName]
    FromEmailAddress: Optional[EmailAddress]
    TemplateSubject: Optional[EmailTemplateSubject]
    SuccessRedirectionURL: Optional[SuccessRedirectionURL]
    FailureRedirectionURL: Optional[FailureRedirectionURL]


CustomVerificationEmailTemplatesList = List[CustomVerificationEmailTemplateMetadata]
Volume = int


class DomainIspPlacement(TypedDict, total=False):
    IspName: Optional[IspName]
    InboxRawCount: Optional[Volume]
    SpamRawCount: Optional[Volume]
    InboxPercentage: Optional[Percentage]
    SpamPercentage: Optional[Percentage]


DomainIspPlacements = List[DomainIspPlacement]


class VolumeStatistics(TypedDict, total=False):
    InboxRawCount: Optional[Volume]
    SpamRawCount: Optional[Volume]
    ProjectedInbox: Optional[Volume]
    ProjectedSpam: Optional[Volume]


class DailyVolume(TypedDict, total=False):
    StartDate: Optional[Timestamp]
    VolumeStatistics: Optional[VolumeStatistics]
    DomainIspPlacements: Optional[DomainIspPlacements]


DailyVolumes = List[DailyVolume]


class DedicatedIp(TypedDict, total=False):
    Ip: Ip
    WarmupStatus: WarmupStatus
    WarmupPercentage: Percentage100Wrapper
    PoolName: Optional[PoolName]


DedicatedIpList = List[DedicatedIp]


class DeleteConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestinationName: EventDestinationName


class DeleteConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass


class DeleteConfigurationSetRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName


class DeleteConfigurationSetResponse(TypedDict, total=False):
    pass


class DeleteContactListRequest(ServiceRequest):
    ContactListName: ContactListName


class DeleteContactListResponse(TypedDict, total=False):
    pass


class DeleteContactRequest(ServiceRequest):
    ContactListName: ContactListName
    EmailAddress: EmailAddress


class DeleteContactResponse(TypedDict, total=False):
    pass


class DeleteCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName


class DeleteCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    pass


class DeleteDedicatedIpPoolRequest(ServiceRequest):
    PoolName: PoolName


class DeleteDedicatedIpPoolResponse(TypedDict, total=False):
    pass


class DeleteEmailIdentityPolicyRequest(ServiceRequest):
    EmailIdentity: Identity
    PolicyName: PolicyName


class DeleteEmailIdentityPolicyResponse(TypedDict, total=False):
    pass


class DeleteEmailIdentityRequest(ServiceRequest):
    EmailIdentity: Identity


class DeleteEmailIdentityResponse(TypedDict, total=False):
    pass


class DeleteEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName


class DeleteEmailTemplateResponse(TypedDict, total=False):
    pass


class DeleteSuppressedDestinationRequest(ServiceRequest):
    EmailAddress: EmailAddress


class DeleteSuppressedDestinationResponse(TypedDict, total=False):
    pass


class DeliverabilityTestReport(TypedDict, total=False):
    ReportId: Optional[ReportId]
    ReportName: Optional[ReportName]
    Subject: Optional[DeliverabilityTestSubject]
    FromEmailAddress: Optional[EmailAddress]
    CreateDate: Optional[Timestamp]
    DeliverabilityTestStatus: Optional[DeliverabilityTestStatus]


DeliverabilityTestReports = List[DeliverabilityTestReport]
Esps = List[Esp]
IpList = List[Ip]


class DomainDeliverabilityCampaign(TypedDict, total=False):
    CampaignId: Optional[CampaignId]
    ImageUrl: Optional[ImageUrl]
    Subject: Optional[Subject]
    FromAddress: Optional[Identity]
    SendingIps: Optional[IpList]
    FirstSeenDateTime: Optional[Timestamp]
    LastSeenDateTime: Optional[Timestamp]
    InboxCount: Optional[Volume]
    SpamCount: Optional[Volume]
    ReadRate: Optional[Percentage]
    DeleteRate: Optional[Percentage]
    ReadDeleteRate: Optional[Percentage]
    ProjectedVolume: Optional[Volume]
    Esps: Optional[Esps]


DomainDeliverabilityCampaignList = List[DomainDeliverabilityCampaign]
IspNameList = List[IspName]


class InboxPlacementTrackingOption(TypedDict, total=False):
    Global: Optional[Enabled]
    TrackedIsps: Optional[IspNameList]


class DomainDeliverabilityTrackingOption(TypedDict, total=False):
    Domain: Optional[Domain]
    SubscriptionStartDate: Optional[Timestamp]
    InboxPlacementTrackingOption: Optional[InboxPlacementTrackingOption]


DomainDeliverabilityTrackingOptions = List[DomainDeliverabilityTrackingOption]


class EmailTemplateMetadata(TypedDict, total=False):
    TemplateName: Optional[EmailTemplateName]
    CreatedTimestamp: Optional[Timestamp]


EmailTemplateMetadataList = List[EmailTemplateMetadata]


class EventDestination(TypedDict, total=False):
    Name: EventDestinationName
    Enabled: Optional[Enabled]
    MatchingEventTypes: EventTypes
    KinesisFirehoseDestination: Optional[KinesisFirehoseDestination]
    CloudWatchDestination: Optional[CloudWatchDestination]
    SnsDestination: Optional[SnsDestination]
    PinpointDestination: Optional[PinpointDestination]


EventDestinations = List[EventDestination]


class FailureInfo(TypedDict, total=False):
    FailedRecordsS3Url: Optional[FailedRecordsS3Url]
    ErrorMessage: Optional[ErrorMessage]


class GetAccountRequest(ServiceRequest):
    pass


class SuppressionAttributes(TypedDict, total=False):
    SuppressedReasons: Optional[SuppressionListReasons]


class SendQuota(TypedDict, total=False):
    Max24HourSend: Optional[Max24HourSend]
    MaxSendRate: Optional[MaxSendRate]
    SentLast24Hours: Optional[SentLast24Hours]


class GetAccountResponse(TypedDict, total=False):
    DedicatedIpAutoWarmupEnabled: Optional[Enabled]
    EnforcementStatus: Optional[GeneralEnforcementStatus]
    ProductionAccessEnabled: Optional[Enabled]
    SendQuota: Optional[SendQuota]
    SendingEnabled: Optional[Enabled]
    SuppressionAttributes: Optional[SuppressionAttributes]
    Details: Optional[AccountDetails]


class GetBlacklistReportsRequest(ServiceRequest):
    BlacklistItemNames: BlacklistItemNames


class GetBlacklistReportsResponse(TypedDict, total=False):
    BlacklistReport: BlacklistReport


class GetConfigurationSetEventDestinationsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName


class GetConfigurationSetEventDestinationsResponse(TypedDict, total=False):
    EventDestinations: Optional[EventDestinations]


class GetConfigurationSetRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName


class GetConfigurationSetResponse(TypedDict, total=False):
    ConfigurationSetName: Optional[ConfigurationSetName]
    TrackingOptions: Optional[TrackingOptions]
    DeliveryOptions: Optional[DeliveryOptions]
    ReputationOptions: Optional[ReputationOptions]
    SendingOptions: Optional[SendingOptions]
    Tags: Optional[TagList]
    SuppressionOptions: Optional[SuppressionOptions]


class GetContactListRequest(ServiceRequest):
    ContactListName: ContactListName


class GetContactListResponse(TypedDict, total=False):
    ContactListName: Optional[ContactListName]
    Topics: Optional[Topics]
    Description: Optional[Description]
    CreatedTimestamp: Optional[Timestamp]
    LastUpdatedTimestamp: Optional[Timestamp]
    Tags: Optional[TagList]


class GetContactRequest(ServiceRequest):
    ContactListName: ContactListName
    EmailAddress: EmailAddress


class GetContactResponse(TypedDict, total=False):
    ContactListName: Optional[ContactListName]
    EmailAddress: Optional[EmailAddress]
    TopicPreferences: Optional[TopicPreferenceList]
    TopicDefaultPreferences: Optional[TopicPreferenceList]
    UnsubscribeAll: Optional[UnsubscribeAll]
    AttributesData: Optional[AttributesData]
    CreatedTimestamp: Optional[Timestamp]
    LastUpdatedTimestamp: Optional[Timestamp]


class GetCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName


class GetCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    TemplateName: Optional[EmailTemplateName]
    FromEmailAddress: Optional[EmailAddress]
    TemplateSubject: Optional[EmailTemplateSubject]
    TemplateContent: Optional[TemplateContent]
    SuccessRedirectionURL: Optional[SuccessRedirectionURL]
    FailureRedirectionURL: Optional[FailureRedirectionURL]


class GetDedicatedIpRequest(ServiceRequest):
    Ip: Ip


class GetDedicatedIpResponse(TypedDict, total=False):
    DedicatedIp: Optional[DedicatedIp]


class GetDedicatedIpsRequest(ServiceRequest):
    PoolName: Optional[PoolName]
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class GetDedicatedIpsResponse(TypedDict, total=False):
    DedicatedIps: Optional[DedicatedIpList]
    NextToken: Optional[NextToken]


class GetDeliverabilityDashboardOptionsRequest(ServiceRequest):
    pass


class GetDeliverabilityDashboardOptionsResponse(TypedDict, total=False):
    DashboardEnabled: Enabled
    SubscriptionExpiryDate: Optional[Timestamp]
    AccountStatus: Optional[DeliverabilityDashboardAccountStatus]
    ActiveSubscribedDomains: Optional[DomainDeliverabilityTrackingOptions]
    PendingExpirationSubscribedDomains: Optional[DomainDeliverabilityTrackingOptions]


class GetDeliverabilityTestReportRequest(ServiceRequest):
    ReportId: ReportId


class PlacementStatistics(TypedDict, total=False):
    InboxPercentage: Optional[Percentage]
    SpamPercentage: Optional[Percentage]
    MissingPercentage: Optional[Percentage]
    SpfPercentage: Optional[Percentage]
    DkimPercentage: Optional[Percentage]


class IspPlacement(TypedDict, total=False):
    IspName: Optional[IspName]
    PlacementStatistics: Optional[PlacementStatistics]


IspPlacements = List[IspPlacement]


class GetDeliverabilityTestReportResponse(TypedDict, total=False):
    DeliverabilityTestReport: DeliverabilityTestReport
    OverallPlacement: PlacementStatistics
    IspPlacements: IspPlacements
    Message: Optional[MessageContent]
    Tags: Optional[TagList]


class GetDomainDeliverabilityCampaignRequest(ServiceRequest):
    CampaignId: CampaignId


class GetDomainDeliverabilityCampaignResponse(TypedDict, total=False):
    DomainDeliverabilityCampaign: DomainDeliverabilityCampaign


class GetDomainStatisticsReportRequest(ServiceRequest):
    Domain: Identity
    StartDate: Timestamp
    EndDate: Timestamp


class OverallVolume(TypedDict, total=False):
    VolumeStatistics: Optional[VolumeStatistics]
    ReadRatePercent: Optional[Percentage]
    DomainIspPlacements: Optional[DomainIspPlacements]


class GetDomainStatisticsReportResponse(TypedDict, total=False):
    OverallVolume: OverallVolume
    DailyVolumes: DailyVolumes


class GetEmailIdentityPoliciesRequest(ServiceRequest):
    EmailIdentity: Identity


PolicyMap = Dict[PolicyName, Policy]


class GetEmailIdentityPoliciesResponse(TypedDict, total=False):
    Policies: Optional[PolicyMap]


class GetEmailIdentityRequest(ServiceRequest):
    EmailIdentity: Identity


class MailFromAttributes(TypedDict, total=False):
    MailFromDomain: MailFromDomainName
    MailFromDomainStatus: MailFromDomainStatus
    BehaviorOnMxFailure: BehaviorOnMxFailure


class GetEmailIdentityResponse(TypedDict, total=False):
    IdentityType: Optional[IdentityType]
    FeedbackForwardingStatus: Optional[Enabled]
    VerifiedForSendingStatus: Optional[Enabled]
    DkimAttributes: Optional[DkimAttributes]
    MailFromAttributes: Optional[MailFromAttributes]
    Policies: Optional[PolicyMap]
    Tags: Optional[TagList]
    ConfigurationSetName: Optional[ConfigurationSetName]


class GetEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName


class GetEmailTemplateResponse(TypedDict, total=False):
    TemplateName: EmailTemplateName
    TemplateContent: EmailTemplateContent


class GetImportJobRequest(ServiceRequest):
    JobId: JobId


class GetImportJobResponse(TypedDict, total=False):
    JobId: Optional[JobId]
    ImportDestination: Optional[ImportDestination]
    ImportDataSource: Optional[ImportDataSource]
    FailureInfo: Optional[FailureInfo]
    JobStatus: Optional[JobStatus]
    CreatedTimestamp: Optional[Timestamp]
    CompletedTimestamp: Optional[Timestamp]
    ProcessedRecordsCount: Optional[ProcessedRecordsCount]
    FailedRecordsCount: Optional[FailedRecordsCount]


class GetSuppressedDestinationRequest(ServiceRequest):
    EmailAddress: EmailAddress


class SuppressedDestinationAttributes(TypedDict, total=False):
    MessageId: Optional[OutboundMessageId]
    FeedbackId: Optional[FeedbackId]


class SuppressedDestination(TypedDict, total=False):
    EmailAddress: EmailAddress
    Reason: SuppressionListReason
    LastUpdateTime: Timestamp
    Attributes: Optional[SuppressedDestinationAttributes]


class GetSuppressedDestinationResponse(TypedDict, total=False):
    SuppressedDestination: SuppressedDestination


class IdentityInfo(TypedDict, total=False):
    IdentityType: Optional[IdentityType]
    IdentityName: Optional[Identity]
    SendingEnabled: Optional[Enabled]


IdentityInfoList = List[IdentityInfo]


class ImportJobSummary(TypedDict, total=False):
    JobId: Optional[JobId]
    ImportDestination: Optional[ImportDestination]
    JobStatus: Optional[JobStatus]
    CreatedTimestamp: Optional[Timestamp]


ImportJobSummaryList = List[ImportJobSummary]


class ListConfigurationSetsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class ListConfigurationSetsResponse(TypedDict, total=False):
    ConfigurationSets: Optional[ConfigurationSetNameList]
    NextToken: Optional[NextToken]


class ListContactListsRequest(ServiceRequest):
    PageSize: Optional[MaxItems]
    NextToken: Optional[NextToken]


ListOfContactLists = List[ContactList]


class ListContactListsResponse(TypedDict, total=False):
    ContactLists: Optional[ListOfContactLists]
    NextToken: Optional[NextToken]


class TopicFilter(TypedDict, total=False):
    TopicName: Optional[TopicName]
    UseDefaultIfPreferenceUnavailable: Optional[UseDefaultIfPreferenceUnavailable]


class ListContactsFilter(TypedDict, total=False):
    FilteredStatus: Optional[SubscriptionStatus]
    TopicFilter: Optional[TopicFilter]


class ListContactsRequest(ServiceRequest):
    ContactListName: ContactListName
    Filter: Optional[ListContactsFilter]
    PageSize: Optional[MaxItems]
    NextToken: Optional[NextToken]


ListOfContacts = List[Contact]


class ListContactsResponse(TypedDict, total=False):
    Contacts: Optional[ListOfContacts]
    NextToken: Optional[NextToken]


class ListCustomVerificationEmailTemplatesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class ListCustomVerificationEmailTemplatesResponse(TypedDict, total=False):
    CustomVerificationEmailTemplates: Optional[CustomVerificationEmailTemplatesList]
    NextToken: Optional[NextToken]


class ListDedicatedIpPoolsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


ListOfDedicatedIpPools = List[PoolName]


class ListDedicatedIpPoolsResponse(TypedDict, total=False):
    DedicatedIpPools: Optional[ListOfDedicatedIpPools]
    NextToken: Optional[NextToken]


class ListDeliverabilityTestReportsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class ListDeliverabilityTestReportsResponse(TypedDict, total=False):
    DeliverabilityTestReports: DeliverabilityTestReports
    NextToken: Optional[NextToken]


class ListDomainDeliverabilityCampaignsRequest(ServiceRequest):
    StartDate: Timestamp
    EndDate: Timestamp
    SubscribedDomain: Domain
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class ListDomainDeliverabilityCampaignsResponse(TypedDict, total=False):
    DomainDeliverabilityCampaigns: DomainDeliverabilityCampaignList
    NextToken: Optional[NextToken]


class ListEmailIdentitiesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class ListEmailIdentitiesResponse(TypedDict, total=False):
    EmailIdentities: Optional[IdentityInfoList]
    NextToken: Optional[NextToken]


class ListEmailTemplatesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class ListEmailTemplatesResponse(TypedDict, total=False):
    TemplatesMetadata: Optional[EmailTemplateMetadataList]
    NextToken: Optional[NextToken]


class ListImportJobsRequest(ServiceRequest):
    ImportDestinationType: Optional[ImportDestinationType]
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class ListImportJobsResponse(TypedDict, total=False):
    ImportJobs: Optional[ImportJobSummaryList]
    NextToken: Optional[NextToken]


class ListManagementOptions(TypedDict, total=False):
    ContactListName: ContactListName
    TopicName: Optional[TopicName]


class ListSuppressedDestinationsRequest(ServiceRequest):
    Reasons: Optional[SuppressionListReasons]
    StartDate: Optional[Timestamp]
    EndDate: Optional[Timestamp]
    NextToken: Optional[NextToken]
    PageSize: Optional[MaxItems]


class SuppressedDestinationSummary(TypedDict, total=False):
    EmailAddress: EmailAddress
    Reason: SuppressionListReason
    LastUpdateTime: Timestamp


SuppressedDestinationSummaries = List[SuppressedDestinationSummary]


class ListSuppressedDestinationsResponse(TypedDict, total=False):
    SuppressedDestinationSummaries: Optional[SuppressedDestinationSummaries]
    NextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: TagList


class PutAccountDedicatedIpWarmupAttributesRequest(ServiceRequest):
    AutoWarmupEnabled: Optional[Enabled]


class PutAccountDedicatedIpWarmupAttributesResponse(TypedDict, total=False):
    pass


class PutAccountDetailsRequest(ServiceRequest):
    MailType: MailType
    WebsiteURL: WebsiteURL
    ContactLanguage: Optional[ContactLanguage]
    UseCaseDescription: UseCaseDescription
    AdditionalContactEmailAddresses: Optional[AdditionalContactEmailAddresses]
    ProductionAccessEnabled: Optional[EnabledWrapper]


class PutAccountDetailsResponse(TypedDict, total=False):
    pass


class PutAccountSendingAttributesRequest(ServiceRequest):
    SendingEnabled: Optional[Enabled]


class PutAccountSendingAttributesResponse(TypedDict, total=False):
    pass


class PutAccountSuppressionAttributesRequest(ServiceRequest):
    SuppressedReasons: Optional[SuppressionListReasons]


class PutAccountSuppressionAttributesResponse(TypedDict, total=False):
    pass


class PutConfigurationSetDeliveryOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    TlsPolicy: Optional[TlsPolicy]
    SendingPoolName: Optional[SendingPoolName]


class PutConfigurationSetDeliveryOptionsResponse(TypedDict, total=False):
    pass


class PutConfigurationSetReputationOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    ReputationMetricsEnabled: Optional[Enabled]


class PutConfigurationSetReputationOptionsResponse(TypedDict, total=False):
    pass


class PutConfigurationSetSendingOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    SendingEnabled: Optional[Enabled]


class PutConfigurationSetSendingOptionsResponse(TypedDict, total=False):
    pass


class PutConfigurationSetSuppressionOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    SuppressedReasons: Optional[SuppressionListReasons]


class PutConfigurationSetSuppressionOptionsResponse(TypedDict, total=False):
    pass


class PutConfigurationSetTrackingOptionsRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    CustomRedirectDomain: Optional[CustomRedirectDomain]


class PutConfigurationSetTrackingOptionsResponse(TypedDict, total=False):
    pass


class PutDedicatedIpInPoolRequest(ServiceRequest):
    Ip: Ip
    DestinationPoolName: PoolName


class PutDedicatedIpInPoolResponse(TypedDict, total=False):
    pass


class PutDedicatedIpWarmupAttributesRequest(ServiceRequest):
    Ip: Ip
    WarmupPercentage: Percentage100Wrapper


class PutDedicatedIpWarmupAttributesResponse(TypedDict, total=False):
    pass


class PutDeliverabilityDashboardOptionRequest(ServiceRequest):
    DashboardEnabled: Enabled
    SubscribedDomains: Optional[DomainDeliverabilityTrackingOptions]


class PutDeliverabilityDashboardOptionResponse(TypedDict, total=False):
    pass


class PutEmailIdentityConfigurationSetAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    ConfigurationSetName: Optional[ConfigurationSetName]


class PutEmailIdentityConfigurationSetAttributesResponse(TypedDict, total=False):
    pass


class PutEmailIdentityDkimAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    SigningEnabled: Optional[Enabled]


class PutEmailIdentityDkimAttributesResponse(TypedDict, total=False):
    pass


class PutEmailIdentityDkimSigningAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    SigningAttributesOrigin: DkimSigningAttributesOrigin
    SigningAttributes: Optional[DkimSigningAttributes]


class PutEmailIdentityDkimSigningAttributesResponse(TypedDict, total=False):
    DkimStatus: Optional[DkimStatus]
    DkimTokens: Optional[DnsTokenList]


class PutEmailIdentityFeedbackAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    EmailForwardingEnabled: Optional[Enabled]


class PutEmailIdentityFeedbackAttributesResponse(TypedDict, total=False):
    pass


class PutEmailIdentityMailFromAttributesRequest(ServiceRequest):
    EmailIdentity: Identity
    MailFromDomain: Optional[MailFromDomainName]
    BehaviorOnMxFailure: Optional[BehaviorOnMxFailure]


class PutEmailIdentityMailFromAttributesResponse(TypedDict, total=False):
    pass


class PutSuppressedDestinationRequest(ServiceRequest):
    EmailAddress: EmailAddress
    Reason: SuppressionListReason


class PutSuppressedDestinationResponse(TypedDict, total=False):
    pass


class SendBulkEmailRequest(ServiceRequest):
    FromEmailAddress: Optional[EmailAddress]
    FromEmailAddressIdentityArn: Optional[AmazonResourceName]
    ReplyToAddresses: Optional[EmailAddressList]
    FeedbackForwardingEmailAddress: Optional[EmailAddress]
    FeedbackForwardingEmailAddressIdentityArn: Optional[AmazonResourceName]
    DefaultEmailTags: Optional[MessageTagList]
    DefaultContent: BulkEmailContent
    BulkEmailEntries: BulkEmailEntryList
    ConfigurationSetName: Optional[ConfigurationSetName]


class SendBulkEmailResponse(TypedDict, total=False):
    BulkEmailEntryResults: BulkEmailEntryResultList


class SendCustomVerificationEmailRequest(ServiceRequest):
    EmailAddress: EmailAddress
    TemplateName: EmailTemplateName
    ConfigurationSetName: Optional[ConfigurationSetName]


class SendCustomVerificationEmailResponse(TypedDict, total=False):
    MessageId: Optional[OutboundMessageId]


class SendEmailRequest(ServiceRequest):
    FromEmailAddress: Optional[EmailAddress]
    FromEmailAddressIdentityArn: Optional[AmazonResourceName]
    Destination: Optional[Destination]
    ReplyToAddresses: Optional[EmailAddressList]
    FeedbackForwardingEmailAddress: Optional[EmailAddress]
    FeedbackForwardingEmailAddressIdentityArn: Optional[AmazonResourceName]
    Content: EmailContent
    EmailTags: Optional[MessageTagList]
    ConfigurationSetName: Optional[ConfigurationSetName]
    ListManagementOptions: Optional[ListManagementOptions]


class SendEmailResponse(TypedDict, total=False):
    MessageId: Optional[OutboundMessageId]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class TestRenderEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    TemplateData: EmailTemplateData


class TestRenderEmailTemplateResponse(TypedDict, total=False):
    RenderedTemplate: RenderedEmailTemplate


class UntagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateConfigurationSetEventDestinationRequest(ServiceRequest):
    ConfigurationSetName: ConfigurationSetName
    EventDestinationName: EventDestinationName
    EventDestination: EventDestinationDefinition


class UpdateConfigurationSetEventDestinationResponse(TypedDict, total=False):
    pass


class UpdateContactListRequest(ServiceRequest):
    ContactListName: ContactListName
    Topics: Optional[Topics]
    Description: Optional[Description]


class UpdateContactListResponse(TypedDict, total=False):
    pass


class UpdateContactRequest(ServiceRequest):
    ContactListName: ContactListName
    EmailAddress: EmailAddress
    TopicPreferences: Optional[TopicPreferenceList]
    UnsubscribeAll: Optional[UnsubscribeAll]
    AttributesData: Optional[AttributesData]


class UpdateContactResponse(TypedDict, total=False):
    pass


class UpdateCustomVerificationEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    FromEmailAddress: EmailAddress
    TemplateSubject: EmailTemplateSubject
    TemplateContent: TemplateContent
    SuccessRedirectionURL: SuccessRedirectionURL
    FailureRedirectionURL: FailureRedirectionURL


class UpdateCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    pass


class UpdateEmailIdentityPolicyRequest(ServiceRequest):
    EmailIdentity: Identity
    PolicyName: PolicyName
    Policy: Policy


class UpdateEmailIdentityPolicyResponse(TypedDict, total=False):
    pass


class UpdateEmailTemplateRequest(ServiceRequest):
    TemplateName: EmailTemplateName
    TemplateContent: EmailTemplateContent


class UpdateEmailTemplateResponse(TypedDict, total=False):
    pass


class Sesv2Api:

    service = "sesv2"
    version = "2019-09-27"

    @handler("CreateConfigurationSet")
    def create_configuration_set(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        tracking_options: TrackingOptions = None,
        delivery_options: DeliveryOptions = None,
        reputation_options: ReputationOptions = None,
        sending_options: SendingOptions = None,
        tags: TagList = None,
        suppression_options: SuppressionOptions = None,
    ) -> CreateConfigurationSetResponse:
        raise NotImplementedError

    @handler("CreateConfigurationSetEventDestination")
    def create_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination_name: EventDestinationName,
        event_destination: EventDestinationDefinition,
    ) -> CreateConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("CreateContact")
    def create_contact(
        self,
        context: RequestContext,
        contact_list_name: ContactListName,
        email_address: EmailAddress,
        topic_preferences: TopicPreferenceList = None,
        unsubscribe_all: UnsubscribeAll = None,
        attributes_data: AttributesData = None,
    ) -> CreateContactResponse:
        raise NotImplementedError

    @handler("CreateContactList")
    def create_contact_list(
        self,
        context: RequestContext,
        contact_list_name: ContactListName,
        topics: Topics = None,
        description: Description = None,
        tags: TagList = None,
    ) -> CreateContactListResponse:
        raise NotImplementedError

    @handler("CreateCustomVerificationEmailTemplate")
    def create_custom_verification_email_template(
        self,
        context: RequestContext,
        template_name: EmailTemplateName,
        from_email_address: EmailAddress,
        template_subject: EmailTemplateSubject,
        template_content: TemplateContent,
        success_redirection_url: SuccessRedirectionURL,
        failure_redirection_url: FailureRedirectionURL,
    ) -> CreateCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("CreateDedicatedIpPool")
    def create_dedicated_ip_pool(
        self, context: RequestContext, pool_name: PoolName, tags: TagList = None
    ) -> CreateDedicatedIpPoolResponse:
        raise NotImplementedError

    @handler("CreateDeliverabilityTestReport")
    def create_deliverability_test_report(
        self,
        context: RequestContext,
        from_email_address: EmailAddress,
        content: EmailContent,
        report_name: ReportName = None,
        tags: TagList = None,
    ) -> CreateDeliverabilityTestReportResponse:
        raise NotImplementedError

    @handler("CreateEmailIdentity")
    def create_email_identity(
        self,
        context: RequestContext,
        email_identity: Identity,
        tags: TagList = None,
        dkim_signing_attributes: DkimSigningAttributes = None,
        configuration_set_name: ConfigurationSetName = None,
    ) -> CreateEmailIdentityResponse:
        raise NotImplementedError

    @handler("CreateEmailIdentityPolicy")
    def create_email_identity_policy(
        self,
        context: RequestContext,
        email_identity: Identity,
        policy_name: PolicyName,
        policy: Policy,
    ) -> CreateEmailIdentityPolicyResponse:
        raise NotImplementedError

    @handler("CreateEmailTemplate")
    def create_email_template(
        self,
        context: RequestContext,
        template_name: EmailTemplateName,
        template_content: EmailTemplateContent,
    ) -> CreateEmailTemplateResponse:
        raise NotImplementedError

    @handler("CreateImportJob")
    def create_import_job(
        self,
        context: RequestContext,
        import_destination: ImportDestination,
        import_data_source: ImportDataSource,
    ) -> CreateImportJobResponse:
        raise NotImplementedError

    @handler("DeleteConfigurationSet")
    def delete_configuration_set(
        self, context: RequestContext, configuration_set_name: ConfigurationSetName
    ) -> DeleteConfigurationSetResponse:
        raise NotImplementedError

    @handler("DeleteConfigurationSetEventDestination")
    def delete_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination_name: EventDestinationName,
    ) -> DeleteConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("DeleteContact")
    def delete_contact(
        self,
        context: RequestContext,
        contact_list_name: ContactListName,
        email_address: EmailAddress,
    ) -> DeleteContactResponse:
        raise NotImplementedError

    @handler("DeleteContactList")
    def delete_contact_list(
        self, context: RequestContext, contact_list_name: ContactListName
    ) -> DeleteContactListResponse:
        raise NotImplementedError

    @handler("DeleteCustomVerificationEmailTemplate")
    def delete_custom_verification_email_template(
        self, context: RequestContext, template_name: EmailTemplateName
    ) -> DeleteCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("DeleteDedicatedIpPool")
    def delete_dedicated_ip_pool(
        self, context: RequestContext, pool_name: PoolName
    ) -> DeleteDedicatedIpPoolResponse:
        raise NotImplementedError

    @handler("DeleteEmailIdentity")
    def delete_email_identity(
        self, context: RequestContext, email_identity: Identity
    ) -> DeleteEmailIdentityResponse:
        raise NotImplementedError

    @handler("DeleteEmailIdentityPolicy")
    def delete_email_identity_policy(
        self, context: RequestContext, email_identity: Identity, policy_name: PolicyName
    ) -> DeleteEmailIdentityPolicyResponse:
        raise NotImplementedError

    @handler("DeleteEmailTemplate")
    def delete_email_template(
        self, context: RequestContext, template_name: EmailTemplateName
    ) -> DeleteEmailTemplateResponse:
        raise NotImplementedError

    @handler("DeleteSuppressedDestination")
    def delete_suppressed_destination(
        self, context: RequestContext, email_address: EmailAddress
    ) -> DeleteSuppressedDestinationResponse:
        raise NotImplementedError

    @handler("GetAccount")
    def get_account(
        self,
        context: RequestContext,
    ) -> GetAccountResponse:
        raise NotImplementedError

    @handler("GetBlacklistReports")
    def get_blacklist_reports(
        self, context: RequestContext, blacklist_item_names: BlacklistItemNames
    ) -> GetBlacklistReportsResponse:
        raise NotImplementedError

    @handler("GetConfigurationSet")
    def get_configuration_set(
        self, context: RequestContext, configuration_set_name: ConfigurationSetName
    ) -> GetConfigurationSetResponse:
        raise NotImplementedError

    @handler("GetConfigurationSetEventDestinations")
    def get_configuration_set_event_destinations(
        self, context: RequestContext, configuration_set_name: ConfigurationSetName
    ) -> GetConfigurationSetEventDestinationsResponse:
        raise NotImplementedError

    @handler("GetContact")
    def get_contact(
        self,
        context: RequestContext,
        contact_list_name: ContactListName,
        email_address: EmailAddress,
    ) -> GetContactResponse:
        raise NotImplementedError

    @handler("GetContactList")
    def get_contact_list(
        self, context: RequestContext, contact_list_name: ContactListName
    ) -> GetContactListResponse:
        raise NotImplementedError

    @handler("GetCustomVerificationEmailTemplate")
    def get_custom_verification_email_template(
        self, context: RequestContext, template_name: EmailTemplateName
    ) -> GetCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("GetDedicatedIp")
    def get_dedicated_ip(self, context: RequestContext, ip: Ip) -> GetDedicatedIpResponse:
        raise NotImplementedError

    @handler("GetDedicatedIps")
    def get_dedicated_ips(
        self,
        context: RequestContext,
        pool_name: PoolName = None,
        next_token: NextToken = None,
        page_size: MaxItems = None,
    ) -> GetDedicatedIpsResponse:
        raise NotImplementedError

    @handler("GetDeliverabilityDashboardOptions")
    def get_deliverability_dashboard_options(
        self,
        context: RequestContext,
    ) -> GetDeliverabilityDashboardOptionsResponse:
        raise NotImplementedError

    @handler("GetDeliverabilityTestReport")
    def get_deliverability_test_report(
        self, context: RequestContext, report_id: ReportId
    ) -> GetDeliverabilityTestReportResponse:
        raise NotImplementedError

    @handler("GetDomainDeliverabilityCampaign")
    def get_domain_deliverability_campaign(
        self, context: RequestContext, campaign_id: CampaignId
    ) -> GetDomainDeliverabilityCampaignResponse:
        raise NotImplementedError

    @handler("GetDomainStatisticsReport")
    def get_domain_statistics_report(
        self, context: RequestContext, domain: Identity, start_date: Timestamp, end_date: Timestamp
    ) -> GetDomainStatisticsReportResponse:
        raise NotImplementedError

    @handler("GetEmailIdentity")
    def get_email_identity(
        self, context: RequestContext, email_identity: Identity
    ) -> GetEmailIdentityResponse:
        raise NotImplementedError

    @handler("GetEmailIdentityPolicies")
    def get_email_identity_policies(
        self, context: RequestContext, email_identity: Identity
    ) -> GetEmailIdentityPoliciesResponse:
        raise NotImplementedError

    @handler("GetEmailTemplate")
    def get_email_template(
        self, context: RequestContext, template_name: EmailTemplateName
    ) -> GetEmailTemplateResponse:
        raise NotImplementedError

    @handler("GetImportJob")
    def get_import_job(self, context: RequestContext, job_id: JobId) -> GetImportJobResponse:
        raise NotImplementedError

    @handler("GetSuppressedDestination")
    def get_suppressed_destination(
        self, context: RequestContext, email_address: EmailAddress
    ) -> GetSuppressedDestinationResponse:
        raise NotImplementedError

    @handler("ListConfigurationSets")
    def list_configuration_sets(
        self, context: RequestContext, next_token: NextToken = None, page_size: MaxItems = None
    ) -> ListConfigurationSetsResponse:
        raise NotImplementedError

    @handler("ListContactLists")
    def list_contact_lists(
        self, context: RequestContext, page_size: MaxItems = None, next_token: NextToken = None
    ) -> ListContactListsResponse:
        raise NotImplementedError

    @handler("ListContacts")
    def list_contacts(
        self,
        context: RequestContext,
        contact_list_name: ContactListName,
        filter: ListContactsFilter = None,
        page_size: MaxItems = None,
        next_token: NextToken = None,
    ) -> ListContactsResponse:
        raise NotImplementedError

    @handler("ListCustomVerificationEmailTemplates")
    def list_custom_verification_email_templates(
        self, context: RequestContext, next_token: NextToken = None, page_size: MaxItems = None
    ) -> ListCustomVerificationEmailTemplatesResponse:
        raise NotImplementedError

    @handler("ListDedicatedIpPools")
    def list_dedicated_ip_pools(
        self, context: RequestContext, next_token: NextToken = None, page_size: MaxItems = None
    ) -> ListDedicatedIpPoolsResponse:
        raise NotImplementedError

    @handler("ListDeliverabilityTestReports")
    def list_deliverability_test_reports(
        self, context: RequestContext, next_token: NextToken = None, page_size: MaxItems = None
    ) -> ListDeliverabilityTestReportsResponse:
        raise NotImplementedError

    @handler("ListDomainDeliverabilityCampaigns")
    def list_domain_deliverability_campaigns(
        self,
        context: RequestContext,
        start_date: Timestamp,
        end_date: Timestamp,
        subscribed_domain: Domain,
        next_token: NextToken = None,
        page_size: MaxItems = None,
    ) -> ListDomainDeliverabilityCampaignsResponse:
        raise NotImplementedError

    @handler("ListEmailIdentities")
    def list_email_identities(
        self, context: RequestContext, next_token: NextToken = None, page_size: MaxItems = None
    ) -> ListEmailIdentitiesResponse:
        raise NotImplementedError

    @handler("ListEmailTemplates")
    def list_email_templates(
        self, context: RequestContext, next_token: NextToken = None, page_size: MaxItems = None
    ) -> ListEmailTemplatesResponse:
        raise NotImplementedError

    @handler("ListImportJobs")
    def list_import_jobs(
        self,
        context: RequestContext,
        import_destination_type: ImportDestinationType = None,
        next_token: NextToken = None,
        page_size: MaxItems = None,
    ) -> ListImportJobsResponse:
        raise NotImplementedError

    @handler("ListSuppressedDestinations")
    def list_suppressed_destinations(
        self,
        context: RequestContext,
        reasons: SuppressionListReasons = None,
        start_date: Timestamp = None,
        end_date: Timestamp = None,
        next_token: NextToken = None,
        page_size: MaxItems = None,
    ) -> ListSuppressedDestinationsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutAccountDedicatedIpWarmupAttributes")
    def put_account_dedicated_ip_warmup_attributes(
        self, context: RequestContext, auto_warmup_enabled: Enabled = None
    ) -> PutAccountDedicatedIpWarmupAttributesResponse:
        raise NotImplementedError

    @handler("PutAccountDetails")
    def put_account_details(
        self,
        context: RequestContext,
        mail_type: MailType,
        website_url: WebsiteURL,
        use_case_description: UseCaseDescription,
        contact_language: ContactLanguage = None,
        additional_contact_email_addresses: AdditionalContactEmailAddresses = None,
        production_access_enabled: EnabledWrapper = None,
    ) -> PutAccountDetailsResponse:
        raise NotImplementedError

    @handler("PutAccountSendingAttributes")
    def put_account_sending_attributes(
        self, context: RequestContext, sending_enabled: Enabled = None
    ) -> PutAccountSendingAttributesResponse:
        raise NotImplementedError

    @handler("PutAccountSuppressionAttributes")
    def put_account_suppression_attributes(
        self, context: RequestContext, suppressed_reasons: SuppressionListReasons = None
    ) -> PutAccountSuppressionAttributesResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetDeliveryOptions")
    def put_configuration_set_delivery_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        tls_policy: TlsPolicy = None,
        sending_pool_name: SendingPoolName = None,
    ) -> PutConfigurationSetDeliveryOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetReputationOptions")
    def put_configuration_set_reputation_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        reputation_metrics_enabled: Enabled = None,
    ) -> PutConfigurationSetReputationOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetSendingOptions")
    def put_configuration_set_sending_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        sending_enabled: Enabled = None,
    ) -> PutConfigurationSetSendingOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetSuppressionOptions")
    def put_configuration_set_suppression_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        suppressed_reasons: SuppressionListReasons = None,
    ) -> PutConfigurationSetSuppressionOptionsResponse:
        raise NotImplementedError

    @handler("PutConfigurationSetTrackingOptions")
    def put_configuration_set_tracking_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        custom_redirect_domain: CustomRedirectDomain = None,
    ) -> PutConfigurationSetTrackingOptionsResponse:
        raise NotImplementedError

    @handler("PutDedicatedIpInPool")
    def put_dedicated_ip_in_pool(
        self, context: RequestContext, ip: Ip, destination_pool_name: PoolName
    ) -> PutDedicatedIpInPoolResponse:
        raise NotImplementedError

    @handler("PutDedicatedIpWarmupAttributes")
    def put_dedicated_ip_warmup_attributes(
        self, context: RequestContext, ip: Ip, warmup_percentage: Percentage100Wrapper
    ) -> PutDedicatedIpWarmupAttributesResponse:
        raise NotImplementedError

    @handler("PutDeliverabilityDashboardOption")
    def put_deliverability_dashboard_option(
        self,
        context: RequestContext,
        dashboard_enabled: Enabled,
        subscribed_domains: DomainDeliverabilityTrackingOptions = None,
    ) -> PutDeliverabilityDashboardOptionResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityConfigurationSetAttributes")
    def put_email_identity_configuration_set_attributes(
        self,
        context: RequestContext,
        email_identity: Identity,
        configuration_set_name: ConfigurationSetName = None,
    ) -> PutEmailIdentityConfigurationSetAttributesResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityDkimAttributes")
    def put_email_identity_dkim_attributes(
        self, context: RequestContext, email_identity: Identity, signing_enabled: Enabled = None
    ) -> PutEmailIdentityDkimAttributesResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityDkimSigningAttributes")
    def put_email_identity_dkim_signing_attributes(
        self,
        context: RequestContext,
        email_identity: Identity,
        signing_attributes_origin: DkimSigningAttributesOrigin,
        signing_attributes: DkimSigningAttributes = None,
    ) -> PutEmailIdentityDkimSigningAttributesResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityFeedbackAttributes")
    def put_email_identity_feedback_attributes(
        self,
        context: RequestContext,
        email_identity: Identity,
        email_forwarding_enabled: Enabled = None,
    ) -> PutEmailIdentityFeedbackAttributesResponse:
        raise NotImplementedError

    @handler("PutEmailIdentityMailFromAttributes")
    def put_email_identity_mail_from_attributes(
        self,
        context: RequestContext,
        email_identity: Identity,
        mail_from_domain: MailFromDomainName = None,
        behavior_on_mx_failure: BehaviorOnMxFailure = None,
    ) -> PutEmailIdentityMailFromAttributesResponse:
        raise NotImplementedError

    @handler("PutSuppressedDestination")
    def put_suppressed_destination(
        self, context: RequestContext, email_address: EmailAddress, reason: SuppressionListReason
    ) -> PutSuppressedDestinationResponse:
        raise NotImplementedError

    @handler("SendBulkEmail")
    def send_bulk_email(
        self,
        context: RequestContext,
        default_content: BulkEmailContent,
        bulk_email_entries: BulkEmailEntryList,
        from_email_address: EmailAddress = None,
        from_email_address_identity_arn: AmazonResourceName = None,
        reply_to_addresses: EmailAddressList = None,
        feedback_forwarding_email_address: EmailAddress = None,
        feedback_forwarding_email_address_identity_arn: AmazonResourceName = None,
        default_email_tags: MessageTagList = None,
        configuration_set_name: ConfigurationSetName = None,
    ) -> SendBulkEmailResponse:
        raise NotImplementedError

    @handler("SendCustomVerificationEmail")
    def send_custom_verification_email(
        self,
        context: RequestContext,
        email_address: EmailAddress,
        template_name: EmailTemplateName,
        configuration_set_name: ConfigurationSetName = None,
    ) -> SendCustomVerificationEmailResponse:
        raise NotImplementedError

    @handler("SendEmail")
    def send_email(
        self,
        context: RequestContext,
        content: EmailContent,
        from_email_address: EmailAddress = None,
        from_email_address_identity_arn: AmazonResourceName = None,
        destination: Destination = None,
        reply_to_addresses: EmailAddressList = None,
        feedback_forwarding_email_address: EmailAddress = None,
        feedback_forwarding_email_address_identity_arn: AmazonResourceName = None,
        email_tags: MessageTagList = None,
        configuration_set_name: ConfigurationSetName = None,
        list_management_options: ListManagementOptions = None,
    ) -> SendEmailResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("TestRenderEmailTemplate")
    def test_render_email_template(
        self,
        context: RequestContext,
        template_name: EmailTemplateName,
        template_data: EmailTemplateData,
    ) -> TestRenderEmailTemplateResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateConfigurationSetEventDestination")
    def update_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination_name: EventDestinationName,
        event_destination: EventDestinationDefinition,
    ) -> UpdateConfigurationSetEventDestinationResponse:
        raise NotImplementedError

    @handler("UpdateContact")
    def update_contact(
        self,
        context: RequestContext,
        contact_list_name: ContactListName,
        email_address: EmailAddress,
        topic_preferences: TopicPreferenceList = None,
        unsubscribe_all: UnsubscribeAll = None,
        attributes_data: AttributesData = None,
    ) -> UpdateContactResponse:
        raise NotImplementedError

    @handler("UpdateContactList")
    def update_contact_list(
        self,
        context: RequestContext,
        contact_list_name: ContactListName,
        topics: Topics = None,
        description: Description = None,
    ) -> UpdateContactListResponse:
        raise NotImplementedError

    @handler("UpdateCustomVerificationEmailTemplate")
    def update_custom_verification_email_template(
        self,
        context: RequestContext,
        template_name: EmailTemplateName,
        from_email_address: EmailAddress,
        template_subject: EmailTemplateSubject,
        template_content: TemplateContent,
        success_redirection_url: SuccessRedirectionURL,
        failure_redirection_url: FailureRedirectionURL,
    ) -> UpdateCustomVerificationEmailTemplateResponse:
        raise NotImplementedError

    @handler("UpdateEmailIdentityPolicy")
    def update_email_identity_policy(
        self,
        context: RequestContext,
        email_identity: Identity,
        policy_name: PolicyName,
        policy: Policy,
    ) -> UpdateEmailIdentityPolicyResponse:
        raise NotImplementedError

    @handler("UpdateEmailTemplate")
    def update_email_template(
        self,
        context: RequestContext,
        template_name: EmailTemplateName,
        template_content: EmailTemplateContent,
    ) -> UpdateEmailTemplateResponse:
        raise NotImplementedError
