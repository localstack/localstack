import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Address = str
AmazonResourceName = str
BounceMessage = str
BounceSmtpReplyCode = str
BounceStatusCode = str
Charset = str
Cidr = str
ConfigurationSetName = str
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


class BehaviorOnMXFailure(str):
    UseDefaultValue = "UseDefaultValue"
    RejectMessage = "RejectMessage"


class BounceType(str):
    DoesNotExist = "DoesNotExist"
    MessageTooLarge = "MessageTooLarge"
    ExceededQuota = "ExceededQuota"
    ContentRejected = "ContentRejected"
    Undefined = "Undefined"
    TemporaryFailure = "TemporaryFailure"


class BulkEmailStatus(str):
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


class ConfigurationSetAttribute(str):
    eventDestinations = "eventDestinations"
    trackingOptions = "trackingOptions"
    deliveryOptions = "deliveryOptions"
    reputationOptions = "reputationOptions"


class CustomMailFromStatus(str):
    Pending = "Pending"
    Success = "Success"
    Failed = "Failed"
    TemporaryFailure = "TemporaryFailure"


class DimensionValueSource(str):
    messageTag = "messageTag"
    emailHeader = "emailHeader"
    linkTag = "linkTag"


class DsnAction(str):
    failed = "failed"
    delayed = "delayed"
    delivered = "delivered"
    relayed = "relayed"
    expanded = "expanded"


class EventType(str):
    send = "send"
    reject = "reject"
    bounce = "bounce"
    complaint = "complaint"
    delivery = "delivery"
    open = "open"
    click = "click"
    renderingFailure = "renderingFailure"


class IdentityType(str):
    EmailAddress = "EmailAddress"
    Domain = "Domain"


class InvocationType(str):
    Event = "Event"
    RequestResponse = "RequestResponse"


class NotificationType(str):
    Bounce = "Bounce"
    Complaint = "Complaint"
    Delivery = "Delivery"


class ReceiptFilterPolicy(str):
    Block = "Block"
    Allow = "Allow"


class SNSActionEncoding(str):
    UTF_8 = "UTF-8"
    Base64 = "Base64"


class StopScope(str):
    RuleSet = "RuleSet"


class TlsPolicy(str):
    Require = "Require"
    Optional_ = "Optional"


class VerificationStatus(str):
    Pending = "Pending"
    Success = "Success"
    Failed = "Failed"
    TemporaryFailure = "TemporaryFailure"
    NotStarted = "NotStarted"


class AccountSendingPausedException(ServiceException):
    """Indicates that email sending is disabled for your entire Amazon SES
    account.

    You can enable or disable email sending for your Amazon SES account
    using UpdateAccountSendingEnabled.
    """


class AlreadyExistsException(ServiceException):
    """Indicates that a resource could not be created because of a naming
    conflict.
    """

    Name: Optional[RuleOrRuleSetName]


class CannotDeleteException(ServiceException):
    """Indicates that the delete operation could not be completed."""

    Name: Optional[RuleOrRuleSetName]


class ConfigurationSetAlreadyExistsException(ServiceException):
    """Indicates that the configuration set could not be created because of a
    naming conflict.
    """

    ConfigurationSetName: Optional[ConfigurationSetName]


class ConfigurationSetDoesNotExistException(ServiceException):
    """Indicates that the configuration set does not exist."""

    ConfigurationSetName: Optional[ConfigurationSetName]


class ConfigurationSetSendingPausedException(ServiceException):
    """Indicates that email sending is disabled for the configuration set.

    You can enable or disable email sending for a configuration set using
    UpdateConfigurationSetSendingEnabled.
    """

    ConfigurationSetName: Optional[ConfigurationSetName]


class CustomVerificationEmailInvalidContentException(ServiceException):
    """Indicates that custom verification email template provided content is
    invalid.
    """


class CustomVerificationEmailTemplateAlreadyExistsException(ServiceException):
    """Indicates that a custom verification email template with the name you
    specified already exists.
    """

    CustomVerificationEmailTemplateName: Optional[TemplateName]


class CustomVerificationEmailTemplateDoesNotExistException(ServiceException):
    """Indicates that a custom verification email template with the name you
    specified does not exist.
    """

    CustomVerificationEmailTemplateName: Optional[TemplateName]


class EventDestinationAlreadyExistsException(ServiceException):
    """Indicates that the event destination could not be created because of a
    naming conflict.
    """

    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class EventDestinationDoesNotExistException(ServiceException):
    """Indicates that the event destination does not exist."""

    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class FromEmailAddressNotVerifiedException(ServiceException):
    """Indicates that the sender address specified for a custom verification
    email is not verified, and is therefore not eligible to send the custom
    verification email.
    """

    FromEmailAddress: Optional[FromAddress]


class InvalidCloudWatchDestinationException(ServiceException):
    """Indicates that the Amazon CloudWatch destination is invalid. See the
    error message for details.
    """

    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class InvalidConfigurationSetException(ServiceException):
    """Indicates that the configuration set is invalid. See the error message
    for details.
    """


class InvalidDeliveryOptionsException(ServiceException):
    """Indicates that provided delivery option is invalid."""


class InvalidFirehoseDestinationException(ServiceException):
    """Indicates that the Amazon Kinesis Firehose destination is invalid. See
    the error message for details.
    """

    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class InvalidLambdaFunctionException(ServiceException):
    """Indicates that the provided AWS Lambda function is invalid, or that
    Amazon SES could not execute the provided function, possibly due to
    permissions issues. For information about giving permissions, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html>`__.
    """

    FunctionArn: Optional[AmazonResourceName]


class InvalidPolicyException(ServiceException):
    """Indicates that the provided policy is invalid. Check the error stack for
    more information about what caused the error.
    """


class InvalidRenderingParameterException(ServiceException):
    """Indicates that one or more of the replacement values you provided is
    invalid. This error may occur when the TemplateData object contains
    invalid JSON.
    """

    TemplateName: Optional[TemplateName]


class InvalidS3ConfigurationException(ServiceException):
    """Indicates that the provided Amazon S3 bucket or AWS KMS encryption key
    is invalid, or that Amazon SES could not publish to the bucket, possibly
    due to permissions issues. For information about giving permissions, see
    the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html>`__.
    """

    Bucket: Optional[S3BucketName]


class InvalidSNSDestinationException(ServiceException):
    """Indicates that the Amazon Simple Notification Service (Amazon SNS)
    destination is invalid. See the error message for details.
    """

    ConfigurationSetName: Optional[ConfigurationSetName]
    EventDestinationName: Optional[EventDestinationName]


class InvalidSnsTopicException(ServiceException):
    """Indicates that the provided Amazon SNS topic is invalid, or that Amazon
    SES could not publish to the topic, possibly due to permissions issues.
    For information about giving permissions, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html>`__.
    """

    Topic: Optional[AmazonResourceName]


class InvalidTemplateException(ServiceException):
    """Indicates that the template that you specified could not be rendered.
    This issue may occur when a template refers to a partial that does not
    exist.
    """

    TemplateName: Optional[TemplateName]


class InvalidTrackingOptionsException(ServiceException):
    """Indicates that the custom domain to be used for open and click tracking
    redirects is invalid. This error appears most often in the following
    situations:

    -  When the tracking domain you specified is not verified in Amazon SES.

    -  When the tracking domain you specified is not a valid domain or
       subdomain.
    """


class LimitExceededException(ServiceException):
    """Indicates that a resource could not be created because of service
    limits. For a list of Amazon SES limits, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/limits.html>`__.
    """


class MailFromDomainNotVerifiedException(ServiceException):
    """Indicates that the message could not be sent because Amazon SES could
    not read the MX record required to use the specified MAIL FROM domain.
    For information about editing the custom MAIL FROM domain settings for
    an identity, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/mail-from-edit.html>`__.
    """


class MessageRejected(ServiceException):
    """Indicates that the action failed, and the message could not be sent.
    Check the error stack for more information about what caused the error.
    """


class MissingRenderingAttributeException(ServiceException):
    """Indicates that one or more of the replacement values for the specified
    template was not specified. Ensure that the TemplateData object contains
    references to all of the replacement tags in the specified template.
    """

    TemplateName: Optional[TemplateName]


class ProductionAccessNotGrantedException(ServiceException):
    """Indicates that the account has not been granted production access."""


class RuleDoesNotExistException(ServiceException):
    """Indicates that the provided receipt rule does not exist."""

    Name: Optional[RuleOrRuleSetName]


class RuleSetDoesNotExistException(ServiceException):
    """Indicates that the provided receipt rule set does not exist."""

    Name: Optional[RuleOrRuleSetName]


class TemplateDoesNotExistException(ServiceException):
    """Indicates that the Template object you specified does not exist in your
    Amazon SES account.
    """

    TemplateName: Optional[TemplateName]


class TrackingOptionsAlreadyExistsException(ServiceException):
    """Indicates that the configuration set you specified already contains a
    TrackingOptions object.
    """

    ConfigurationSetName: Optional[ConfigurationSetName]


class TrackingOptionsDoesNotExistException(ServiceException):
    """Indicates that the TrackingOptions object you specified does not exist."""

    ConfigurationSetName: Optional[ConfigurationSetName]


class AddHeaderAction(TypedDict, total=False):
    """When included in a receipt rule, this action adds a header to the
    received email.

    For information about adding a header using a receipt rule, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-action-add-header.html>`__.
    """

    HeaderName: HeaderName
    HeaderValue: HeaderValue


AddressList = List[Address]
ArrivalDate = datetime


class Content(TypedDict, total=False):
    """Represents textual data, plus an optional character set specification.

    By default, the text must be 7-bit ASCII, due to the constraints of the
    SMTP protocol. If the text must contain any other characters, then you
    must also specify a character set. Examples include UTF-8, ISO-8859-1,
    and Shift_JIS.
    """

    Data: MessageData
    Charset: Optional[Charset]


class Body(TypedDict, total=False):
    """Represents the body of the message. You can specify text, HTML, or both.
    If you use both, then the message should display correctly in the widest
    variety of email clients.
    """

    Text: Optional[Content]
    Html: Optional[Content]


class BounceAction(TypedDict, total=False):
    """When included in a receipt rule, this action rejects the received email
    by returning a bounce response to the sender and, optionally, publishes
    a notification to Amazon Simple Notification Service (Amazon SNS).

    For information about sending a bounce message in response to a received
    email, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-action-bounce.html>`__.
    """

    TopicArn: Optional[AmazonResourceName]
    SmtpReplyCode: BounceSmtpReplyCode
    StatusCode: Optional[BounceStatusCode]
    Message: BounceMessage
    Sender: Address


class ExtensionField(TypedDict, total=False):
    """Additional X-headers to include in the Delivery Status Notification
    (DSN) when an email that Amazon SES receives on your behalf bounces.

    For information about receiving email through Amazon SES, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email.html>`__.
    """

    Name: ExtensionFieldName
    Value: ExtensionFieldValue


ExtensionFieldList = List[ExtensionField]
LastAttemptDate = datetime


class RecipientDsnFields(TypedDict, total=False):
    """Recipient-related information to include in the Delivery Status
    Notification (DSN) when an email that Amazon SES receives on your behalf
    bounces.

    For information about receiving email through Amazon SES, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email.html>`__.
    """

    FinalRecipient: Optional[Address]
    Action: DsnAction
    RemoteMta: Optional[RemoteMta]
    Status: DsnStatus
    DiagnosticCode: Optional[DiagnosticCode]
    LastAttemptDate: Optional[LastAttemptDate]
    ExtensionFields: Optional[ExtensionFieldList]


class BouncedRecipientInfo(TypedDict, total=False):
    """Recipient-related information to include in the Delivery Status
    Notification (DSN) when an email that Amazon SES receives on your behalf
    bounces.

    For information about receiving email through Amazon SES, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email.html>`__.
    """

    Recipient: Address
    RecipientArn: Optional[AmazonResourceName]
    BounceType: Optional[BounceType]
    RecipientDsnFields: Optional[RecipientDsnFields]


BouncedRecipientInfoList = List[BouncedRecipientInfo]


class MessageTag(TypedDict, total=False):
    """Contains the name and value of a tag that you can provide to
    ``SendEmail`` or ``SendRawEmail`` to apply to an email.

    Message tags, which you use with configuration sets, enable you to
    publish email sending events. For information about using configuration
    sets, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    Name: MessageTagName
    Value: MessageTagValue


MessageTagList = List[MessageTag]


class Destination(TypedDict, total=False):
    """Represents the destination of the message, consisting of To:, CC:, and
    BCC: fields.

    Amazon SES does not support the SMTPUTF8 extension, as described in
    `RFC6531 <https://tools.ietf.org/html/rfc6531>`__. For this reason, the
    *local part* of a destination email address (the part of the email
    address that precedes the @ sign) may only contain `7-bit ASCII
    characters <https://en.wikipedia.org/wiki/Email_address#Local-part>`__.
    If the *domain part* of an address (the part after the @ sign) contains
    non-ASCII characters, they must be encoded using Punycode, as described
    in `RFC3492 <https://tools.ietf.org/html/rfc3492.html>`__.
    """

    ToAddresses: Optional[AddressList]
    CcAddresses: Optional[AddressList]
    BccAddresses: Optional[AddressList]


class BulkEmailDestination(TypedDict, total=False):
    """An array that contains one or more Destinations, as well as the tags and
    replacement data associated with each of those Destinations.
    """

    Destination: Destination
    ReplacementTags: Optional[MessageTagList]
    ReplacementTemplateData: Optional[TemplateData]


BulkEmailDestinationList = List[BulkEmailDestination]


class BulkEmailDestinationStatus(TypedDict, total=False):
    """An object that contains the response from the ``SendBulkTemplatedEmail``
    operation.
    """

    Status: Optional[BulkEmailStatus]
    Error: Optional[Error]
    MessageId: Optional[MessageId]


BulkEmailDestinationStatusList = List[BulkEmailDestinationStatus]


class CloneReceiptRuleSetRequest(ServiceRequest):
    """Represents a request to create a receipt rule set by cloning an existing
    one. You use receipt rule sets to receive email with Amazon SES. For
    more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName
    OriginalRuleSetName: ReceiptRuleSetName


class CloneReceiptRuleSetResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class CloudWatchDimensionConfiguration(TypedDict, total=False):
    """Contains the dimension configuration to use when you publish email
    sending events to Amazon CloudWatch.

    For information about publishing email sending events to Amazon
    CloudWatch, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    DimensionName: DimensionName
    DimensionValueSource: DimensionValueSource
    DefaultDimensionValue: DefaultDimensionValue


CloudWatchDimensionConfigurations = List[CloudWatchDimensionConfiguration]


class CloudWatchDestination(TypedDict, total=False):
    """Contains information associated with an Amazon CloudWatch event
    destination to which email sending events are published.

    Event destinations, such as Amazon CloudWatch, are associated with
    configuration sets, which enable you to publish email sending events.
    For information about using configuration sets, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    DimensionConfigurations: CloudWatchDimensionConfigurations


class ConfigurationSet(TypedDict, total=False):
    """The name of the configuration set.

    Configuration sets let you create groups of rules that you can apply to
    the emails you send using Amazon SES. For more information about using
    configuration sets, see `Using Amazon SES Configuration
    Sets <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/using-configuration-sets.html>`__
    in the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/>`__.
    """

    Name: ConfigurationSetName


ConfigurationSetAttributeList = List[ConfigurationSetAttribute]
ConfigurationSets = List[ConfigurationSet]
Counter = int


class SNSDestination(TypedDict, total=False):
    """Contains the topic ARN associated with an Amazon Simple Notification
    Service (Amazon SNS) event destination.

    Event destinations, such as Amazon SNS, are associated with
    configuration sets, which enable you to publish email sending events.
    For information about using configuration sets, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    TopicARN: AmazonResourceName


class KinesisFirehoseDestination(TypedDict, total=False):
    """Contains the delivery stream ARN and the IAM role ARN associated with an
    Amazon Kinesis Firehose event destination.

    Event destinations, such as Amazon Kinesis Firehose, are associated with
    configuration sets, which enable you to publish email sending events.
    For information about using configuration sets, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    IAMRoleARN: AmazonResourceName
    DeliveryStreamARN: AmazonResourceName


EventTypes = List[EventType]


class EventDestination(TypedDict, total=False):
    """Contains information about the event destination that the specified
    email sending events will be published to.

    When you create or update an event destination, you must provide one,
    and only one, destination. The destination can be Amazon CloudWatch,
    Amazon Kinesis Firehose or Amazon Simple Notification Service (Amazon
    SNS).

    Event destinations are associated with configuration sets, which enable
    you to publish email sending events to Amazon CloudWatch, Amazon Kinesis
    Firehose, or Amazon Simple Notification Service (Amazon SNS). For
    information about using configuration sets, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    Name: EventDestinationName
    Enabled: Optional[Enabled]
    MatchingEventTypes: EventTypes
    KinesisFirehoseDestination: Optional[KinesisFirehoseDestination]
    CloudWatchDestination: Optional[CloudWatchDestination]
    SNSDestination: Optional[SNSDestination]


class CreateConfigurationSetEventDestinationRequest(ServiceRequest):
    """Represents a request to create a configuration set event destination. A
    configuration set event destination, which can be either Amazon
    CloudWatch or Amazon Kinesis Firehose, describes an AWS service in which
    Amazon SES publishes the email sending events associated with a
    configuration set. For information about using configuration sets, see
    the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    ConfigurationSetName: ConfigurationSetName
    EventDestination: EventDestination


class CreateConfigurationSetEventDestinationResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class CreateConfigurationSetRequest(ServiceRequest):
    """Represents a request to create a configuration set. Configuration sets
    enable you to publish email sending events. For information about using
    configuration sets, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    ConfigurationSet: ConfigurationSet


class CreateConfigurationSetResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class TrackingOptions(TypedDict, total=False):
    """A domain that is used to redirect email recipients to an Amazon
    SES-operated domain. This domain captures open and click events
    generated by Amazon SES emails.

    For more information, see `Configuring Custom Domains to Handle Open and
    Click
    Tracking <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/configure-custom-open-click-domains.html>`__
    in the *Amazon SES Developer Guide*.
    """

    CustomRedirectDomain: Optional[CustomRedirectDomain]


class CreateConfigurationSetTrackingOptionsRequest(ServiceRequest):
    """Represents a request to create an open and click tracking option object
    in a configuration set.
    """

    ConfigurationSetName: ConfigurationSetName
    TrackingOptions: TrackingOptions


class CreateConfigurationSetTrackingOptionsResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class CreateCustomVerificationEmailTemplateRequest(ServiceRequest):
    """Represents a request to create a custom verification email template."""

    TemplateName: TemplateName
    FromEmailAddress: FromAddress
    TemplateSubject: Subject
    TemplateContent: TemplateContent
    SuccessRedirectionURL: SuccessRedirectionURL
    FailureRedirectionURL: FailureRedirectionURL


class ReceiptIpFilter(TypedDict, total=False):
    """A receipt IP address filter enables you to specify whether to accept or
    reject mail originating from an IP address or range of IP addresses.

    For information about setting up IP address filters, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-ip-filters.html>`__.
    """

    Policy: ReceiptFilterPolicy
    Cidr: Cidr


class ReceiptFilter(TypedDict, total=False):
    """A receipt IP address filter enables you to specify whether to accept or
    reject mail originating from an IP address or range of IP addresses.

    For information about setting up IP address filters, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-ip-filters.html>`__.
    """

    Name: ReceiptFilterName
    IpFilter: ReceiptIpFilter


class CreateReceiptFilterRequest(ServiceRequest):
    """Represents a request to create a new IP address filter. You use IP
    address filters when you receive email with Amazon SES. For more
    information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    Filter: ReceiptFilter


class CreateReceiptFilterResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SNSAction(TypedDict, total=False):
    """When included in a receipt rule, this action publishes a notification to
    Amazon Simple Notification Service (Amazon SNS). This action includes a
    complete copy of the email content in the Amazon SNS notifications.
    Amazon SNS notifications for all other actions simply provide
    information about the email. They do not include the email content
    itself.

    If you own the Amazon SNS topic, you don't need to do anything to give
    Amazon SES permission to publish emails to it. However, if you don't own
    the Amazon SNS topic, you need to attach a policy to the topic to give
    Amazon SES permissions to access it. For information about giving
    permissions, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html>`__.

    You can only publish emails that are 150 KB or less (including the
    header) to Amazon SNS. Larger emails will bounce. If you anticipate
    emails larger than 150 KB, use the S3 action instead.

    For information about using a receipt rule to publish an Amazon SNS
    notification, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-action-sns.html>`__.
    """

    TopicArn: AmazonResourceName
    Encoding: Optional[SNSActionEncoding]


class StopAction(TypedDict, total=False):
    """When included in a receipt rule, this action terminates the evaluation
    of the receipt rule set and, optionally, publishes a notification to
    Amazon Simple Notification Service (Amazon SNS).

    For information about setting a stop action in a receipt rule, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-action-stop.html>`__.
    """

    Scope: StopScope
    TopicArn: Optional[AmazonResourceName]


class LambdaAction(TypedDict, total=False):
    """When included in a receipt rule, this action calls an AWS Lambda
    function and, optionally, publishes a notification to Amazon Simple
    Notification Service (Amazon SNS).

    To enable Amazon SES to call your AWS Lambda function or to publish to
    an Amazon SNS topic of another account, Amazon SES must have permission
    to access those resources. For information about giving permissions, see
    the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html>`__.

    For information about using AWS Lambda actions in receipt rules, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-action-lambda.html>`__.
    """

    TopicArn: Optional[AmazonResourceName]
    FunctionArn: AmazonResourceName
    InvocationType: Optional[InvocationType]


class WorkmailAction(TypedDict, total=False):
    """When included in a receipt rule, this action calls Amazon WorkMail and,
    optionally, publishes a notification to Amazon Simple Notification
    Service (Amazon SNS). You will typically not use this action directly
    because Amazon WorkMail adds the rule automatically during its setup
    procedure.

    For information using a receipt rule to call Amazon WorkMail, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-action-workmail.html>`__.
    """

    TopicArn: Optional[AmazonResourceName]
    OrganizationArn: AmazonResourceName


class S3Action(TypedDict, total=False):
    """When included in a receipt rule, this action saves the received message
    to an Amazon Simple Storage Service (Amazon S3) bucket and, optionally,
    publishes a notification to Amazon Simple Notification Service (Amazon
    SNS).

    To enable Amazon SES to write emails to your Amazon S3 bucket, use an
    AWS KMS key to encrypt your emails, or publish to an Amazon SNS topic of
    another account, Amazon SES must have permission to access those
    resources. For information about giving permissions, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-permissions.html>`__.

    When you save your emails to an Amazon S3 bucket, the maximum email size
    (including headers) is 30 MB. Emails larger than that will bounce.

    For information about specifying Amazon S3 actions in receipt rules, see
    the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-action-s3.html>`__.
    """

    TopicArn: Optional[AmazonResourceName]
    BucketName: S3BucketName
    ObjectKeyPrefix: Optional[S3KeyPrefix]
    KmsKeyArn: Optional[AmazonResourceName]


class ReceiptAction(TypedDict, total=False):
    """An action that Amazon SES can take when it receives an email on behalf
    of one or more email addresses or domains that you own. An instance of
    this data type can represent only one action.

    For information about setting up receipt rules, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-receipt-rules.html>`__.
    """

    S3Action: Optional[S3Action]
    BounceAction: Optional[BounceAction]
    WorkmailAction: Optional[WorkmailAction]
    LambdaAction: Optional[LambdaAction]
    StopAction: Optional[StopAction]
    AddHeaderAction: Optional[AddHeaderAction]
    SNSAction: Optional[SNSAction]


ReceiptActionsList = List[ReceiptAction]
RecipientsList = List[Recipient]


class ReceiptRule(TypedDict, total=False):
    """Receipt rules enable you to specify which actions Amazon SES should take
    when it receives mail on behalf of one or more email addresses or
    domains that you own.

    Each receipt rule defines a set of email addresses or domains that it
    applies to. If the email addresses or domains match at least one
    recipient address of the message, Amazon SES executes all of the receipt
    rule's actions on the message.

    For information about setting up receipt rules, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-receipt-rules.html>`__.
    """

    Name: ReceiptRuleName
    Enabled: Optional[Enabled]
    TlsPolicy: Optional[TlsPolicy]
    Recipients: Optional[RecipientsList]
    Actions: Optional[ReceiptActionsList]
    ScanEnabled: Optional[Enabled]


class CreateReceiptRuleRequest(ServiceRequest):
    """Represents a request to create a receipt rule. You use receipt rules to
    receive email with Amazon SES. For more information, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName
    After: Optional[ReceiptRuleName]
    Rule: ReceiptRule


class CreateReceiptRuleResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class CreateReceiptRuleSetRequest(ServiceRequest):
    """Represents a request to create an empty receipt rule set. You use
    receipt rule sets to receive email with Amazon SES. For more
    information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName


class CreateReceiptRuleSetResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class Template(TypedDict, total=False):
    """The content of the email, composed of a subject line, an HTML part, and
    a text-only part.
    """

    TemplateName: TemplateName
    SubjectPart: Optional[SubjectPart]
    TextPart: Optional[TextPart]
    HtmlPart: Optional[HtmlPart]


class CreateTemplateRequest(ServiceRequest):
    """Represents a request to create an email template. For more information,
    see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-personalized-email-api.html>`__.
    """

    Template: Template


class CreateTemplateResponse(TypedDict, total=False):
    pass


class CustomVerificationEmailTemplate(TypedDict, total=False):
    """Contains information about a custom verification email template."""

    TemplateName: Optional[TemplateName]
    FromEmailAddress: Optional[FromAddress]
    TemplateSubject: Optional[Subject]
    SuccessRedirectionURL: Optional[SuccessRedirectionURL]
    FailureRedirectionURL: Optional[FailureRedirectionURL]


CustomVerificationEmailTemplates = List[CustomVerificationEmailTemplate]


class DeleteConfigurationSetEventDestinationRequest(ServiceRequest):
    """Represents a request to delete a configuration set event destination.
    Configuration set event destinations are associated with configuration
    sets, which enable you to publish email sending events. For information
    about using configuration sets, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    ConfigurationSetName: ConfigurationSetName
    EventDestinationName: EventDestinationName


class DeleteConfigurationSetEventDestinationResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class DeleteConfigurationSetRequest(ServiceRequest):
    """Represents a request to delete a configuration set. Configuration sets
    enable you to publish email sending events. For information about using
    configuration sets, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    ConfigurationSetName: ConfigurationSetName


class DeleteConfigurationSetResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class DeleteConfigurationSetTrackingOptionsRequest(ServiceRequest):
    """Represents a request to delete open and click tracking options in a
    configuration set.
    """

    ConfigurationSetName: ConfigurationSetName


class DeleteConfigurationSetTrackingOptionsResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class DeleteCustomVerificationEmailTemplateRequest(ServiceRequest):
    """Represents a request to delete an existing custom verification email
    template.
    """

    TemplateName: TemplateName


class DeleteIdentityPolicyRequest(ServiceRequest):
    """Represents a request to delete a sending authorization policy for an
    identity. Sending authorization is an Amazon SES feature that enables
    you to authorize other senders to use your identities. For information,
    see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__.
    """

    Identity: Identity
    PolicyName: PolicyName


class DeleteIdentityPolicyResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class DeleteIdentityRequest(ServiceRequest):
    """Represents a request to delete one of your Amazon SES identities (an
    email address or domain).
    """

    Identity: Identity


class DeleteIdentityResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class DeleteReceiptFilterRequest(ServiceRequest):
    """Represents a request to delete an IP address filter. You use IP address
    filters when you receive email with Amazon SES. For more information,
    see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    FilterName: ReceiptFilterName


class DeleteReceiptFilterResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class DeleteReceiptRuleRequest(ServiceRequest):
    """Represents a request to delete a receipt rule. You use receipt rules to
    receive email with Amazon SES. For more information, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName
    RuleName: ReceiptRuleName


class DeleteReceiptRuleResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class DeleteReceiptRuleSetRequest(ServiceRequest):
    """Represents a request to delete a receipt rule set and all of the receipt
    rules it contains. You use receipt rule sets to receive email with
    Amazon SES. For more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName


class DeleteReceiptRuleSetResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class DeleteTemplateRequest(ServiceRequest):
    """Represents a request to delete an email template. For more information,
    see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-personalized-email-api.html>`__.
    """

    TemplateName: TemplateName


class DeleteTemplateResponse(TypedDict, total=False):
    pass


class DeleteVerifiedEmailAddressRequest(ServiceRequest):
    """Represents a request to delete an email address from the list of email
    addresses you have attempted to verify under your AWS account.
    """

    EmailAddress: Address


class DeliveryOptions(TypedDict, total=False):
    """Specifies whether messages that use the configuration set are required
    to use Transport Layer Security (TLS).
    """

    TlsPolicy: Optional[TlsPolicy]


class DescribeActiveReceiptRuleSetRequest(ServiceRequest):
    """Represents a request to return the metadata and receipt rules for the
    receipt rule set that is currently active. You use receipt rule sets to
    receive email with Amazon SES. For more information, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """


ReceiptRulesList = List[ReceiptRule]
Timestamp = datetime


class ReceiptRuleSetMetadata(TypedDict, total=False):
    """Information about a receipt rule set.

    A receipt rule set is a collection of rules that specify what Amazon SES
    should do with mail it receives on behalf of your account's verified
    domains.

    For information about setting up receipt rule sets, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-receipt-rule-set.html>`__.
    """

    Name: Optional[ReceiptRuleSetName]
    CreatedTimestamp: Optional[Timestamp]


class DescribeActiveReceiptRuleSetResponse(TypedDict, total=False):
    """Represents the metadata and receipt rules for the receipt rule set that
    is currently active.
    """

    Metadata: Optional[ReceiptRuleSetMetadata]
    Rules: Optional[ReceiptRulesList]


class DescribeConfigurationSetRequest(ServiceRequest):
    """Represents a request to return the details of a configuration set.
    Configuration sets enable you to publish email sending events. For
    information about using configuration sets, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    ConfigurationSetName: ConfigurationSetName
    ConfigurationSetAttributeNames: Optional[ConfigurationSetAttributeList]


LastFreshStart = datetime


class ReputationOptions(TypedDict, total=False):
    """Contains information about the reputation settings for a configuration
    set.
    """

    SendingEnabled: Optional[Enabled]
    ReputationMetricsEnabled: Optional[Enabled]
    LastFreshStart: Optional[LastFreshStart]


EventDestinations = List[EventDestination]


class DescribeConfigurationSetResponse(TypedDict, total=False):
    """Represents the details of a configuration set. Configuration sets enable
    you to publish email sending events. For information about using
    configuration sets, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    ConfigurationSet: Optional[ConfigurationSet]
    EventDestinations: Optional[EventDestinations]
    TrackingOptions: Optional[TrackingOptions]
    DeliveryOptions: Optional[DeliveryOptions]
    ReputationOptions: Optional[ReputationOptions]


class DescribeReceiptRuleRequest(ServiceRequest):
    """Represents a request to return the details of a receipt rule. You use
    receipt rules to receive email with Amazon SES. For more information,
    see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName
    RuleName: ReceiptRuleName


class DescribeReceiptRuleResponse(TypedDict, total=False):
    """Represents the details of a receipt rule."""

    Rule: Optional[ReceiptRule]


class DescribeReceiptRuleSetRequest(ServiceRequest):
    """Represents a request to return the details of a receipt rule set. You
    use receipt rule sets to receive email with Amazon SES. For more
    information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName


class DescribeReceiptRuleSetResponse(TypedDict, total=False):
    """Represents the details of the specified receipt rule set."""

    Metadata: Optional[ReceiptRuleSetMetadata]
    Rules: Optional[ReceiptRulesList]


VerificationTokenList = List[VerificationToken]


class IdentityDkimAttributes(TypedDict, total=False):
    """Represents the DKIM attributes of a verified email address or a domain."""

    DkimEnabled: Enabled
    DkimVerificationStatus: VerificationStatus
    DkimTokens: Optional[VerificationTokenList]


DkimAttributes = Dict[Identity, IdentityDkimAttributes]


class GetAccountSendingEnabledResponse(TypedDict, total=False):
    """Represents a request to return the email sending status for your Amazon
    SES account in the current AWS Region.
    """

    Enabled: Optional[Enabled]


class GetCustomVerificationEmailTemplateRequest(ServiceRequest):
    """Represents a request to retrieve an existing custom verification email
    template.
    """

    TemplateName: TemplateName


class GetCustomVerificationEmailTemplateResponse(TypedDict, total=False):
    """The content of the custom verification email template."""

    TemplateName: Optional[TemplateName]
    FromEmailAddress: Optional[FromAddress]
    TemplateSubject: Optional[Subject]
    TemplateContent: Optional[TemplateContent]
    SuccessRedirectionURL: Optional[SuccessRedirectionURL]
    FailureRedirectionURL: Optional[FailureRedirectionURL]


IdentityList = List[Identity]


class GetIdentityDkimAttributesRequest(ServiceRequest):
    """Represents a request for the status of Amazon SES Easy DKIM signing for
    an identity. For domain identities, this request also returns the DKIM
    tokens that are required for Easy DKIM signing, and whether Amazon SES
    successfully verified that these tokens were published. For more
    information about Easy DKIM, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html>`__.
    """

    Identities: IdentityList


class GetIdentityDkimAttributesResponse(TypedDict, total=False):
    """Represents the status of Amazon SES Easy DKIM signing for an identity.
    For domain identities, this response also contains the DKIM tokens that
    are required for Easy DKIM signing, and whether Amazon SES successfully
    verified that these tokens were published.
    """

    DkimAttributes: DkimAttributes


class GetIdentityMailFromDomainAttributesRequest(ServiceRequest):
    """Represents a request to return the Amazon SES custom MAIL FROM
    attributes for a list of identities. For information about using a
    custom MAIL FROM domain, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/mail-from.html>`__.
    """

    Identities: IdentityList


class IdentityMailFromDomainAttributes(TypedDict, total=False):
    """Represents the custom MAIL FROM domain attributes of a verified identity
    (email address or domain).
    """

    MailFromDomain: MailFromDomainName
    MailFromDomainStatus: CustomMailFromStatus
    BehaviorOnMXFailure: BehaviorOnMXFailure


MailFromDomainAttributes = Dict[Identity, IdentityMailFromDomainAttributes]


class GetIdentityMailFromDomainAttributesResponse(TypedDict, total=False):
    """Represents the custom MAIL FROM attributes for a list of identities."""

    MailFromDomainAttributes: MailFromDomainAttributes


class GetIdentityNotificationAttributesRequest(ServiceRequest):
    """Represents a request to return the notification attributes for a list of
    identities you verified with Amazon SES. For information about Amazon
    SES notifications, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notifications.html>`__.
    """

    Identities: IdentityList


class IdentityNotificationAttributes(TypedDict, total=False):
    """Represents the notification attributes of an identity, including whether
    an identity has Amazon Simple Notification Service (Amazon SNS) topics
    set for bounce, complaint, and/or delivery notifications, and whether
    feedback forwarding is enabled for bounce and complaint notifications.
    """

    BounceTopic: NotificationTopic
    ComplaintTopic: NotificationTopic
    DeliveryTopic: NotificationTopic
    ForwardingEnabled: Enabled
    HeadersInBounceNotificationsEnabled: Optional[Enabled]
    HeadersInComplaintNotificationsEnabled: Optional[Enabled]
    HeadersInDeliveryNotificationsEnabled: Optional[Enabled]


NotificationAttributes = Dict[Identity, IdentityNotificationAttributes]


class GetIdentityNotificationAttributesResponse(TypedDict, total=False):
    """Represents the notification attributes for a list of identities."""

    NotificationAttributes: NotificationAttributes


PolicyNameList = List[PolicyName]


class GetIdentityPoliciesRequest(ServiceRequest):
    """Represents a request to return the requested sending authorization
    policies for an identity. Sending authorization is an Amazon SES feature
    that enables you to authorize other senders to use your identities. For
    information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__.
    """

    Identity: Identity
    PolicyNames: PolicyNameList


PolicyMap = Dict[PolicyName, Policy]


class GetIdentityPoliciesResponse(TypedDict, total=False):
    """Represents the requested sending authorization policies."""

    Policies: PolicyMap


class GetIdentityVerificationAttributesRequest(ServiceRequest):
    """Represents a request to return the Amazon SES verification status of a
    list of identities. For domain identities, this request also returns the
    verification token. For information about verifying identities with
    Amazon SES, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-addresses-and-domains.html>`__.
    """

    Identities: IdentityList


class IdentityVerificationAttributes(TypedDict, total=False):
    """Represents the verification attributes of a single identity."""

    VerificationStatus: VerificationStatus
    VerificationToken: Optional[VerificationToken]


VerificationAttributes = Dict[Identity, IdentityVerificationAttributes]


class GetIdentityVerificationAttributesResponse(TypedDict, total=False):
    """The Amazon SES verification status of a list of identities. For domain
    identities, this response also contains the verification token.
    """

    VerificationAttributes: VerificationAttributes


class GetSendQuotaResponse(TypedDict, total=False):
    """Represents your Amazon SES daily sending quota, maximum send rate, and
    the number of emails you have sent in the last 24 hours.
    """

    Max24HourSend: Optional[Max24HourSend]
    MaxSendRate: Optional[MaxSendRate]
    SentLast24Hours: Optional[SentLast24Hours]


class SendDataPoint(TypedDict, total=False):
    """Represents sending statistics data. Each ``SendDataPoint`` contains
    statistics for a 15-minute period of sending activity.
    """

    Timestamp: Optional[Timestamp]
    DeliveryAttempts: Optional[Counter]
    Bounces: Optional[Counter]
    Complaints: Optional[Counter]
    Rejects: Optional[Counter]


SendDataPointList = List[SendDataPoint]


class GetSendStatisticsResponse(TypedDict, total=False):
    """Represents a list of data points. This list contains aggregated data
    from the previous two weeks of your sending activity with Amazon SES.
    """

    SendDataPoints: Optional[SendDataPointList]


class GetTemplateRequest(ServiceRequest):
    TemplateName: TemplateName


class GetTemplateResponse(TypedDict, total=False):
    Template: Optional[Template]


class ListConfigurationSetsRequest(ServiceRequest):
    """Represents a request to list the configuration sets associated with your
    AWS account. Configuration sets enable you to publish email sending
    events. For information about using configuration sets, see the `Amazon
    SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    NextToken: Optional[NextToken]
    MaxItems: Optional[MaxItems]


class ListConfigurationSetsResponse(TypedDict, total=False):
    """A list of configuration sets associated with your AWS account.
    Configuration sets enable you to publish email sending events. For
    information about using configuration sets, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    ConfigurationSets: Optional[ConfigurationSets]
    NextToken: Optional[NextToken]


class ListCustomVerificationEmailTemplatesRequest(ServiceRequest):
    """Represents a request to list the existing custom verification email
    templates for your account.

    For more information about custom verification email templates, see
    `Using Custom Verification Email
    Templates <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/custom-verification-emails.html>`__
    in the *Amazon SES Developer Guide*.
    """

    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListCustomVerificationEmailTemplatesResponse(TypedDict, total=False):
    """A paginated list of custom verification email templates."""

    CustomVerificationEmailTemplates: Optional[CustomVerificationEmailTemplates]
    NextToken: Optional[NextToken]


class ListIdentitiesRequest(ServiceRequest):
    """Represents a request to return a list of all identities (email addresses
    and domains) that you have attempted to verify under your AWS account,
    regardless of verification status.
    """

    IdentityType: Optional[IdentityType]
    NextToken: Optional[NextToken]
    MaxItems: Optional[MaxItems]


class ListIdentitiesResponse(TypedDict, total=False):
    """A list of all identities that you have attempted to verify under your
    AWS account, regardless of verification status.
    """

    Identities: IdentityList
    NextToken: Optional[NextToken]


class ListIdentityPoliciesRequest(ServiceRequest):
    """Represents a request to return a list of sending authorization policies
    that are attached to an identity. Sending authorization is an Amazon SES
    feature that enables you to authorize other senders to use your
    identities. For information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__.
    """

    Identity: Identity


class ListIdentityPoliciesResponse(TypedDict, total=False):
    """A list of names of sending authorization policies that apply to an
    identity.
    """

    PolicyNames: PolicyNameList


class ListReceiptFiltersRequest(ServiceRequest):
    """Represents a request to list the IP address filters that exist under
    your AWS account. You use IP address filters when you receive email with
    Amazon SES. For more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """


ReceiptFilterList = List[ReceiptFilter]


class ListReceiptFiltersResponse(TypedDict, total=False):
    """A list of IP address filters that exist under your AWS account."""

    Filters: Optional[ReceiptFilterList]


class ListReceiptRuleSetsRequest(ServiceRequest):
    """Represents a request to list the receipt rule sets that exist under your
    AWS account. You use receipt rule sets to receive email with Amazon SES.
    For more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    NextToken: Optional[NextToken]


ReceiptRuleSetsLists = List[ReceiptRuleSetMetadata]


class ListReceiptRuleSetsResponse(TypedDict, total=False):
    """A list of receipt rule sets that exist under your AWS account."""

    RuleSets: Optional[ReceiptRuleSetsLists]
    NextToken: Optional[NextToken]


class ListTemplatesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxItems: Optional[MaxItems]


class TemplateMetadata(TypedDict, total=False):
    """Contains information about an email template."""

    Name: Optional[TemplateName]
    CreatedTimestamp: Optional[Timestamp]


TemplateMetadataList = List[TemplateMetadata]


class ListTemplatesResponse(TypedDict, total=False):
    TemplatesMetadata: Optional[TemplateMetadataList]
    NextToken: Optional[NextToken]


class ListVerifiedEmailAddressesResponse(TypedDict, total=False):
    """A list of email addresses that you have verified with Amazon SES under
    your AWS account.
    """

    VerifiedEmailAddresses: Optional[AddressList]


class Message(TypedDict, total=False):
    """Represents the message to be sent, composed of a subject and a body."""

    Subject: Content
    Body: Body


class MessageDsn(TypedDict, total=False):
    """Message-related information to include in the Delivery Status
    Notification (DSN) when an email that Amazon SES receives on your behalf
    bounces.

    For information about receiving email through Amazon SES, see the
    `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email.html>`__.
    """

    ReportingMta: ReportingMta
    ArrivalDate: Optional[ArrivalDate]
    ExtensionFields: Optional[ExtensionFieldList]


class PutConfigurationSetDeliveryOptionsRequest(ServiceRequest):
    """A request to modify the delivery options for a configuration set."""

    ConfigurationSetName: ConfigurationSetName
    DeliveryOptions: Optional[DeliveryOptions]


class PutConfigurationSetDeliveryOptionsResponse(TypedDict, total=False):
    """An HTTP 200 response if the request succeeds, or an error message if the
    request fails.
    """


class PutIdentityPolicyRequest(ServiceRequest):
    """Represents a request to add or update a sending authorization policy for
    an identity. Sending authorization is an Amazon SES feature that enables
    you to authorize other senders to use your identities. For information,
    see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__.
    """

    Identity: Identity
    PolicyName: PolicyName
    Policy: Policy


class PutIdentityPolicyResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


RawMessageData = bytes


class RawMessage(TypedDict, total=False):
    """Represents the raw data of the message."""

    Data: RawMessageData


ReceiptRuleNamesList = List[ReceiptRuleName]


class ReorderReceiptRuleSetRequest(ServiceRequest):
    """Represents a request to reorder the receipt rules within a receipt rule
    set. You use receipt rule sets to receive email with Amazon SES. For
    more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName
    RuleNames: ReceiptRuleNamesList


class ReorderReceiptRuleSetResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SendBounceRequest(ServiceRequest):
    """Represents a request to send a bounce message to the sender of an email
    you received through Amazon SES.
    """

    OriginalMessageId: MessageId
    BounceSender: Address
    Explanation: Optional[Explanation]
    MessageDsn: Optional[MessageDsn]
    BouncedRecipientInfoList: BouncedRecipientInfoList
    BounceSenderArn: Optional[AmazonResourceName]


class SendBounceResponse(TypedDict, total=False):
    """Represents a unique message ID."""

    MessageId: Optional[MessageId]


class SendBulkTemplatedEmailRequest(ServiceRequest):
    """Represents a request to send a templated email to multiple destinations
    using Amazon SES. For more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-personalized-email-api.html>`__.
    """

    Source: Address
    SourceArn: Optional[AmazonResourceName]
    ReplyToAddresses: Optional[AddressList]
    ReturnPath: Optional[Address]
    ReturnPathArn: Optional[AmazonResourceName]
    ConfigurationSetName: Optional[ConfigurationSetName]
    DefaultTags: Optional[MessageTagList]
    Template: TemplateName
    TemplateArn: Optional[AmazonResourceName]
    DefaultTemplateData: Optional[TemplateData]
    Destinations: BulkEmailDestinationList


class SendBulkTemplatedEmailResponse(TypedDict, total=False):
    Status: BulkEmailDestinationStatusList


class SendCustomVerificationEmailRequest(ServiceRequest):
    """Represents a request to send a custom verification email to a specified
    recipient.
    """

    EmailAddress: Address
    TemplateName: TemplateName
    ConfigurationSetName: Optional[ConfigurationSetName]


class SendCustomVerificationEmailResponse(TypedDict, total=False):
    """The response received when attempting to send the custom verification
    email.
    """

    MessageId: Optional[MessageId]


class SendEmailRequest(ServiceRequest):
    """Represents a request to send a single formatted email using Amazon SES.
    For more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-email-formatted.html>`__.
    """

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
    """Represents a unique message ID."""

    MessageId: MessageId


class SendRawEmailRequest(ServiceRequest):
    """Represents a request to send a single raw email using Amazon SES. For
    more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-email-raw.html>`__.
    """

    Source: Optional[Address]
    Destinations: Optional[AddressList]
    RawMessage: RawMessage
    FromArn: Optional[AmazonResourceName]
    SourceArn: Optional[AmazonResourceName]
    ReturnPathArn: Optional[AmazonResourceName]
    Tags: Optional[MessageTagList]
    ConfigurationSetName: Optional[ConfigurationSetName]


class SendRawEmailResponse(TypedDict, total=False):
    """Represents a unique message ID."""

    MessageId: MessageId


class SendTemplatedEmailRequest(ServiceRequest):
    """Represents a request to send a templated email using Amazon SES. For
    more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-personalized-email-api.html>`__.
    """

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
    """Represents a request to set a receipt rule set as the active receipt
    rule set. You use receipt rule sets to receive email with Amazon SES.
    For more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: Optional[ReceiptRuleSetName]


class SetActiveReceiptRuleSetResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SetIdentityDkimEnabledRequest(ServiceRequest):
    """Represents a request to enable or disable Amazon SES Easy DKIM signing
    for an identity. For more information about setting up Easy DKIM, see
    the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html>`__.
    """

    Identity: Identity
    DkimEnabled: Enabled


class SetIdentityDkimEnabledResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SetIdentityFeedbackForwardingEnabledRequest(ServiceRequest):
    """Represents a request to enable or disable whether Amazon SES forwards
    you bounce and complaint notifications through email. For information
    about email feedback forwarding, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notifications-via-email.html>`__.
    """

    Identity: Identity
    ForwardingEnabled: Enabled


class SetIdentityFeedbackForwardingEnabledResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SetIdentityHeadersInNotificationsEnabledRequest(ServiceRequest):
    """Represents a request to set whether Amazon SES includes the original
    email headers in the Amazon SNS notifications of a specified type. For
    information about notifications, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notifications-via-sns.html>`__.
    """

    Identity: Identity
    NotificationType: NotificationType
    Enabled: Enabled


class SetIdentityHeadersInNotificationsEnabledResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SetIdentityMailFromDomainRequest(ServiceRequest):
    """Represents a request to enable or disable the Amazon SES custom MAIL
    FROM domain setup for a verified identity. For information about using a
    custom MAIL FROM domain, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/mail-from.html>`__.
    """

    Identity: Identity
    MailFromDomain: Optional[MailFromDomainName]
    BehaviorOnMXFailure: Optional[BehaviorOnMXFailure]


class SetIdentityMailFromDomainResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SetIdentityNotificationTopicRequest(ServiceRequest):
    """Represents a request to specify the Amazon SNS topic to which Amazon SES
    will publish bounce, complaint, or delivery notifications for emails
    sent with that identity as the Source. For information about Amazon SES
    notifications, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notifications-via-sns.html>`__.
    """

    Identity: Identity
    NotificationType: NotificationType
    SnsTopic: Optional[NotificationTopic]


class SetIdentityNotificationTopicResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SetReceiptRulePositionRequest(ServiceRequest):
    """Represents a request to set the position of a receipt rule in a receipt
    rule set. You use receipt rule sets to receive email with Amazon SES.
    For more information, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName
    RuleName: ReceiptRuleName
    After: Optional[ReceiptRuleName]


class SetReceiptRulePositionResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class TestRenderTemplateRequest(ServiceRequest):
    TemplateName: TemplateName
    TemplateData: TemplateData


class TestRenderTemplateResponse(TypedDict, total=False):
    RenderedTemplate: Optional[RenderedTemplate]


class UpdateAccountSendingEnabledRequest(ServiceRequest):
    """Represents a request to enable or disable the email sending capabilities
    for your entire Amazon SES account.
    """

    Enabled: Optional[Enabled]


class UpdateConfigurationSetEventDestinationRequest(ServiceRequest):
    """Represents a request to update the event destination of a configuration
    set. Configuration sets enable you to publish email sending events. For
    information about using configuration sets, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.
    """

    ConfigurationSetName: ConfigurationSetName
    EventDestination: EventDestination


class UpdateConfigurationSetEventDestinationResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class UpdateConfigurationSetReputationMetricsEnabledRequest(ServiceRequest):
    """Represents a request to modify the reputation metric publishing settings
    for a configuration set.
    """

    ConfigurationSetName: ConfigurationSetName
    Enabled: Enabled


class UpdateConfigurationSetSendingEnabledRequest(ServiceRequest):
    """Represents a request to enable or disable the email sending capabilities
    for a specific configuration set.
    """

    ConfigurationSetName: ConfigurationSetName
    Enabled: Enabled


class UpdateConfigurationSetTrackingOptionsRequest(ServiceRequest):
    """Represents a request to update the tracking options for a configuration
    set.
    """

    ConfigurationSetName: ConfigurationSetName
    TrackingOptions: TrackingOptions


class UpdateConfigurationSetTrackingOptionsResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class UpdateCustomVerificationEmailTemplateRequest(ServiceRequest):
    """Represents a request to update an existing custom verification email
    template.
    """

    TemplateName: TemplateName
    FromEmailAddress: Optional[FromAddress]
    TemplateSubject: Optional[Subject]
    TemplateContent: Optional[TemplateContent]
    SuccessRedirectionURL: Optional[SuccessRedirectionURL]
    FailureRedirectionURL: Optional[FailureRedirectionURL]


class UpdateReceiptRuleRequest(ServiceRequest):
    """Represents a request to update a receipt rule. You use receipt rules to
    receive email with Amazon SES. For more information, see the `Amazon SES
    Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-concepts.html>`__.
    """

    RuleSetName: ReceiptRuleSetName
    Rule: ReceiptRule


class UpdateReceiptRuleResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class UpdateTemplateRequest(ServiceRequest):
    Template: Template


class UpdateTemplateResponse(TypedDict, total=False):
    pass


class VerifyDomainDkimRequest(ServiceRequest):
    """Represents a request to generate the CNAME records needed to set up Easy
    DKIM with Amazon SES. For more information about setting up Easy DKIM,
    see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html>`__.
    """

    Domain: Domain


class VerifyDomainDkimResponse(TypedDict, total=False):
    """Returns CNAME records that you must publish to the DNS server of your
    domain to set up Easy DKIM with Amazon SES.
    """

    DkimTokens: VerificationTokenList


class VerifyDomainIdentityRequest(ServiceRequest):
    """Represents a request to begin Amazon SES domain verification and to
    generate the TXT records that you must publish to the DNS server of your
    domain to complete the verification. For information about domain
    verification, see the `Amazon SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-domains.html>`__.
    """

    Domain: Domain


class VerifyDomainIdentityResponse(TypedDict, total=False):
    """Returns a TXT record that you must publish to the DNS server of your
    domain to complete domain verification with Amazon SES.
    """

    VerificationToken: VerificationToken


class VerifyEmailAddressRequest(ServiceRequest):
    """Represents a request to begin email address verification with Amazon
    SES. For information about email address verification, see the `Amazon
    SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-email-addresses.html>`__.
    """

    EmailAddress: Address


class VerifyEmailIdentityRequest(ServiceRequest):
    """Represents a request to begin email address verification with Amazon
    SES. For information about email address verification, see the `Amazon
    SES Developer
    Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-email-addresses.html>`__.
    """

    EmailAddress: Address


class VerifyEmailIdentityResponse(TypedDict, total=False):
    """An empty element returned on a successful request."""


class SesApi:

    service = "ses"
    version = "2010-12-01"

    @handler("CloneReceiptRuleSet")
    def clone_receipt_rule_set(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        original_rule_set_name: ReceiptRuleSetName,
    ) -> CloneReceiptRuleSetResponse:
        """Creates a receipt rule set by cloning an existing one. All receipt rules
        and configurations are copied to the new receipt rule set and are
        completely independent of the source rule set.

        For information about setting up rule sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-receipt-rule-set.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the rule set to create.
        :param original_rule_set_name: The name of the rule set to clone.
        :returns: CloneReceiptRuleSetResponse
        :raises RuleSetDoesNotExistException:
        :raises AlreadyExistsException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("CreateConfigurationSet")
    def create_configuration_set(
        self, context: RequestContext, configuration_set: ConfigurationSet
    ) -> CreateConfigurationSetResponse:
        """Creates a configuration set.

        Configuration sets enable you to publish email sending events. For
        information about using configuration sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.

        You can execute this operation no more than once per second.

        :param configuration_set: A data structure that contains the name of the configuration set.
        :returns: CreateConfigurationSetResponse
        :raises ConfigurationSetAlreadyExistsException:
        :raises InvalidConfigurationSetException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("CreateConfigurationSetEventDestination")
    def create_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination: EventDestination,
    ) -> CreateConfigurationSetEventDestinationResponse:
        """Creates a configuration set event destination.

        When you create or update an event destination, you must provide one,
        and only one, destination. The destination can be CloudWatch, Amazon
        Kinesis Firehose, or Amazon Simple Notification Service (Amazon SNS).

        An event destination is the AWS service to which Amazon SES publishes
        the email sending events associated with a configuration set. For
        information about using configuration sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.

        You can execute this operation no more than once per second.

        :param configuration_set_name: The name of the configuration set that the event destination should be
        associated with.
        :param event_destination: An object that describes the AWS service that email sending event
        information will be published to.
        :returns: CreateConfigurationSetEventDestinationResponse
        :raises ConfigurationSetDoesNotExistException:
        :raises EventDestinationAlreadyExistsException:
        :raises InvalidCloudWatchDestinationException:
        :raises InvalidFirehoseDestinationException:
        :raises InvalidSNSDestinationException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("CreateConfigurationSetTrackingOptions")
    def create_configuration_set_tracking_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        tracking_options: TrackingOptions,
    ) -> CreateConfigurationSetTrackingOptionsResponse:
        """Creates an association between a configuration set and a custom domain
        for open and click event tracking.

        By default, images and links used for tracking open and click events are
        hosted on domains operated by Amazon SES. You can configure a subdomain
        of your own to handle these events. For information about using custom
        domains, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/configure-custom-open-click-domains.html>`__.

        :param configuration_set_name: The name of the configuration set that the tracking options should be
        associated with.
        :param tracking_options: A domain that is used to redirect email recipients to an Amazon
        SES-operated domain.
        :returns: CreateConfigurationSetTrackingOptionsResponse
        :raises ConfigurationSetDoesNotExistException:
        :raises TrackingOptionsAlreadyExistsException:
        :raises InvalidTrackingOptionsException:
        """
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
    ) -> None:
        """Creates a new custom verification email template.

        For more information about custom verification email templates, see
        `Using Custom Verification Email
        Templates <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/custom-verification-emails.html>`__
        in the *Amazon SES Developer Guide*.

        You can execute this operation no more than once per second.

        :param template_name: The name of the custom verification email template.
        :param from_email_address: The email address that the custom verification email is sent from.
        :param template_subject: The subject line of the custom verification email.
        :param template_content: The content of the custom verification email.
        :param success_redirection_url: The URL that the recipient of the verification email is sent to if his
        or her address is successfully verified.
        :param failure_redirection_url: The URL that the recipient of the verification email is sent to if his
        or her address is not successfully verified.
        :raises CustomVerificationEmailTemplateAlreadyExistsException:
        :raises FromEmailAddressNotVerifiedException:
        :raises CustomVerificationEmailInvalidContentException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("CreateReceiptFilter")
    def create_receipt_filter(
        self, context: RequestContext, filter: ReceiptFilter
    ) -> CreateReceiptFilterResponse:
        """Creates a new IP address filter.

        For information about setting up IP address filters, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-ip-filters.html>`__.

        You can execute this operation no more than once per second.

        :param filter: A data structure that describes the IP address filter to create, which
        consists of a name, an IP address range, and whether to allow or block
        mail from it.
        :returns: CreateReceiptFilterResponse
        :raises LimitExceededException:
        :raises AlreadyExistsException:
        """
        raise NotImplementedError

    @handler("CreateReceiptRule")
    def create_receipt_rule(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule: ReceiptRule,
        after: ReceiptRuleName = None,
    ) -> CreateReceiptRuleResponse:
        """Creates a receipt rule.

        For information about setting up receipt rules, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-receipt-rules.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the rule set that the receipt rule will be added to.
        :param rule: A data structure that contains the specified rule's name, actions,
        recipients, domains, enabled status, scan status, and TLS policy.
        :param after: The name of an existing rule after which the new rule will be placed.
        :returns: CreateReceiptRuleResponse
        :raises InvalidSnsTopicException:
        :raises InvalidS3ConfigurationException:
        :raises InvalidLambdaFunctionException:
        :raises AlreadyExistsException:
        :raises RuleDoesNotExistException:
        :raises RuleSetDoesNotExistException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("CreateReceiptRuleSet")
    def create_receipt_rule_set(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName
    ) -> CreateReceiptRuleSetResponse:
        """Creates an empty receipt rule set.

        For information about setting up receipt rule sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-receipt-rule-set.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the rule set to create.
        :returns: CreateReceiptRuleSetResponse
        :raises AlreadyExistsException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("CreateTemplate")
    def create_template(
        self, context: RequestContext, template: Template
    ) -> CreateTemplateResponse:
        """Creates an email template. Email templates enable you to send
        personalized email to one or more destinations in a single API
        operation. For more information, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-personalized-email-api.html>`__.

        You can execute this operation no more than once per second.

        :param template: The content of the email, composed of a subject line, an HTML part, and
        a text-only part.
        :returns: CreateTemplateResponse
        :raises AlreadyExistsException:
        :raises InvalidTemplateException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("DeleteConfigurationSet")
    def delete_configuration_set(
        self, context: RequestContext, configuration_set_name: ConfigurationSetName
    ) -> DeleteConfigurationSetResponse:
        """Deletes a configuration set. Configuration sets enable you to publish
        email sending events. For information about using configuration sets,
        see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.

        You can execute this operation no more than once per second.

        :param configuration_set_name: The name of the configuration set to delete.
        :returns: DeleteConfigurationSetResponse
        :raises ConfigurationSetDoesNotExistException:
        """
        raise NotImplementedError

    @handler("DeleteConfigurationSetEventDestination")
    def delete_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination_name: EventDestinationName,
    ) -> DeleteConfigurationSetEventDestinationResponse:
        """Deletes a configuration set event destination. Configuration set event
        destinations are associated with configuration sets, which enable you to
        publish email sending events. For information about using configuration
        sets, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.

        You can execute this operation no more than once per second.

        :param configuration_set_name: The name of the configuration set from which to delete the event
        destination.
        :param event_destination_name: The name of the event destination to delete.
        :returns: DeleteConfigurationSetEventDestinationResponse
        :raises ConfigurationSetDoesNotExistException:
        :raises EventDestinationDoesNotExistException:
        """
        raise NotImplementedError

    @handler("DeleteConfigurationSetTrackingOptions")
    def delete_configuration_set_tracking_options(
        self, context: RequestContext, configuration_set_name: ConfigurationSetName
    ) -> DeleteConfigurationSetTrackingOptionsResponse:
        """Deletes an association between a configuration set and a custom domain
        for open and click event tracking.

        By default, images and links used for tracking open and click events are
        hosted on domains operated by Amazon SES. You can configure a subdomain
        of your own to handle these events. For information about using custom
        domains, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/configure-custom-open-click-domains.html>`__.

        Deleting this kind of association will result in emails sent using the
        specified configuration set to capture open and click events using the
        standard, Amazon SES-operated domains.

        :param configuration_set_name: The name of the configuration set from which you want to delete the
        tracking options.
        :returns: DeleteConfigurationSetTrackingOptionsResponse
        :raises ConfigurationSetDoesNotExistException:
        :raises TrackingOptionsDoesNotExistException:
        """
        raise NotImplementedError

    @handler("DeleteCustomVerificationEmailTemplate")
    def delete_custom_verification_email_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> None:
        """Deletes an existing custom verification email template.

        For more information about custom verification email templates, see
        `Using Custom Verification Email
        Templates <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/custom-verification-emails.html>`__
        in the *Amazon SES Developer Guide*.

        You can execute this operation no more than once per second.

        :param template_name: The name of the custom verification email template that you want to
        delete.
        """
        raise NotImplementedError

    @handler("DeleteIdentity")
    def delete_identity(
        self, context: RequestContext, identity: Identity
    ) -> DeleteIdentityResponse:
        """Deletes the specified identity (an email address or a domain) from the
        list of verified identities.

        You can execute this operation no more than once per second.

        :param identity: The identity to be removed from the list of identities for the AWS
        Account.
        :returns: DeleteIdentityResponse
        """
        raise NotImplementedError

    @handler("DeleteIdentityPolicy")
    def delete_identity_policy(
        self, context: RequestContext, identity: Identity, policy_name: PolicyName
    ) -> DeleteIdentityPolicyResponse:
        """Deletes the specified sending authorization policy for the given
        identity (an email address or a domain). This API returns successfully
        even if a policy with the specified name does not exist.

        This API is for the identity owner only. If you have not verified the
        identity, this API will return an error.

        Sending authorization is a feature that enables an identity owner to
        authorize other senders to use its identities. For information about
        using sending authorization, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__.

        You can execute this operation no more than once per second.

        :param identity: The identity that is associated with the policy that you want to delete.
        :param policy_name: The name of the policy to be deleted.
        :returns: DeleteIdentityPolicyResponse
        """
        raise NotImplementedError

    @handler("DeleteReceiptFilter")
    def delete_receipt_filter(
        self, context: RequestContext, filter_name: ReceiptFilterName
    ) -> DeleteReceiptFilterResponse:
        """Deletes the specified IP address filter.

        For information about managing IP address filters, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-ip-filters.html>`__.

        You can execute this operation no more than once per second.

        :param filter_name: The name of the IP address filter to delete.
        :returns: DeleteReceiptFilterResponse
        """
        raise NotImplementedError

    @handler("DeleteReceiptRule")
    def delete_receipt_rule(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName, rule_name: ReceiptRuleName
    ) -> DeleteReceiptRuleResponse:
        """Deletes the specified receipt rule.

        For information about managing receipt rules, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-receipt-rules.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the receipt rule set that contains the receipt rule to
        delete.
        :param rule_name: The name of the receipt rule to delete.
        :returns: DeleteReceiptRuleResponse
        :raises RuleSetDoesNotExistException:
        """
        raise NotImplementedError

    @handler("DeleteReceiptRuleSet")
    def delete_receipt_rule_set(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName
    ) -> DeleteReceiptRuleSetResponse:
        """Deletes the specified receipt rule set and all of the receipt rules it
        contains.

        The currently active rule set cannot be deleted.

        For information about managing receipt rule sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-receipt-rule-sets.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the receipt rule set to delete.
        :returns: DeleteReceiptRuleSetResponse
        :raises CannotDeleteException:
        """
        raise NotImplementedError

    @handler("DeleteTemplate")
    def delete_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> DeleteTemplateResponse:
        """Deletes an email template.

        You can execute this operation no more than once per second.

        :param template_name: The name of the template to be deleted.
        :returns: DeleteTemplateResponse
        """
        raise NotImplementedError

    @handler("DeleteVerifiedEmailAddress")
    def delete_verified_email_address(
        self, context: RequestContext, email_address: Address
    ) -> None:
        """Deprecated. Use the ``DeleteIdentity`` operation to delete email
        addresses and domains.

        :param email_address: An email address to be removed from the list of verified addresses.
        """
        raise NotImplementedError

    @handler("DescribeActiveReceiptRuleSet")
    def describe_active_receipt_rule_set(
        self,
        context: RequestContext,
    ) -> DescribeActiveReceiptRuleSetResponse:
        """Returns the metadata and receipt rules for the receipt rule set that is
        currently active.

        For information about setting up receipt rule sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-receipt-rule-set.html>`__.

        You can execute this operation no more than once per second.

        :returns: DescribeActiveReceiptRuleSetResponse
        """
        raise NotImplementedError

    @handler("DescribeConfigurationSet")
    def describe_configuration_set(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        configuration_set_attribute_names: ConfigurationSetAttributeList = None,
    ) -> DescribeConfigurationSetResponse:
        """Returns the details of the specified configuration set. For information
        about using configuration sets, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__.

        You can execute this operation no more than once per second.

        :param configuration_set_name: The name of the configuration set to describe.
        :param configuration_set_attribute_names: A list of configuration set attributes to return.
        :returns: DescribeConfigurationSetResponse
        :raises ConfigurationSetDoesNotExistException:
        """
        raise NotImplementedError

    @handler("DescribeReceiptRule")
    def describe_receipt_rule(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName, rule_name: ReceiptRuleName
    ) -> DescribeReceiptRuleResponse:
        """Returns the details of the specified receipt rule.

        For information about setting up receipt rules, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-receipt-rules.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the receipt rule set that the receipt rule belongs to.
        :param rule_name: The name of the receipt rule.
        :returns: DescribeReceiptRuleResponse
        :raises RuleDoesNotExistException:
        :raises RuleSetDoesNotExistException:
        """
        raise NotImplementedError

    @handler("DescribeReceiptRuleSet")
    def describe_receipt_rule_set(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName
    ) -> DescribeReceiptRuleSetResponse:
        """Returns the details of the specified receipt rule set.

        For information about managing receipt rule sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-receipt-rule-sets.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the receipt rule set to describe.
        :returns: DescribeReceiptRuleSetResponse
        :raises RuleSetDoesNotExistException:
        """
        raise NotImplementedError

    @handler("GetAccountSendingEnabled")
    def get_account_sending_enabled(
        self,
        context: RequestContext,
    ) -> GetAccountSendingEnabledResponse:
        """Returns the email sending status of the Amazon SES account for the
        current region.

        You can execute this operation no more than once per second.

        :returns: GetAccountSendingEnabledResponse
        """
        raise NotImplementedError

    @handler("GetCustomVerificationEmailTemplate")
    def get_custom_verification_email_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> GetCustomVerificationEmailTemplateResponse:
        """Returns the custom email verification template for the template name you
        specify.

        For more information about custom verification email templates, see
        `Using Custom Verification Email
        Templates <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/custom-verification-emails.html>`__
        in the *Amazon SES Developer Guide*.

        You can execute this operation no more than once per second.

        :param template_name: The name of the custom verification email template that you want to
        retrieve.
        :returns: GetCustomVerificationEmailTemplateResponse
        :raises CustomVerificationEmailTemplateDoesNotExistException:
        """
        raise NotImplementedError

    @handler("GetIdentityDkimAttributes")
    def get_identity_dkim_attributes(
        self, context: RequestContext, identities: IdentityList
    ) -> GetIdentityDkimAttributesResponse:
        """Returns the current status of Easy DKIM signing for an entity. For
        domain name identities, this operation also returns the DKIM tokens that
        are required for Easy DKIM signing, and whether Amazon SES has
        successfully verified that these tokens have been published.

        This operation takes a list of identities as input and returns the
        following information for each:

        -  Whether Easy DKIM signing is enabled or disabled.

        -  A set of DKIM tokens that represent the identity. If the identity is
           an email address, the tokens represent the domain of that address.

        -  Whether Amazon SES has successfully verified the DKIM tokens
           published in the domain's DNS. This information is only returned for
           domain name identities, not for email addresses.

        This operation is throttled at one request per second and can only get
        DKIM attributes for up to 100 identities at a time.

        For more information about creating DNS records using DKIM tokens, go to
        the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim-dns-records.html>`__.

        :param identities: A list of one or more verified identities - email addresses, domains, or
        both.
        :returns: GetIdentityDkimAttributesResponse
        """
        raise NotImplementedError

    @handler("GetIdentityMailFromDomainAttributes")
    def get_identity_mail_from_domain_attributes(
        self, context: RequestContext, identities: IdentityList
    ) -> GetIdentityMailFromDomainAttributesResponse:
        """Returns the custom MAIL FROM attributes for a list of identities (email
        addresses : domains).

        This operation is throttled at one request per second and can only get
        custom MAIL FROM attributes for up to 100 identities at a time.

        :param identities: A list of one or more identities.
        :returns: GetIdentityMailFromDomainAttributesResponse
        """
        raise NotImplementedError

    @handler("GetIdentityNotificationAttributes")
    def get_identity_notification_attributes(
        self, context: RequestContext, identities: IdentityList
    ) -> GetIdentityNotificationAttributesResponse:
        """Given a list of verified identities (email addresses and/or domains),
        returns a structure describing identity notification attributes.

        This operation is throttled at one request per second and can only get
        notification attributes for up to 100 identities at a time.

        For more information about using notifications with Amazon SES, see the
        `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notifications.html>`__.

        :param identities: A list of one or more identities.
        :returns: GetIdentityNotificationAttributesResponse
        """
        raise NotImplementedError

    @handler("GetIdentityPolicies")
    def get_identity_policies(
        self, context: RequestContext, identity: Identity, policy_names: PolicyNameList
    ) -> GetIdentityPoliciesResponse:
        """Returns the requested sending authorization policies for the given
        identity (an email address or a domain). The policies are returned as a
        map of policy names to policy contents. You can retrieve a maximum of 20
        policies at a time.

        This API is for the identity owner only. If you have not verified the
        identity, this API will return an error.

        Sending authorization is a feature that enables an identity owner to
        authorize other senders to use its identities. For information about
        using sending authorization, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__.

        You can execute this operation no more than once per second.

        :param identity: The identity for which the policies will be retrieved.
        :param policy_names: A list of the names of policies to be retrieved.
        :returns: GetIdentityPoliciesResponse
        """
        raise NotImplementedError

    @handler("GetIdentityVerificationAttributes")
    def get_identity_verification_attributes(
        self, context: RequestContext, identities: IdentityList
    ) -> GetIdentityVerificationAttributesResponse:
        """Given a list of identities (email addresses and/or domains), returns the
        verification status and (for domain identities) the verification token
        for each identity.

        The verification status of an email address is "Pending" until the email
        address owner clicks the link within the verification email that Amazon
        SES sent to that address. If the email address owner clicks the link
        within 24 hours, the verification status of the email address changes to
        "Success". If the link is not clicked within 24 hours, the verification
        status changes to "Failed." In that case, if you still want to verify
        the email address, you must restart the verification process from the
        beginning.

        For domain identities, the domain's verification status is "Pending" as
        Amazon SES searches for the required TXT record in the DNS settings of
        the domain. When Amazon SES detects the record, the domain's
        verification status changes to "Success". If Amazon SES is unable to
        detect the record within 72 hours, the domain's verification status
        changes to "Failed." In that case, if you still want to verify the
        domain, you must restart the verification process from the beginning.

        This operation is throttled at one request per second and can only get
        verification attributes for up to 100 identities at a time.

        :param identities: A list of identities.
        :returns: GetIdentityVerificationAttributesResponse
        """
        raise NotImplementedError

    @handler("GetSendQuota")
    def get_send_quota(
        self,
        context: RequestContext,
    ) -> GetSendQuotaResponse:
        """Provides the sending limits for the Amazon SES account.

        You can execute this operation no more than once per second.

        :returns: GetSendQuotaResponse
        """
        raise NotImplementedError

    @handler("GetSendStatistics")
    def get_send_statistics(
        self,
        context: RequestContext,
    ) -> GetSendStatisticsResponse:
        """Provides sending statistics for the current AWS Region. The result is a
        list of data points, representing the last two weeks of sending
        activity. Each data point in the list contains statistics for a
        15-minute period of time.

        You can execute this operation no more than once per second.

        :returns: GetSendStatisticsResponse
        """
        raise NotImplementedError

    @handler("GetTemplate")
    def get_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> GetTemplateResponse:
        """Displays the template object (which includes the Subject line, HTML part
        and text part) for the template you specify.

        You can execute this operation no more than once per second.

        :param template_name: The name of the template you want to retrieve.
        :returns: GetTemplateResponse
        :raises TemplateDoesNotExistException:
        """
        raise NotImplementedError

    @handler("ListConfigurationSets")
    def list_configuration_sets(
        self, context: RequestContext, next_token: NextToken = None, max_items: MaxItems = None
    ) -> ListConfigurationSetsResponse:
        """Provides a list of the configuration sets associated with your Amazon
        SES account in the current AWS Region. For information about using
        configuration sets, see `Monitoring Your Amazon SES Sending
        Activity <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__
        in the *Amazon SES Developer Guide.*

        You can execute this operation no more than once per second. This
        operation will return up to 1,000 configuration sets each time it is
        run. If your Amazon SES account has more than 1,000 configuration sets,
        this operation will also return a NextToken element. You can then
        execute the ``ListConfigurationSets`` operation again, passing the
        ``NextToken`` parameter and the value of the NextToken element to
        retrieve additional results.

        :param next_token: A token returned from a previous call to ``ListConfigurationSets`` to
        indicate the position of the configuration set in the configuration set
        list.
        :param max_items: The number of configuration sets to return.
        :returns: ListConfigurationSetsResponse
        """
        raise NotImplementedError

    @handler("ListCustomVerificationEmailTemplates")
    def list_custom_verification_email_templates(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListCustomVerificationEmailTemplatesResponse:
        """Lists the existing custom verification email templates for your account
        in the current AWS Region.

        For more information about custom verification email templates, see
        `Using Custom Verification Email
        Templates <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/custom-verification-emails.html>`__
        in the *Amazon SES Developer Guide*.

        You can execute this operation no more than once per second.

        :param next_token: An array the contains the name and creation time stamp for each template
        in your Amazon SES account.
        :param max_results: The maximum number of custom verification email templates to return.
        :returns: ListCustomVerificationEmailTemplatesResponse
        """
        raise NotImplementedError

    @handler("ListIdentities")
    def list_identities(
        self,
        context: RequestContext,
        identity_type: IdentityType = None,
        next_token: NextToken = None,
        max_items: MaxItems = None,
    ) -> ListIdentitiesResponse:
        """Returns a list containing all of the identities (email addresses and
        domains) for your AWS account in the current AWS Region, regardless of
        verification status.

        You can execute this operation no more than once per second.

        :param identity_type: The type of the identities to list.
        :param next_token: The token to use for pagination.
        :param max_items: The maximum number of identities per page.
        :returns: ListIdentitiesResponse
        """
        raise NotImplementedError

    @handler("ListIdentityPolicies")
    def list_identity_policies(
        self, context: RequestContext, identity: Identity
    ) -> ListIdentityPoliciesResponse:
        """Returns a list of sending authorization policies that are attached to
        the given identity (an email address or a domain). This API returns only
        a list. If you want the actual policy content, you can use
        ``GetIdentityPolicies``.

        This API is for the identity owner only. If you have not verified the
        identity, this API will return an error.

        Sending authorization is a feature that enables an identity owner to
        authorize other senders to use its identities. For information about
        using sending authorization, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__.

        You can execute this operation no more than once per second.

        :param identity: The identity that is associated with the policy for which the policies
        will be listed.
        :returns: ListIdentityPoliciesResponse
        """
        raise NotImplementedError

    @handler("ListReceiptFilters")
    def list_receipt_filters(
        self,
        context: RequestContext,
    ) -> ListReceiptFiltersResponse:
        """Lists the IP address filters associated with your AWS account in the
        current AWS Region.

        For information about managing IP address filters, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-ip-filters.html>`__.

        You can execute this operation no more than once per second.

        :returns: ListReceiptFiltersResponse
        """
        raise NotImplementedError

    @handler("ListReceiptRuleSets")
    def list_receipt_rule_sets(
        self, context: RequestContext, next_token: NextToken = None
    ) -> ListReceiptRuleSetsResponse:
        """Lists the receipt rule sets that exist under your AWS account in the
        current AWS Region. If there are additional receipt rule sets to be
        retrieved, you will receive a ``NextToken`` that you can provide to the
        next call to ``ListReceiptRuleSets`` to retrieve the additional entries.

        For information about managing receipt rule sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-receipt-rule-sets.html>`__.

        You can execute this operation no more than once per second.

        :param next_token: A token returned from a previous call to ``ListReceiptRuleSets`` to
        indicate the position in the receipt rule set list.
        :returns: ListReceiptRuleSetsResponse
        """
        raise NotImplementedError

    @handler("ListTemplates")
    def list_templates(
        self, context: RequestContext, next_token: NextToken = None, max_items: MaxItems = None
    ) -> ListTemplatesResponse:
        """Lists the email templates present in your Amazon SES account in the
        current AWS Region.

        You can execute this operation no more than once per second.

        :param next_token: A token returned from a previous call to ``ListTemplates`` to indicate
        the position in the list of email templates.
        :param max_items: The maximum number of templates to return.
        :returns: ListTemplatesResponse
        """
        raise NotImplementedError

    @handler("ListVerifiedEmailAddresses")
    def list_verified_email_addresses(
        self,
        context: RequestContext,
    ) -> ListVerifiedEmailAddressesResponse:
        """Deprecated. Use the ``ListIdentities`` operation to list the email
        addresses and domains associated with your account.

        :returns: ListVerifiedEmailAddressesResponse
        """
        raise NotImplementedError

    @handler("PutConfigurationSetDeliveryOptions")
    def put_configuration_set_delivery_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        delivery_options: DeliveryOptions = None,
    ) -> PutConfigurationSetDeliveryOptionsResponse:
        """Adds or updates the delivery options for a configuration set.

        :param configuration_set_name: The name of the configuration set that you want to specify the delivery
        options for.
        :param delivery_options: Specifies whether messages that use the configuration set are required
        to use Transport Layer Security (TLS).
        :returns: PutConfigurationSetDeliveryOptionsResponse
        :raises ConfigurationSetDoesNotExistException:
        :raises InvalidDeliveryOptionsException:
        """
        raise NotImplementedError

    @handler("PutIdentityPolicy")
    def put_identity_policy(
        self, context: RequestContext, identity: Identity, policy_name: PolicyName, policy: Policy
    ) -> PutIdentityPolicyResponse:
        """Adds or updates a sending authorization policy for the specified
        identity (an email address or a domain).

        This API is for the identity owner only. If you have not verified the
        identity, this API will return an error.

        Sending authorization is a feature that enables an identity owner to
        authorize other senders to use its identities. For information about
        using sending authorization, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__.

        You can execute this operation no more than once per second.

        :param identity: The identity that the policy will apply to.
        :param policy_name: The name of the policy.
        :param policy: The text of the policy in JSON format.
        :returns: PutIdentityPolicyResponse
        :raises InvalidPolicyException:
        """
        raise NotImplementedError

    @handler("ReorderReceiptRuleSet")
    def reorder_receipt_rule_set(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule_names: ReceiptRuleNamesList,
    ) -> ReorderReceiptRuleSetResponse:
        """Reorders the receipt rules within a receipt rule set.

        All of the rules in the rule set must be represented in this request.
        That is, this API will return an error if the reorder request doesn't
        explicitly position all of the rules.

        For information about managing receipt rule sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-receipt-rule-sets.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the receipt rule set to reorder.
        :param rule_names: A list of the specified receipt rule set's receipt rules in the order
        that you want to put them.
        :returns: ReorderReceiptRuleSetResponse
        :raises RuleSetDoesNotExistException:
        :raises RuleDoesNotExistException:
        """
        raise NotImplementedError

    @handler("SendBounce")
    def send_bounce(
        self,
        context: RequestContext,
        original_message_id: MessageId,
        bounce_sender: Address,
        bounced_recipient_info_list: BouncedRecipientInfoList,
        explanation: Explanation = None,
        message_dsn: MessageDsn = None,
        bounce_sender_arn: AmazonResourceName = None,
    ) -> SendBounceResponse:
        """Generates and sends a bounce message to the sender of an email you
        received through Amazon SES. You can only use this API on an email up to
        24 hours after you receive it.

        You cannot use this API to send generic bounces for mail that was not
        received by Amazon SES.

        For information about receiving email through Amazon SES, see the
        `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email.html>`__.

        You can execute this operation no more than once per second.

        :param original_message_id: The message ID of the message to be bounced.
        :param bounce_sender: The address to use in the "From" header of the bounce message.
        :param bounced_recipient_info_list: A list of recipients of the bounced message, including the information
        required to create the Delivery Status Notifications (DSNs) for the
        recipients.
        :param explanation: Human-readable text for the bounce message to explain the failure.
        :param message_dsn: Message-related DSN fields.
        :param bounce_sender_arn: This parameter is used only for sending authorization.
        :returns: SendBounceResponse
        :raises MessageRejected:
        """
        raise NotImplementedError

    @handler("SendBulkTemplatedEmail")
    def send_bulk_templated_email(
        self,
        context: RequestContext,
        source: Address,
        template: TemplateName,
        destinations: BulkEmailDestinationList,
        source_arn: AmazonResourceName = None,
        reply_to_addresses: AddressList = None,
        return_path: Address = None,
        return_path_arn: AmazonResourceName = None,
        configuration_set_name: ConfigurationSetName = None,
        default_tags: MessageTagList = None,
        template_arn: AmazonResourceName = None,
        default_template_data: TemplateData = None,
    ) -> SendBulkTemplatedEmailResponse:
        """Composes an email message to multiple destinations. The message body is
        created using an email template.

        In order to send email using the ``SendBulkTemplatedEmail`` operation,
        your call to the API must meet the following requirements:

        -  The call must refer to an existing email template. You can create
           email templates using the CreateTemplate operation.

        -  The message must be sent from a verified email address or domain.

        -  If your account is still in the Amazon SES sandbox, you may only send
           to verified addresses or domains, or to email addresses associated
           with the Amazon SES Mailbox Simulator. For more information, see
           `Verifying Email Addresses and
           Domains <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-addresses-and-domains.html>`__
           in the *Amazon SES Developer Guide.*

        -  The maximum message size is 10 MB.

        -  Each ``Destination`` parameter must include at least one recipient
           email address. The recipient address can be a To: address, a CC:
           address, or a BCC: address. If a recipient email address is invalid
           (that is, it is not in the format
           *UserName@[SubDomain.]Domain.TopLevelDomain*), the entire message
           will be rejected, even if the message contains other recipients that
           are valid.

        -  The message may not include more than 50 recipients, across the To:,
           CC: and BCC: fields. If you need to send an email message to a larger
           audience, you can divide your recipient list into groups of 50 or
           fewer, and then call the ``SendBulkTemplatedEmail`` operation several
           times to send the message to each group.

        -  The number of destinations you can contact in a single call to the
           API may be limited by your account's maximum sending rate.

        :param source: The email address that is sending the email.
        :param template: The template to use when sending this email.
        :param destinations: One or more ``Destination`` objects.
        :param source_arn: This parameter is used only for sending authorization.
        :param reply_to_addresses: The reply-to email address(es) for the message.
        :param return_path: The email address that bounces and complaints will be forwarded to when
        feedback forwarding is enabled.
        :param return_path_arn: This parameter is used only for sending authorization.
        :param configuration_set_name: The name of the configuration set to use when you send an email using
        ``SendBulkTemplatedEmail``.
        :param default_tags: A list of tags, in the form of name/value pairs, to apply to an email
        that you send to a destination using ``SendBulkTemplatedEmail``.
        :param template_arn: The ARN of the template to use when sending this email.
        :param default_template_data: A list of replacement values to apply to the template when replacement
        data is not specified in a Destination object.
        :returns: SendBulkTemplatedEmailResponse
        :raises MessageRejected:
        :raises MailFromDomainNotVerifiedException:
        :raises ConfigurationSetDoesNotExistException:
        :raises TemplateDoesNotExistException:
        :raises ConfigurationSetSendingPausedException:
        :raises AccountSendingPausedException:
        """
        raise NotImplementedError

    @handler("SendCustomVerificationEmail")
    def send_custom_verification_email(
        self,
        context: RequestContext,
        email_address: Address,
        template_name: TemplateName,
        configuration_set_name: ConfigurationSetName = None,
    ) -> SendCustomVerificationEmailResponse:
        """Adds an email address to the list of identities for your Amazon SES
        account in the current AWS Region and attempts to verify it. As a result
        of executing this operation, a customized verification email is sent to
        the specified address.

        To use this operation, you must first create a custom verification email
        template. For more information about creating and using custom
        verification email templates, see `Using Custom Verification Email
        Templates <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/custom-verification-emails.html>`__
        in the *Amazon SES Developer Guide*.

        You can execute this operation no more than once per second.

        :param email_address: The email address to verify.
        :param template_name: The name of the custom verification email template to use when sending
        the verification email.
        :param configuration_set_name: Name of a configuration set to use when sending the verification email.
        :returns: SendCustomVerificationEmailResponse
        :raises MessageRejected:
        :raises ConfigurationSetDoesNotExistException:
        :raises CustomVerificationEmailTemplateDoesNotExistException:
        :raises FromEmailAddressNotVerifiedException:
        :raises ProductionAccessNotGrantedException:
        """
        raise NotImplementedError

    @handler("SendEmail")
    def send_email(
        self,
        context: RequestContext,
        source: Address,
        destination: Destination,
        message: Message,
        reply_to_addresses: AddressList = None,
        return_path: Address = None,
        source_arn: AmazonResourceName = None,
        return_path_arn: AmazonResourceName = None,
        tags: MessageTagList = None,
        configuration_set_name: ConfigurationSetName = None,
    ) -> SendEmailResponse:
        """Composes an email message and immediately queues it for sending. In
        order to send email using the ``SendEmail`` operation, your message must
        meet the following requirements:

        -  The message must be sent from a verified email address or domain. If
           you attempt to send email using a non-verified address or domain, the
           operation will result in an "Email address not verified" error.

        -  If your account is still in the Amazon SES sandbox, you may only send
           to verified addresses or domains, or to email addresses associated
           with the Amazon SES Mailbox Simulator. For more information, see
           `Verifying Email Addresses and
           Domains <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-addresses-and-domains.html>`__
           in the *Amazon SES Developer Guide.*

        -  The maximum message size is 10 MB.

        -  The message must include at least one recipient email address. The
           recipient address can be a To: address, a CC: address, or a BCC:
           address. If a recipient email address is invalid (that is, it is not
           in the format *UserName@[SubDomain.]Domain.TopLevelDomain*), the
           entire message will be rejected, even if the message contains other
           recipients that are valid.

        -  The message may not include more than 50 recipients, across the To:,
           CC: and BCC: fields. If you need to send an email message to a larger
           audience, you can divide your recipient list into groups of 50 or
           fewer, and then call the ``SendEmail`` operation several times to
           send the message to each group.

        For every message that you send, the total number of recipients
        (including each recipient in the To:, CC: and BCC: fields) is counted
        against the maximum number of emails you can send in a 24-hour period
        (your *sending quota*). For more information about sending quotas in
        Amazon SES, see `Managing Your Amazon SES Sending
        Limits <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/manage-sending-limits.html>`__
        in the *Amazon SES Developer Guide.*

        :param source: The email address that is sending the email.
        :param destination: The destination for this email, composed of To:, CC:, and BCC: fields.
        :param message: The message to be sent.
        :param reply_to_addresses: The reply-to email address(es) for the message.
        :param return_path: The email address that bounces and complaints will be forwarded to when
        feedback forwarding is enabled.
        :param source_arn: This parameter is used only for sending authorization.
        :param return_path_arn: This parameter is used only for sending authorization.
        :param tags: A list of tags, in the form of name/value pairs, to apply to an email
        that you send using ``SendEmail``.
        :param configuration_set_name: The name of the configuration set to use when you send an email using
        ``SendEmail``.
        :returns: SendEmailResponse
        :raises MessageRejected:
        :raises MailFromDomainNotVerifiedException:
        :raises ConfigurationSetDoesNotExistException:
        :raises ConfigurationSetSendingPausedException:
        :raises AccountSendingPausedException:
        """
        raise NotImplementedError

    @handler("SendRawEmail")
    def send_raw_email(
        self,
        context: RequestContext,
        raw_message: RawMessage,
        source: Address = None,
        destinations: AddressList = None,
        from_arn: AmazonResourceName = None,
        source_arn: AmazonResourceName = None,
        return_path_arn: AmazonResourceName = None,
        tags: MessageTagList = None,
        configuration_set_name: ConfigurationSetName = None,
    ) -> SendRawEmailResponse:
        """Composes an email message and immediately queues it for sending.

        This operation is more flexible than the ``SendEmail`` API operation.
        When you use the ``SendRawEmail`` operation, you can specify the headers
        of the message as well as its content. This flexibility is useful, for
        example, when you want to send a multipart MIME email (such a message
        that contains both a text and an HTML version). You can also use this
        operation to send messages that include attachments.

        The ``SendRawEmail`` operation has the following requirements:

        -  You can only send email from `verified email addresses or
           domains <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-addresses-and-domains.html>`__.
           If you try to send email from an address that isn't verified, the
           operation results in an "Email address not verified" error.

        -  If your account is still in the `Amazon SES
           sandbox <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html>`__,
           you can only send email to other verified addresses in your account,
           or to addresses that are associated with the `Amazon SES mailbox
           simulator <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/mailbox-simulator.html>`__.

        -  The maximum message size, including attachments, is 10 MB.

        -  Each message has to include at least one recipient address. A
           recipient address includes any address on the To:, CC:, or BCC:
           lines.

        -  If you send a single message to more than one recipient address, and
           one of the recipient addresses isn't in a valid format (that is, it's
           not in the format *UserName@[SubDomain.]Domain.TopLevelDomain*),
           Amazon SES rejects the entire message, even if the other addresses
           are valid.

        -  Each message can include up to 50 recipient addresses across the To:,
           CC:, or BCC: lines. If you need to send a single message to more than
           50 recipients, you have to split the list of recipient addresses into
           groups of less than 50 recipients, and send separate messages to each
           group.

        -  Amazon SES allows you to specify 8-bit Content-Transfer-Encoding for
           MIME message parts. However, if Amazon SES has to modify the contents
           of your message (for example, if you use open and click tracking),
           8-bit content isn't preserved. For this reason, we highly recommend
           that you encode all content that isn't 7-bit ASCII. For more
           information, see `MIME
           Encoding <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-email-raw.html#send-email-mime-encoding>`__
           in the *Amazon SES Developer Guide*.

        Additionally, keep the following considerations in mind when using the
        ``SendRawEmail`` operation:

        -  Although you can customize the message headers when using the
           ``SendRawEmail`` operation, Amazon SES will automatically apply its
           own ``Message-ID`` and ``Date`` headers; if you passed these headers
           when creating the message, they will be overwritten by the values
           that Amazon SES provides.

        -  If you are using sending authorization to send on behalf of another
           user, ``SendRawEmail`` enables you to specify the cross-account
           identity for the email's Source, From, and Return-Path parameters in
           one of two ways: you can pass optional parameters ``SourceArn``,
           ``FromArn``, and/or ``ReturnPathArn`` to the API, or you can include
           the following X-headers in the header of your raw email:

           -  ``X-SES-SOURCE-ARN``

           -  ``X-SES-FROM-ARN``

           -  ``X-SES-RETURN-PATH-ARN``

           Don't include these X-headers in the DKIM signature. Amazon SES
           removes these before it sends the email.

           If you only specify the ``SourceIdentityArn`` parameter, Amazon SES
           sets the From and Return-Path addresses to the same identity that you
           specified.

           For more information about sending authorization, see the `Using
           Sending Authorization with Amazon
           SES <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/sending-authorization.html>`__
           in the *Amazon SES Developer Guide.*

        -  For every message that you send, the total number of recipients
           (including each recipient in the To:, CC: and BCC: fields) is counted
           against the maximum number of emails you can send in a 24-hour period
           (your *sending quota*). For more information about sending quotas in
           Amazon SES, see `Managing Your Amazon SES Sending
           Limits <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/manage-sending-limits.html>`__
           in the *Amazon SES Developer Guide.*

        :param raw_message: The raw email message itself.
        :param source: The identity's email address.
        :param destinations: A list of destinations for the message, consisting of To:, CC:, and BCC:
        addresses.
        :param from_arn: This parameter is used only for sending authorization.
        :param source_arn: This parameter is used only for sending authorization.
        :param return_path_arn: This parameter is used only for sending authorization.
        :param tags: A list of tags, in the form of name/value pairs, to apply to an email
        that you send using ``SendRawEmail``.
        :param configuration_set_name: The name of the configuration set to use when you send an email using
        ``SendRawEmail``.
        :returns: SendRawEmailResponse
        :raises MessageRejected:
        :raises MailFromDomainNotVerifiedException:
        :raises ConfigurationSetDoesNotExistException:
        :raises ConfigurationSetSendingPausedException:
        :raises AccountSendingPausedException:
        """
        raise NotImplementedError

    @handler("SendTemplatedEmail")
    def send_templated_email(
        self,
        context: RequestContext,
        source: Address,
        destination: Destination,
        template: TemplateName,
        template_data: TemplateData,
        reply_to_addresses: AddressList = None,
        return_path: Address = None,
        source_arn: AmazonResourceName = None,
        return_path_arn: AmazonResourceName = None,
        tags: MessageTagList = None,
        configuration_set_name: ConfigurationSetName = None,
        template_arn: AmazonResourceName = None,
    ) -> SendTemplatedEmailResponse:
        """Composes an email message using an email template and immediately queues
        it for sending.

        In order to send email using the ``SendTemplatedEmail`` operation, your
        call to the API must meet the following requirements:

        -  The call must refer to an existing email template. You can create
           email templates using the CreateTemplate operation.

        -  The message must be sent from a verified email address or domain.

        -  If your account is still in the Amazon SES sandbox, you may only send
           to verified addresses or domains, or to email addresses associated
           with the Amazon SES Mailbox Simulator. For more information, see
           `Verifying Email Addresses and
           Domains <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-addresses-and-domains.html>`__
           in the *Amazon SES Developer Guide.*

        -  The maximum message size is 10 MB.

        -  Calls to the ``SendTemplatedEmail`` operation may only include one
           ``Destination`` parameter. A destination is a set of recipients who
           will receive the same version of the email. The ``Destination``
           parameter can include up to 50 recipients, across the To:, CC: and
           BCC: fields.

        -  The ``Destination`` parameter must include at least one recipient
           email address. The recipient address can be a To: address, a CC:
           address, or a BCC: address. If a recipient email address is invalid
           (that is, it is not in the format
           *UserName@[SubDomain.]Domain.TopLevelDomain*), the entire message
           will be rejected, even if the message contains other recipients that
           are valid.

        If your call to the ``SendTemplatedEmail`` operation includes all of the
        required parameters, Amazon SES accepts it and returns a Message ID.
        However, if Amazon SES can't render the email because the template
        contains errors, it doesn't send the email. Additionally, because it
        already accepted the message, Amazon SES doesn't return a message
        stating that it was unable to send the email.

        For these reasons, we highly recommend that you set up Amazon SES to
        send you notifications when Rendering Failure events occur. For more
        information, see `Sending Personalized Email Using the Amazon SES
        API <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-personalized-email-api.html>`__
        in the *Amazon Simple Email Service Developer Guide*.

        :param source: The email address that is sending the email.
        :param destination: The destination for this email, composed of To:, CC:, and BCC: fields.
        :param template: The template to use when sending this email.
        :param template_data: A list of replacement values to apply to the template.
        :param reply_to_addresses: The reply-to email address(es) for the message.
        :param return_path: The email address that bounces and complaints will be forwarded to when
        feedback forwarding is enabled.
        :param source_arn: This parameter is used only for sending authorization.
        :param return_path_arn: This parameter is used only for sending authorization.
        :param tags: A list of tags, in the form of name/value pairs, to apply to an email
        that you send using ``SendTemplatedEmail``.
        :param configuration_set_name: The name of the configuration set to use when you send an email using
        ``SendTemplatedEmail``.
        :param template_arn: The ARN of the template to use when sending this email.
        :returns: SendTemplatedEmailResponse
        :raises MessageRejected:
        :raises MailFromDomainNotVerifiedException:
        :raises ConfigurationSetDoesNotExistException:
        :raises TemplateDoesNotExistException:
        :raises ConfigurationSetSendingPausedException:
        :raises AccountSendingPausedException:
        """
        raise NotImplementedError

    @handler("SetActiveReceiptRuleSet")
    def set_active_receipt_rule_set(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName = None
    ) -> SetActiveReceiptRuleSetResponse:
        """Sets the specified receipt rule set as the active receipt rule set.

        To disable your email-receiving through Amazon SES completely, you can
        call this API with RuleSetName set to null.

        For information about managing receipt rule sets, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-receipt-rule-sets.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the receipt rule set to make active.
        :returns: SetActiveReceiptRuleSetResponse
        :raises RuleSetDoesNotExistException:
        """
        raise NotImplementedError

    @handler("SetIdentityDkimEnabled")
    def set_identity_dkim_enabled(
        self, context: RequestContext, identity: Identity, dkim_enabled: Enabled
    ) -> SetIdentityDkimEnabledResponse:
        """Enables or disables Easy DKIM signing of email sent from an identity. If
        Easy DKIM signing is enabled for a domain, then Amazon SES uses DKIM to
        sign all email that it sends from addresses on that domain. If Easy DKIM
        signing is enabled for an email address, then Amazon SES uses DKIM to
        sign all email it sends from that address.

        For email addresses (for example, ``user@example.com``), you can only
        enable DKIM signing if the corresponding domain (in this case,
        ``example.com``) has been set up to use Easy DKIM.

        You can enable DKIM signing for an identity at any time after you start
        the verification process for the identity, even if the verification
        process isn't complete.

        You can execute this operation no more than once per second.

        For more information about Easy DKIM signing, go to the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html>`__.

        :param identity: The identity for which DKIM signing should be enabled or disabled.
        :param dkim_enabled: Sets whether DKIM signing is enabled for an identity.
        :returns: SetIdentityDkimEnabledResponse
        """
        raise NotImplementedError

    @handler("SetIdentityFeedbackForwardingEnabled")
    def set_identity_feedback_forwarding_enabled(
        self, context: RequestContext, identity: Identity, forwarding_enabled: Enabled
    ) -> SetIdentityFeedbackForwardingEnabledResponse:
        """Given an identity (an email address or a domain), enables or disables
        whether Amazon SES forwards bounce and complaint notifications as email.
        Feedback forwarding can only be disabled when Amazon Simple Notification
        Service (Amazon SNS) topics are specified for both bounces and
        complaints.

        Feedback forwarding does not apply to delivery notifications. Delivery
        notifications are only available through Amazon SNS.

        You can execute this operation no more than once per second.

        For more information about using notifications with Amazon SES, see the
        `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notifications.html>`__.

        :param identity: The identity for which to set bounce and complaint notification
        forwarding.
        :param forwarding_enabled: Sets whether Amazon SES will forward bounce and complaint notifications
        as email.
        :returns: SetIdentityFeedbackForwardingEnabledResponse
        """
        raise NotImplementedError

    @handler("SetIdentityHeadersInNotificationsEnabled")
    def set_identity_headers_in_notifications_enabled(
        self,
        context: RequestContext,
        identity: Identity,
        notification_type: NotificationType,
        enabled: Enabled,
    ) -> SetIdentityHeadersInNotificationsEnabledResponse:
        """Given an identity (an email address or a domain), sets whether Amazon
        SES includes the original email headers in the Amazon Simple
        Notification Service (Amazon SNS) notifications of a specified type.

        You can execute this operation no more than once per second.

        For more information about using notifications with Amazon SES, see the
        `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notifications.html>`__.

        :param identity: The identity for which to enable or disable headers in notifications.
        :param notification_type: The notification type for which to enable or disable headers in
        notifications.
        :param enabled: Sets whether Amazon SES includes the original email headers in Amazon
        SNS notifications of the specified notification type.
        :returns: SetIdentityHeadersInNotificationsEnabledResponse
        """
        raise NotImplementedError

    @handler("SetIdentityMailFromDomain")
    def set_identity_mail_from_domain(
        self,
        context: RequestContext,
        identity: Identity,
        mail_from_domain: MailFromDomainName = None,
        behavior_on_mx_failure: BehaviorOnMXFailure = None,
    ) -> SetIdentityMailFromDomainResponse:
        """Enables or disables the custom MAIL FROM domain setup for a verified
        identity (an email address or a domain).

        To send emails using the specified MAIL FROM domain, you must add an MX
        record to your MAIL FROM domain's DNS settings. If you want your emails
        to pass Sender Policy Framework (SPF) checks, you must also add or
        update an SPF record. For more information, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/mail-from-set.html>`__.

        You can execute this operation no more than once per second.

        :param identity: The verified identity for which you want to enable or disable the
        specified custom MAIL FROM domain.
        :param mail_from_domain: The custom MAIL FROM domain that you want the verified identity to use.
        :param behavior_on_mx_failure: The action that you want Amazon SES to take if it cannot successfully
        read the required MX record when you send an email.
        :returns: SetIdentityMailFromDomainResponse
        """
        raise NotImplementedError

    @handler("SetIdentityNotificationTopic")
    def set_identity_notification_topic(
        self,
        context: RequestContext,
        identity: Identity,
        notification_type: NotificationType,
        sns_topic: NotificationTopic = None,
    ) -> SetIdentityNotificationTopicResponse:
        """Sets an Amazon Simple Notification Service (Amazon SNS) topic to use
        when delivering notifications. When you use this operation, you specify
        a verified identity, such as an email address or domain. When you send
        an email that uses the chosen identity in the Source field, Amazon SES
        sends notifications to the topic you specified. You can send bounce,
        complaint, or delivery notifications (or any combination of the three)
        to the Amazon SNS topic that you specify.

        You can execute this operation no more than once per second.

        For more information about feedback notification, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notifications.html>`__.

        :param identity: The identity (email address or domain) that you want to set the Amazon
        SNS topic for.
        :param notification_type: The type of notifications that will be published to the specified Amazon
        SNS topic.
        :param sns_topic: The Amazon Resource Name (ARN) of the Amazon SNS topic.
        :returns: SetIdentityNotificationTopicResponse
        """
        raise NotImplementedError

    @handler("SetReceiptRulePosition")
    def set_receipt_rule_position(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        rule_name: ReceiptRuleName,
        after: ReceiptRuleName = None,
    ) -> SetReceiptRulePositionResponse:
        """Sets the position of the specified receipt rule in the receipt rule set.

        For information about managing receipt rules, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-receipt-rules.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the receipt rule set that contains the receipt rule to
        reposition.
        :param rule_name: The name of the receipt rule to reposition.
        :param after: The name of the receipt rule after which to place the specified receipt
        rule.
        :returns: SetReceiptRulePositionResponse
        :raises RuleSetDoesNotExistException:
        :raises RuleDoesNotExistException:
        """
        raise NotImplementedError

    @handler("TestRenderTemplate")
    def test_render_template(
        self, context: RequestContext, template_name: TemplateName, template_data: TemplateData
    ) -> TestRenderTemplateResponse:
        """Creates a preview of the MIME content of an email when provided with a
        template and a set of replacement data.

        You can execute this operation no more than once per second.

        :param template_name: The name of the template that you want to render.
        :param template_data: A list of replacement values to apply to the template.
        :returns: TestRenderTemplateResponse
        :raises TemplateDoesNotExistException:
        :raises InvalidRenderingParameterException:
        :raises MissingRenderingAttributeException:
        """
        raise NotImplementedError

    @handler("UpdateAccountSendingEnabled")
    def update_account_sending_enabled(
        self, context: RequestContext, enabled: Enabled = None
    ) -> None:
        """Enables or disables email sending across your entire Amazon SES account
        in the current AWS Region. You can use this operation in conjunction
        with Amazon CloudWatch alarms to temporarily pause email sending across
        your Amazon SES account in a given AWS Region when reputation metrics
        (such as your bounce or complaint rates) reach certain thresholds.

        You can execute this operation no more than once per second.

        :param enabled: Describes whether email sending is enabled or disabled for your Amazon
        SES account in the current AWS Region.
        """
        raise NotImplementedError

    @handler("UpdateConfigurationSetEventDestination")
    def update_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination: EventDestination,
    ) -> UpdateConfigurationSetEventDestinationResponse:
        """Updates the event destination of a configuration set. Event destinations
        are associated with configuration sets, which enable you to publish
        email sending events to Amazon CloudWatch, Amazon Kinesis Firehose, or
        Amazon Simple Notification Service (Amazon SNS). For information about
        using configuration sets, see `Monitoring Your Amazon SES Sending
        Activity <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/monitor-sending-activity.html>`__
        in the *Amazon SES Developer Guide.*

        When you create or update an event destination, you must provide one,
        and only one, destination. The destination can be Amazon CloudWatch,
        Amazon Kinesis Firehose, or Amazon Simple Notification Service (Amazon
        SNS).

        You can execute this operation no more than once per second.

        :param configuration_set_name: The name of the configuration set that contains the event destination
        that you want to update.
        :param event_destination: The event destination object that you want to apply to the specified
        configuration set.
        :returns: UpdateConfigurationSetEventDestinationResponse
        :raises ConfigurationSetDoesNotExistException:
        :raises EventDestinationDoesNotExistException:
        :raises InvalidCloudWatchDestinationException:
        :raises InvalidFirehoseDestinationException:
        :raises InvalidSNSDestinationException:
        """
        raise NotImplementedError

    @handler("UpdateConfigurationSetReputationMetricsEnabled")
    def update_configuration_set_reputation_metrics_enabled(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        enabled: Enabled,
    ) -> None:
        """Enables or disables the publishing of reputation metrics for emails sent
        using a specific configuration set in a given AWS Region. Reputation
        metrics include bounce and complaint rates. These metrics are published
        to Amazon CloudWatch. By using CloudWatch, you can create alarms when
        bounce or complaint rates exceed certain thresholds.

        You can execute this operation no more than once per second.

        :param configuration_set_name: The name of the configuration set that you want to update.
        :param enabled: Describes whether or not Amazon SES will publish reputation metrics for
        the configuration set, such as bounce and complaint rates, to Amazon
        CloudWatch.
        :raises ConfigurationSetDoesNotExistException:
        """
        raise NotImplementedError

    @handler("UpdateConfigurationSetSendingEnabled")
    def update_configuration_set_sending_enabled(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        enabled: Enabled,
    ) -> None:
        """Enables or disables email sending for messages sent using a specific
        configuration set in a given AWS Region. You can use this operation in
        conjunction with Amazon CloudWatch alarms to temporarily pause email
        sending for a configuration set when the reputation metrics for that
        configuration set (such as your bounce on complaint rate) exceed certain
        thresholds.

        You can execute this operation no more than once per second.

        :param configuration_set_name: The name of the configuration set that you want to update.
        :param enabled: Describes whether email sending is enabled or disabled for the
        configuration set.
        :raises ConfigurationSetDoesNotExistException:
        """
        raise NotImplementedError

    @handler("UpdateConfigurationSetTrackingOptions")
    def update_configuration_set_tracking_options(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        tracking_options: TrackingOptions,
    ) -> UpdateConfigurationSetTrackingOptionsResponse:
        """Modifies an association between a configuration set and a custom domain
        for open and click event tracking.

        By default, images and links used for tracking open and click events are
        hosted on domains operated by Amazon SES. You can configure a subdomain
        of your own to handle these events. For information about using custom
        domains, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/configure-custom-open-click-domains.html>`__.

        :param configuration_set_name: The name of the configuration set for which you want to update the
        custom tracking domain.
        :param tracking_options: A domain that is used to redirect email recipients to an Amazon
        SES-operated domain.
        :returns: UpdateConfigurationSetTrackingOptionsResponse
        :raises ConfigurationSetDoesNotExistException:
        :raises TrackingOptionsDoesNotExistException:
        :raises InvalidTrackingOptionsException:
        """
        raise NotImplementedError

    @handler("UpdateCustomVerificationEmailTemplate")
    def update_custom_verification_email_template(
        self,
        context: RequestContext,
        template_name: TemplateName,
        from_email_address: FromAddress = None,
        template_subject: Subject = None,
        template_content: TemplateContent = None,
        success_redirection_url: SuccessRedirectionURL = None,
        failure_redirection_url: FailureRedirectionURL = None,
    ) -> None:
        """Updates an existing custom verification email template.

        For more information about custom verification email templates, see
        `Using Custom Verification Email
        Templates <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/custom-verification-emails.html>`__
        in the *Amazon SES Developer Guide*.

        You can execute this operation no more than once per second.

        :param template_name: The name of the custom verification email template that you want to
        update.
        :param from_email_address: The email address that the custom verification email is sent from.
        :param template_subject: The subject line of the custom verification email.
        :param template_content: The content of the custom verification email.
        :param success_redirection_url: The URL that the recipient of the verification email is sent to if his
        or her address is successfully verified.
        :param failure_redirection_url: The URL that the recipient of the verification email is sent to if his
        or her address is not successfully verified.
        :raises CustomVerificationEmailTemplateDoesNotExistException:
        :raises FromEmailAddressNotVerifiedException:
        :raises CustomVerificationEmailInvalidContentException:
        """
        raise NotImplementedError

    @handler("UpdateReceiptRule")
    def update_receipt_rule(
        self, context: RequestContext, rule_set_name: ReceiptRuleSetName, rule: ReceiptRule
    ) -> UpdateReceiptRuleResponse:
        """Updates a receipt rule.

        For information about managing receipt rules, see the `Amazon SES
        Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/receiving-email-managing-receipt-rules.html>`__.

        You can execute this operation no more than once per second.

        :param rule_set_name: The name of the receipt rule set that the receipt rule belongs to.
        :param rule: A data structure that contains the updated receipt rule information.
        :returns: UpdateReceiptRuleResponse
        :raises InvalidSnsTopicException:
        :raises InvalidS3ConfigurationException:
        :raises InvalidLambdaFunctionException:
        :raises RuleSetDoesNotExistException:
        :raises RuleDoesNotExistException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("UpdateTemplate")
    def update_template(
        self, context: RequestContext, template: Template
    ) -> UpdateTemplateResponse:
        """Updates an email template. Email templates enable you to send
        personalized email to one or more destinations in a single API
        operation. For more information, see the `Amazon SES Developer
        Guide <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/send-personalized-email-api.html>`__.

        You can execute this operation no more than once per second.

        :param template: The content of the email, composed of a subject line, an HTML part, and
        a text-only part.
        :returns: UpdateTemplateResponse
        :raises TemplateDoesNotExistException:
        :raises InvalidTemplateException:
        """
        raise NotImplementedError

    @handler("VerifyDomainDkim")
    def verify_domain_dkim(
        self, context: RequestContext, domain: Domain
    ) -> VerifyDomainDkimResponse:
        """Returns a set of DKIM tokens for a domain identity.

        When you execute the ``VerifyDomainDkim`` operation, the domain that you
        specify is added to the list of identities that are associated with your
        account. This is true even if you haven't already associated the domain
        with your account by using the ``VerifyDomainIdentity`` operation.
        However, you can't send email from the domain until you either
        successfully `verify
        it <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-domains.html>`__
        or you successfully `set up DKIM for
        it <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html>`__.

        You use the tokens that are generated by this operation to create CNAME
        records. When Amazon SES detects that you've added these records to the
        DNS configuration for a domain, you can start sending email from that
        domain. You can start sending email even if you haven't added the TXT
        record provided by the VerifyDomainIdentity operation to the DNS
        configuration for your domain. All email that you send from the domain
        is authenticated using DKIM.

        To create the CNAME records for DKIM authentication, use the following
        values:

        -  **Name**: *token*._domainkey. *example.com*

        -  **Type**: CNAME

        -  **Value**: *token*.dkim.amazonses.com

        In the preceding example, replace *token* with one of the tokens that
        are generated when you execute this operation. Replace *example.com*
        with your domain. Repeat this process for each token that's generated by
        this operation.

        You can execute this operation no more than once per second.

        :param domain: The name of the domain to be verified for Easy DKIM signing.
        :returns: VerifyDomainDkimResponse
        """
        raise NotImplementedError

    @handler("VerifyDomainIdentity")
    def verify_domain_identity(
        self, context: RequestContext, domain: Domain
    ) -> VerifyDomainIdentityResponse:
        """Adds a domain to the list of identities for your Amazon SES account in
        the current AWS Region and attempts to verify it. For more information
        about verifying domains, see `Verifying Email Addresses and
        Domains <https://docs.aws.amazon.com/ses/latest/DeveloperGuide/verify-addresses-and-domains.html>`__
        in the *Amazon SES Developer Guide.*

        You can execute this operation no more than once per second.

        :param domain: The domain to be verified.
        :returns: VerifyDomainIdentityResponse
        """
        raise NotImplementedError

    @handler("VerifyEmailAddress")
    def verify_email_address(self, context: RequestContext, email_address: Address) -> None:
        """Deprecated. Use the ``VerifyEmailIdentity`` operation to verify a new
        email address.

        :param email_address: The email address to be verified.
        """
        raise NotImplementedError

    @handler("VerifyEmailIdentity")
    def verify_email_identity(
        self, context: RequestContext, email_address: Address
    ) -> VerifyEmailIdentityResponse:
        """Adds an email address to the list of identities for your Amazon SES
        account in the current AWS region and attempts to verify it. As a result
        of executing this operation, a verification email is sent to the
        specified address.

        You can execute this operation no more than once per second.

        :param email_address: The email address to be verified.
        :returns: VerifyEmailIdentityResponse
        """
        raise NotImplementedError
