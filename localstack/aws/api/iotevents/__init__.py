import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AcknowledgeFlowEnabled = bool
AlarmModelArn = str
AlarmModelDescription = str
AlarmModelName = str
AlarmModelVersion = str
AmazonResourceName = str
AnalysisId = str
AnalysisMessage = str
AnalysisResultLocationPath = str
AnalysisType = str
AssetId = str
AssetModelId = str
AssetPropertyAlias = str
AssetPropertyBooleanValue = str
AssetPropertyDoubleValue = str
AssetPropertyEntryId = str
AssetPropertyId = str
AssetPropertyIntegerValue = str
AssetPropertyOffsetInNanos = str
AssetPropertyQuality = str
AssetPropertyStringValue = str
AssetPropertyTimeInSeconds = str
AttributeJsonPath = str
Condition = str
ContentExpression = str
DeliveryStreamName = str
DetectorModelArn = str
DetectorModelDescription = str
DetectorModelName = str
DetectorModelVersion = str
DisabledOnInitialization = bool
DynamoKeyField = str
DynamoKeyType = str
DynamoKeyValue = str
DynamoOperation = str
DynamoTableName = str
EmailSubject = str
EventName = str
FirehoseSeparator = str
FromEmail = str
IdentityStoreId = str
InputArn = str
InputDescription = str
InputName = str
InputProperty = str
KeyValue = str
LoggingEnabled = bool
MQTTTopic = str
MaxAnalysisResults = int
MaxResults = int
NextToken = str
NotificationAdditionalMessage = str
QueueUrl = str
ResourceName = str
SMSSenderId = str
SSOReferenceId = str
Seconds = int
Severity = int
StateName = str
StatusMessage = str
TagKey = str
TagValue = str
Threshold = str
TimerName = str
UseBase64 = bool
VariableName = str
VariableValue = str
errorMessage = str
resourceArn = str
resourceId = str


class AlarmModelVersionStatus(str):
    ACTIVE = "ACTIVE"
    ACTIVATING = "ACTIVATING"
    INACTIVE = "INACTIVE"
    FAILED = "FAILED"


class AnalysisResultLevel(str):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class AnalysisStatus(str):
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class ComparisonOperator(str):
    GREATER = "GREATER"
    GREATER_OR_EQUAL = "GREATER_OR_EQUAL"
    LESS = "LESS"
    LESS_OR_EQUAL = "LESS_OR_EQUAL"
    EQUAL = "EQUAL"
    NOT_EQUAL = "NOT_EQUAL"


class DetectorModelVersionStatus(str):
    ACTIVE = "ACTIVE"
    ACTIVATING = "ACTIVATING"
    INACTIVE = "INACTIVE"
    DEPRECATED = "DEPRECATED"
    DRAFT = "DRAFT"
    PAUSED = "PAUSED"
    FAILED = "FAILED"


class EvaluationMethod(str):
    BATCH = "BATCH"
    SERIAL = "SERIAL"


class InputStatus(str):
    CREATING = "CREATING"
    UPDATING = "UPDATING"
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class LoggingLevel(str):
    ERROR = "ERROR"
    INFO = "INFO"
    DEBUG = "DEBUG"


class PayloadType(str):
    STRING = "STRING"
    JSON = "JSON"


class InternalFailureException(ServiceException):
    message: Optional[errorMessage]


class InvalidRequestException(ServiceException):
    message: Optional[errorMessage]


class LimitExceededException(ServiceException):
    message: Optional[errorMessage]


class ResourceAlreadyExistsException(ServiceException):
    message: Optional[errorMessage]
    resourceId: Optional[resourceId]
    resourceArn: Optional[resourceArn]


class ResourceInUseException(ServiceException):
    message: Optional[errorMessage]


class ResourceNotFoundException(ServiceException):
    message: Optional[errorMessage]


class ServiceUnavailableException(ServiceException):
    message: Optional[errorMessage]


class ThrottlingException(ServiceException):
    message: Optional[errorMessage]


class UnsupportedOperationException(ServiceException):
    message: Optional[errorMessage]


class AcknowledgeFlow(TypedDict, total=False):
    enabled: AcknowledgeFlowEnabled


class AssetPropertyTimestamp(TypedDict, total=False):
    timeInSeconds: AssetPropertyTimeInSeconds
    offsetInNanos: Optional[AssetPropertyOffsetInNanos]


class AssetPropertyVariant(TypedDict, total=False):
    stringValue: Optional[AssetPropertyStringValue]
    integerValue: Optional[AssetPropertyIntegerValue]
    doubleValue: Optional[AssetPropertyDoubleValue]
    booleanValue: Optional[AssetPropertyBooleanValue]


class AssetPropertyValue(TypedDict, total=False):
    value: Optional[AssetPropertyVariant]
    timestamp: Optional[AssetPropertyTimestamp]
    quality: Optional[AssetPropertyQuality]


class IotSiteWiseAction(TypedDict, total=False):
    entryId: Optional[AssetPropertyEntryId]
    assetId: Optional[AssetId]
    propertyId: Optional[AssetPropertyId]
    propertyAlias: Optional[AssetPropertyAlias]
    propertyValue: Optional[AssetPropertyValue]


Payload = TypedDict(
    "Payload",
    {
        "contentExpression": ContentExpression,
        "type": PayloadType,
    },
    total=False,
)


class DynamoDBv2Action(TypedDict, total=False):
    tableName: DynamoTableName
    payload: Optional[Payload]


class DynamoDBAction(TypedDict, total=False):
    hashKeyType: Optional[DynamoKeyType]
    hashKeyField: DynamoKeyField
    hashKeyValue: DynamoKeyValue
    rangeKeyType: Optional[DynamoKeyType]
    rangeKeyField: Optional[DynamoKeyField]
    rangeKeyValue: Optional[DynamoKeyValue]
    operation: Optional[DynamoOperation]
    payloadField: Optional[DynamoKeyField]
    tableName: DynamoTableName
    payload: Optional[Payload]


class FirehoseAction(TypedDict, total=False):
    deliveryStreamName: DeliveryStreamName
    separator: Optional[FirehoseSeparator]
    payload: Optional[Payload]


class SqsAction(TypedDict, total=False):
    queueUrl: QueueUrl
    useBase64: Optional[UseBase64]
    payload: Optional[Payload]


class IotEventsAction(TypedDict, total=False):
    inputName: InputName
    payload: Optional[Payload]


class LambdaAction(TypedDict, total=False):
    functionArn: AmazonResourceName
    payload: Optional[Payload]


class ResetTimerAction(TypedDict, total=False):
    timerName: TimerName


class ClearTimerAction(TypedDict, total=False):
    timerName: TimerName


class SetTimerAction(TypedDict, total=False):
    timerName: TimerName
    seconds: Optional[Seconds]
    durationExpression: Optional[VariableValue]


class IotTopicPublishAction(TypedDict, total=False):
    mqttTopic: MQTTTopic
    payload: Optional[Payload]


class SNSTopicPublishAction(TypedDict, total=False):
    targetArn: AmazonResourceName
    payload: Optional[Payload]


class SetVariableAction(TypedDict, total=False):
    variableName: VariableName
    value: VariableValue


Action = TypedDict(
    "Action",
    {
        "setVariable": Optional[SetVariableAction],
        "sns": Optional[SNSTopicPublishAction],
        "iotTopicPublish": Optional[IotTopicPublishAction],
        "setTimer": Optional[SetTimerAction],
        "clearTimer": Optional[ClearTimerAction],
        "resetTimer": Optional[ResetTimerAction],
        "lambda": Optional[LambdaAction],
        "iotEvents": Optional[IotEventsAction],
        "sqs": Optional[SqsAction],
        "firehose": Optional[FirehoseAction],
        "dynamoDB": Optional[DynamoDBAction],
        "dynamoDBv2": Optional[DynamoDBv2Action],
        "iotSiteWise": Optional[IotSiteWiseAction],
    },
    total=False,
)
Actions = List[Action]
AlarmAction = TypedDict(
    "AlarmAction",
    {
        "sns": Optional[SNSTopicPublishAction],
        "iotTopicPublish": Optional[IotTopicPublishAction],
        "lambda": Optional[LambdaAction],
        "iotEvents": Optional[IotEventsAction],
        "sqs": Optional[SqsAction],
        "firehose": Optional[FirehoseAction],
        "dynamoDB": Optional[DynamoDBAction],
        "dynamoDBv2": Optional[DynamoDBv2Action],
        "iotSiteWise": Optional[IotSiteWiseAction],
    },
    total=False,
)
AlarmActions = List[AlarmAction]


class InitializationConfiguration(TypedDict, total=False):
    disabledOnInitialization: DisabledOnInitialization


class AlarmCapabilities(TypedDict, total=False):
    initializationConfiguration: Optional[InitializationConfiguration]
    acknowledgeFlow: Optional[AcknowledgeFlow]


class AlarmEventActions(TypedDict, total=False):
    alarmActions: Optional[AlarmActions]


Timestamp = datetime


class AlarmModelSummary(TypedDict, total=False):
    creationTime: Optional[Timestamp]
    alarmModelDescription: Optional[AlarmModelDescription]
    alarmModelName: Optional[AlarmModelName]


AlarmModelSummaries = List[AlarmModelSummary]


class AlarmModelVersionSummary(TypedDict, total=False):
    alarmModelName: Optional[AlarmModelName]
    alarmModelArn: Optional[AlarmModelArn]
    alarmModelVersion: Optional[AlarmModelVersion]
    roleArn: Optional[AmazonResourceName]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    status: Optional[AlarmModelVersionStatus]
    statusMessage: Optional[StatusMessage]


AlarmModelVersionSummaries = List[AlarmModelVersionSummary]


class SSOIdentity(TypedDict, total=False):
    identityStoreId: IdentityStoreId
    userId: Optional[SSOReferenceId]


class RecipientDetail(TypedDict, total=False):
    ssoIdentity: Optional[SSOIdentity]


RecipientDetails = List[RecipientDetail]


class EmailRecipients(TypedDict, total=False):
    to: Optional[RecipientDetails]


class EmailContent(TypedDict, total=False):
    subject: Optional[EmailSubject]
    additionalMessage: Optional[NotificationAdditionalMessage]


EmailConfiguration = TypedDict(
    "EmailConfiguration",
    {
        "from": FromEmail,
        "content": Optional[EmailContent],
        "recipients": EmailRecipients,
    },
    total=False,
)
EmailConfigurations = List[EmailConfiguration]


class SMSConfiguration(TypedDict, total=False):
    senderId: Optional[SMSSenderId]
    additionalMessage: Optional[NotificationAdditionalMessage]
    recipients: RecipientDetails


SMSConfigurations = List[SMSConfiguration]


class NotificationTargetActions(TypedDict, total=False):
    lambdaAction: Optional[LambdaAction]


class NotificationAction(TypedDict, total=False):
    action: NotificationTargetActions
    smsConfigurations: Optional[SMSConfigurations]
    emailConfigurations: Optional[EmailConfigurations]


NotificationActions = List[NotificationAction]


class AlarmNotification(TypedDict, total=False):
    notificationActions: Optional[NotificationActions]


class SimpleRule(TypedDict, total=False):
    inputProperty: InputProperty
    comparisonOperator: ComparisonOperator
    threshold: Threshold


class AlarmRule(TypedDict, total=False):
    simpleRule: Optional[SimpleRule]


class AnalysisResultLocation(TypedDict, total=False):
    path: Optional[AnalysisResultLocationPath]


AnalysisResultLocations = List[AnalysisResultLocation]
AnalysisResult = TypedDict(
    "AnalysisResult",
    {
        "type": Optional[AnalysisType],
        "level": Optional[AnalysisResultLevel],
        "message": Optional[AnalysisMessage],
        "locations": Optional[AnalysisResultLocations],
    },
    total=False,
)
AnalysisResults = List[AnalysisResult]


class Attribute(TypedDict, total=False):
    jsonPath: AttributeJsonPath


Attributes = List[Attribute]


class Tag(TypedDict, total=False):
    key: TagKey
    value: TagValue


Tags = List[Tag]


class CreateAlarmModelRequest(ServiceRequest):
    alarmModelName: AlarmModelName
    alarmModelDescription: Optional[AlarmModelDescription]
    roleArn: AmazonResourceName
    tags: Optional[Tags]
    key: Optional[AttributeJsonPath]
    severity: Optional[Severity]
    alarmRule: AlarmRule
    alarmNotification: Optional[AlarmNotification]
    alarmEventActions: Optional[AlarmEventActions]
    alarmCapabilities: Optional[AlarmCapabilities]


class CreateAlarmModelResponse(TypedDict, total=False):
    creationTime: Optional[Timestamp]
    alarmModelArn: Optional[AlarmModelArn]
    alarmModelVersion: Optional[AlarmModelVersion]
    lastUpdateTime: Optional[Timestamp]
    status: Optional[AlarmModelVersionStatus]


class Event(TypedDict, total=False):
    eventName: EventName
    condition: Optional[Condition]
    actions: Optional[Actions]


Events = List[Event]


class OnExitLifecycle(TypedDict, total=False):
    events: Optional[Events]


class OnEnterLifecycle(TypedDict, total=False):
    events: Optional[Events]


class TransitionEvent(TypedDict, total=False):
    eventName: EventName
    condition: Condition
    actions: Optional[Actions]
    nextState: StateName


TransitionEvents = List[TransitionEvent]


class OnInputLifecycle(TypedDict, total=False):
    events: Optional[Events]
    transitionEvents: Optional[TransitionEvents]


class State(TypedDict, total=False):
    stateName: StateName
    onInput: Optional[OnInputLifecycle]
    onEnter: Optional[OnEnterLifecycle]
    onExit: Optional[OnExitLifecycle]


States = List[State]


class DetectorModelDefinition(TypedDict, total=False):
    states: States
    initialStateName: StateName


class CreateDetectorModelRequest(ServiceRequest):
    detectorModelName: DetectorModelName
    detectorModelDefinition: DetectorModelDefinition
    detectorModelDescription: Optional[DetectorModelDescription]
    key: Optional[AttributeJsonPath]
    roleArn: AmazonResourceName
    tags: Optional[Tags]
    evaluationMethod: Optional[EvaluationMethod]


class DetectorModelConfiguration(TypedDict, total=False):
    detectorModelName: Optional[DetectorModelName]
    detectorModelVersion: Optional[DetectorModelVersion]
    detectorModelDescription: Optional[DetectorModelDescription]
    detectorModelArn: Optional[DetectorModelArn]
    roleArn: Optional[AmazonResourceName]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    status: Optional[DetectorModelVersionStatus]
    key: Optional[AttributeJsonPath]
    evaluationMethod: Optional[EvaluationMethod]


class CreateDetectorModelResponse(TypedDict, total=False):
    detectorModelConfiguration: Optional[DetectorModelConfiguration]


class InputDefinition(TypedDict, total=False):
    attributes: Attributes


class CreateInputRequest(ServiceRequest):
    inputName: InputName
    inputDescription: Optional[InputDescription]
    inputDefinition: InputDefinition
    tags: Optional[Tags]


class InputConfiguration(TypedDict, total=False):
    inputName: InputName
    inputDescription: Optional[InputDescription]
    inputArn: InputArn
    creationTime: Timestamp
    lastUpdateTime: Timestamp
    status: InputStatus


class CreateInputResponse(TypedDict, total=False):
    inputConfiguration: Optional[InputConfiguration]


class DeleteAlarmModelRequest(ServiceRequest):
    alarmModelName: AlarmModelName


class DeleteAlarmModelResponse(TypedDict, total=False):
    pass


class DeleteDetectorModelRequest(ServiceRequest):
    detectorModelName: DetectorModelName


class DeleteDetectorModelResponse(TypedDict, total=False):
    pass


class DeleteInputRequest(ServiceRequest):
    inputName: InputName


class DeleteInputResponse(TypedDict, total=False):
    pass


class DescribeAlarmModelRequest(ServiceRequest):
    alarmModelName: AlarmModelName
    alarmModelVersion: Optional[AlarmModelVersion]


class DescribeAlarmModelResponse(TypedDict, total=False):
    creationTime: Optional[Timestamp]
    alarmModelArn: Optional[AlarmModelArn]
    alarmModelVersion: Optional[AlarmModelVersion]
    lastUpdateTime: Optional[Timestamp]
    status: Optional[AlarmModelVersionStatus]
    statusMessage: Optional[StatusMessage]
    alarmModelName: Optional[AlarmModelName]
    alarmModelDescription: Optional[AlarmModelDescription]
    roleArn: Optional[AmazonResourceName]
    key: Optional[AttributeJsonPath]
    severity: Optional[Severity]
    alarmRule: Optional[AlarmRule]
    alarmNotification: Optional[AlarmNotification]
    alarmEventActions: Optional[AlarmEventActions]
    alarmCapabilities: Optional[AlarmCapabilities]


class DescribeDetectorModelAnalysisRequest(ServiceRequest):
    analysisId: AnalysisId


class DescribeDetectorModelAnalysisResponse(TypedDict, total=False):
    status: Optional[AnalysisStatus]


class DescribeDetectorModelRequest(ServiceRequest):
    detectorModelName: DetectorModelName
    detectorModelVersion: Optional[DetectorModelVersion]


class DetectorModel(TypedDict, total=False):
    detectorModelDefinition: Optional[DetectorModelDefinition]
    detectorModelConfiguration: Optional[DetectorModelConfiguration]


class DescribeDetectorModelResponse(TypedDict, total=False):
    detectorModel: Optional[DetectorModel]


class DescribeInputRequest(ServiceRequest):
    inputName: InputName


class Input(TypedDict, total=False):
    inputConfiguration: Optional[InputConfiguration]
    inputDefinition: Optional[InputDefinition]


class DescribeInputResponse(TypedDict, total=False):
    input: Optional[Input]


class DescribeLoggingOptionsRequest(ServiceRequest):
    pass


class DetectorDebugOption(TypedDict, total=False):
    detectorModelName: DetectorModelName
    keyValue: Optional[KeyValue]


DetectorDebugOptions = List[DetectorDebugOption]


class LoggingOptions(TypedDict, total=False):
    roleArn: AmazonResourceName
    level: LoggingLevel
    enabled: LoggingEnabled
    detectorDebugOptions: Optional[DetectorDebugOptions]


class DescribeLoggingOptionsResponse(TypedDict, total=False):
    loggingOptions: Optional[LoggingOptions]


class DetectorModelSummary(TypedDict, total=False):
    detectorModelName: Optional[DetectorModelName]
    detectorModelDescription: Optional[DetectorModelDescription]
    creationTime: Optional[Timestamp]


DetectorModelSummaries = List[DetectorModelSummary]


class DetectorModelVersionSummary(TypedDict, total=False):
    detectorModelName: Optional[DetectorModelName]
    detectorModelVersion: Optional[DetectorModelVersion]
    detectorModelArn: Optional[DetectorModelArn]
    roleArn: Optional[AmazonResourceName]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    status: Optional[DetectorModelVersionStatus]
    evaluationMethod: Optional[EvaluationMethod]


DetectorModelVersionSummaries = List[DetectorModelVersionSummary]


class GetDetectorModelAnalysisResultsRequest(ServiceRequest):
    analysisId: AnalysisId
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxAnalysisResults]


class GetDetectorModelAnalysisResultsResponse(TypedDict, total=False):
    analysisResults: Optional[AnalysisResults]
    nextToken: Optional[NextToken]


class IotSiteWiseAssetModelPropertyIdentifier(TypedDict, total=False):
    assetModelId: AssetModelId
    propertyId: AssetPropertyId


class IotSiteWiseInputIdentifier(TypedDict, total=False):
    iotSiteWiseAssetModelPropertyIdentifier: Optional[IotSiteWiseAssetModelPropertyIdentifier]


class IotEventsInputIdentifier(TypedDict, total=False):
    inputName: InputName


class InputIdentifier(TypedDict, total=False):
    iotEventsInputIdentifier: Optional[IotEventsInputIdentifier]
    iotSiteWiseInputIdentifier: Optional[IotSiteWiseInputIdentifier]


class InputSummary(TypedDict, total=False):
    inputName: Optional[InputName]
    inputDescription: Optional[InputDescription]
    inputArn: Optional[InputArn]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]
    status: Optional[InputStatus]


InputSummaries = List[InputSummary]


class ListAlarmModelVersionsRequest(ServiceRequest):
    alarmModelName: AlarmModelName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListAlarmModelVersionsResponse(TypedDict, total=False):
    alarmModelVersionSummaries: Optional[AlarmModelVersionSummaries]
    nextToken: Optional[NextToken]


class ListAlarmModelsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListAlarmModelsResponse(TypedDict, total=False):
    alarmModelSummaries: Optional[AlarmModelSummaries]
    nextToken: Optional[NextToken]


class ListDetectorModelVersionsRequest(ServiceRequest):
    detectorModelName: DetectorModelName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListDetectorModelVersionsResponse(TypedDict, total=False):
    detectorModelVersionSummaries: Optional[DetectorModelVersionSummaries]
    nextToken: Optional[NextToken]


class ListDetectorModelsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListDetectorModelsResponse(TypedDict, total=False):
    detectorModelSummaries: Optional[DetectorModelSummaries]
    nextToken: Optional[NextToken]


class ListInputRoutingsRequest(ServiceRequest):
    inputIdentifier: InputIdentifier
    maxResults: Optional[MaxResults]
    nextToken: Optional[NextToken]


class RoutedResource(TypedDict, total=False):
    name: Optional[ResourceName]
    arn: Optional[AmazonResourceName]


RoutedResources = List[RoutedResource]


class ListInputRoutingsResponse(TypedDict, total=False):
    routedResources: Optional[RoutedResources]
    nextToken: Optional[NextToken]


class ListInputsRequest(ServiceRequest):
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListInputsResponse(TypedDict, total=False):
    inputSummaries: Optional[InputSummaries]
    nextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[Tags]


class PutLoggingOptionsRequest(ServiceRequest):
    loggingOptions: LoggingOptions


class StartDetectorModelAnalysisRequest(ServiceRequest):
    detectorModelDefinition: DetectorModelDefinition


class StartDetectorModelAnalysisResponse(TypedDict, total=False):
    analysisId: Optional[AnalysisId]


TagKeys = List[TagKey]


class TagResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName
    tags: Tags


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: AmazonResourceName
    tagKeys: TagKeys


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateAlarmModelRequest(ServiceRequest):
    alarmModelName: AlarmModelName
    alarmModelDescription: Optional[AlarmModelDescription]
    roleArn: AmazonResourceName
    severity: Optional[Severity]
    alarmRule: AlarmRule
    alarmNotification: Optional[AlarmNotification]
    alarmEventActions: Optional[AlarmEventActions]
    alarmCapabilities: Optional[AlarmCapabilities]


class UpdateAlarmModelResponse(TypedDict, total=False):
    creationTime: Optional[Timestamp]
    alarmModelArn: Optional[AlarmModelArn]
    alarmModelVersion: Optional[AlarmModelVersion]
    lastUpdateTime: Optional[Timestamp]
    status: Optional[AlarmModelVersionStatus]


class UpdateDetectorModelRequest(ServiceRequest):
    detectorModelName: DetectorModelName
    detectorModelDefinition: DetectorModelDefinition
    detectorModelDescription: Optional[DetectorModelDescription]
    roleArn: AmazonResourceName
    evaluationMethod: Optional[EvaluationMethod]


class UpdateDetectorModelResponse(TypedDict, total=False):
    detectorModelConfiguration: Optional[DetectorModelConfiguration]


class UpdateInputRequest(ServiceRequest):
    inputName: InputName
    inputDescription: Optional[InputDescription]
    inputDefinition: InputDefinition


class UpdateInputResponse(TypedDict, total=False):
    inputConfiguration: Optional[InputConfiguration]


class IoteventsApi:

    service = "iotevents"
    version = "2018-07-27"

    @handler("CreateAlarmModel")
    def create_alarm_model(
        self,
        context: RequestContext,
        alarm_model_name: AlarmModelName,
        role_arn: AmazonResourceName,
        alarm_rule: AlarmRule,
        alarm_model_description: AlarmModelDescription = None,
        tags: Tags = None,
        key: AttributeJsonPath = None,
        severity: Severity = None,
        alarm_notification: AlarmNotification = None,
        alarm_event_actions: AlarmEventActions = None,
        alarm_capabilities: AlarmCapabilities = None,
    ) -> CreateAlarmModelResponse:
        raise NotImplementedError

    @handler("CreateDetectorModel")
    def create_detector_model(
        self,
        context: RequestContext,
        detector_model_name: DetectorModelName,
        detector_model_definition: DetectorModelDefinition,
        role_arn: AmazonResourceName,
        detector_model_description: DetectorModelDescription = None,
        key: AttributeJsonPath = None,
        tags: Tags = None,
        evaluation_method: EvaluationMethod = None,
    ) -> CreateDetectorModelResponse:
        raise NotImplementedError

    @handler("CreateInput")
    def create_input(
        self,
        context: RequestContext,
        input_name: InputName,
        input_definition: InputDefinition,
        input_description: InputDescription = None,
        tags: Tags = None,
    ) -> CreateInputResponse:
        raise NotImplementedError

    @handler("DeleteAlarmModel")
    def delete_alarm_model(
        self, context: RequestContext, alarm_model_name: AlarmModelName
    ) -> DeleteAlarmModelResponse:
        raise NotImplementedError

    @handler("DeleteDetectorModel")
    def delete_detector_model(
        self, context: RequestContext, detector_model_name: DetectorModelName
    ) -> DeleteDetectorModelResponse:
        raise NotImplementedError

    @handler("DeleteInput")
    def delete_input(self, context: RequestContext, input_name: InputName) -> DeleteInputResponse:
        raise NotImplementedError

    @handler("DescribeAlarmModel")
    def describe_alarm_model(
        self,
        context: RequestContext,
        alarm_model_name: AlarmModelName,
        alarm_model_version: AlarmModelVersion = None,
    ) -> DescribeAlarmModelResponse:
        raise NotImplementedError

    @handler("DescribeDetectorModel")
    def describe_detector_model(
        self,
        context: RequestContext,
        detector_model_name: DetectorModelName,
        detector_model_version: DetectorModelVersion = None,
    ) -> DescribeDetectorModelResponse:
        raise NotImplementedError

    @handler("DescribeDetectorModelAnalysis")
    def describe_detector_model_analysis(
        self, context: RequestContext, analysis_id: AnalysisId
    ) -> DescribeDetectorModelAnalysisResponse:
        raise NotImplementedError

    @handler("DescribeInput")
    def describe_input(
        self, context: RequestContext, input_name: InputName
    ) -> DescribeInputResponse:
        raise NotImplementedError

    @handler("DescribeLoggingOptions")
    def describe_logging_options(
        self,
        context: RequestContext,
    ) -> DescribeLoggingOptionsResponse:
        raise NotImplementedError

    @handler("GetDetectorModelAnalysisResults")
    def get_detector_model_analysis_results(
        self,
        context: RequestContext,
        analysis_id: AnalysisId,
        next_token: NextToken = None,
        max_results: MaxAnalysisResults = None,
    ) -> GetDetectorModelAnalysisResultsResponse:
        raise NotImplementedError

    @handler("ListAlarmModelVersions")
    def list_alarm_model_versions(
        self,
        context: RequestContext,
        alarm_model_name: AlarmModelName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAlarmModelVersionsResponse:
        raise NotImplementedError

    @handler("ListAlarmModels")
    def list_alarm_models(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListAlarmModelsResponse:
        raise NotImplementedError

    @handler("ListDetectorModelVersions")
    def list_detector_model_versions(
        self,
        context: RequestContext,
        detector_model_name: DetectorModelName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListDetectorModelVersionsResponse:
        raise NotImplementedError

    @handler("ListDetectorModels")
    def list_detector_models(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListDetectorModelsResponse:
        raise NotImplementedError

    @handler("ListInputRoutings")
    def list_input_routings(
        self,
        context: RequestContext,
        input_identifier: InputIdentifier,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> ListInputRoutingsResponse:
        raise NotImplementedError

    @handler("ListInputs")
    def list_inputs(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListInputsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutLoggingOptions")
    def put_logging_options(self, context: RequestContext, logging_options: LoggingOptions) -> None:
        raise NotImplementedError

    @handler("StartDetectorModelAnalysis")
    def start_detector_model_analysis(
        self, context: RequestContext, detector_model_definition: DetectorModelDefinition
    ) -> StartDetectorModelAnalysisResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: Tags
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeys
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateAlarmModel")
    def update_alarm_model(
        self,
        context: RequestContext,
        alarm_model_name: AlarmModelName,
        role_arn: AmazonResourceName,
        alarm_rule: AlarmRule,
        alarm_model_description: AlarmModelDescription = None,
        severity: Severity = None,
        alarm_notification: AlarmNotification = None,
        alarm_event_actions: AlarmEventActions = None,
        alarm_capabilities: AlarmCapabilities = None,
    ) -> UpdateAlarmModelResponse:
        raise NotImplementedError

    @handler("UpdateDetectorModel")
    def update_detector_model(
        self,
        context: RequestContext,
        detector_model_name: DetectorModelName,
        detector_model_definition: DetectorModelDefinition,
        role_arn: AmazonResourceName,
        detector_model_description: DetectorModelDescription = None,
        evaluation_method: EvaluationMethod = None,
    ) -> UpdateDetectorModelResponse:
        raise NotImplementedError

    @handler("UpdateInput")
    def update_input(
        self,
        context: RequestContext,
        input_name: InputName,
        input_definition: InputDefinition,
        input_description: InputDescription = None,
    ) -> UpdateInputResponse:
        raise NotImplementedError
