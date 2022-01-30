import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AlarmModelName = str
AlarmModelVersion = str
DetectorModelName = str
DetectorModelVersion = str
EphemeralInputName = str
ErrorMessage = str
InputPropertyValue = str
KeyValue = str
MaxResults = int
MessageId = str
NextToken = str
Note = str
RequestId = str
Seconds = int
Severity = int
SnoozeDuration = int
StateName = str
ThresholdValue = str
TimerName = str
VariableName = str
VariableValue = str
errorMessage = str


class AlarmStateName(str):
    DISABLED = "DISABLED"
    NORMAL = "NORMAL"
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    SNOOZE_DISABLED = "SNOOZE_DISABLED"
    LATCHED = "LATCHED"


class ComparisonOperator(str):
    GREATER = "GREATER"
    GREATER_OR_EQUAL = "GREATER_OR_EQUAL"
    LESS = "LESS"
    LESS_OR_EQUAL = "LESS_OR_EQUAL"
    EQUAL = "EQUAL"
    NOT_EQUAL = "NOT_EQUAL"


class CustomerActionName(str):
    SNOOZE = "SNOOZE"
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"
    ACKNOWLEDGE = "ACKNOWLEDGE"
    RESET = "RESET"


class ErrorCode(str):
    ResourceNotFoundException = "ResourceNotFoundException"
    InvalidRequestException = "InvalidRequestException"
    InternalFailureException = "InternalFailureException"
    ServiceUnavailableException = "ServiceUnavailableException"
    ThrottlingException = "ThrottlingException"


class EventType(str):
    STATE_CHANGE = "STATE_CHANGE"


class TriggerType(str):
    SNOOZE_TIMEOUT = "SNOOZE_TIMEOUT"


class InternalFailureException(ServiceException):
    message: Optional[errorMessage]


class InvalidRequestException(ServiceException):
    message: Optional[errorMessage]


class ResourceNotFoundException(ServiceException):
    message: Optional[errorMessage]


class ServiceUnavailableException(ServiceException):
    message: Optional[errorMessage]


class ThrottlingException(ServiceException):
    message: Optional[errorMessage]


class AcknowledgeActionConfiguration(TypedDict, total=False):
    note: Optional[Note]


class AcknowledgeAlarmActionRequest(TypedDict, total=False):
    requestId: RequestId
    alarmModelName: AlarmModelName
    keyValue: Optional[KeyValue]
    note: Optional[Note]


AcknowledgeAlarmActionRequests = List[AcknowledgeAlarmActionRequest]
Timestamp = datetime


class StateChangeConfiguration(TypedDict, total=False):
    triggerType: Optional[TriggerType]


class SystemEvent(TypedDict, total=False):
    eventType: Optional[EventType]
    stateChangeConfiguration: Optional[StateChangeConfiguration]


class ResetActionConfiguration(TypedDict, total=False):
    note: Optional[Note]


class DisableActionConfiguration(TypedDict, total=False):
    note: Optional[Note]


class EnableActionConfiguration(TypedDict, total=False):
    note: Optional[Note]


class SnoozeActionConfiguration(TypedDict, total=False):
    snoozeDuration: Optional[SnoozeDuration]
    note: Optional[Note]


class CustomerAction(TypedDict, total=False):
    actionName: Optional[CustomerActionName]
    snoozeActionConfiguration: Optional[SnoozeActionConfiguration]
    enableActionConfiguration: Optional[EnableActionConfiguration]
    disableActionConfiguration: Optional[DisableActionConfiguration]
    acknowledgeActionConfiguration: Optional[AcknowledgeActionConfiguration]
    resetActionConfiguration: Optional[ResetActionConfiguration]


class SimpleRuleEvaluation(TypedDict, total=False):
    inputPropertyValue: Optional[InputPropertyValue]
    operator: Optional[ComparisonOperator]
    thresholdValue: Optional[ThresholdValue]


class RuleEvaluation(TypedDict, total=False):
    simpleRuleEvaluation: Optional[SimpleRuleEvaluation]


class AlarmState(TypedDict, total=False):
    stateName: Optional[AlarmStateName]
    ruleEvaluation: Optional[RuleEvaluation]
    customerAction: Optional[CustomerAction]
    systemEvent: Optional[SystemEvent]


class Alarm(TypedDict, total=False):
    alarmModelName: Optional[AlarmModelName]
    alarmModelVersion: Optional[AlarmModelVersion]
    keyValue: Optional[KeyValue]
    alarmState: Optional[AlarmState]
    severity: Optional[Severity]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]


class AlarmSummary(TypedDict, total=False):
    alarmModelName: Optional[AlarmModelName]
    alarmModelVersion: Optional[AlarmModelVersion]
    keyValue: Optional[KeyValue]
    stateName: Optional[AlarmStateName]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]


AlarmSummaries = List[AlarmSummary]


class BatchAcknowledgeAlarmRequest(ServiceRequest):
    acknowledgeActionRequests: AcknowledgeAlarmActionRequests


class BatchAlarmActionErrorEntry(TypedDict, total=False):
    requestId: Optional[RequestId]
    errorCode: Optional[ErrorCode]
    errorMessage: Optional[ErrorMessage]


BatchAlarmActionErrorEntries = List[BatchAlarmActionErrorEntry]


class BatchAcknowledgeAlarmResponse(TypedDict, total=False):
    errorEntries: Optional[BatchAlarmActionErrorEntries]


class DisableAlarmActionRequest(TypedDict, total=False):
    requestId: RequestId
    alarmModelName: AlarmModelName
    keyValue: Optional[KeyValue]
    note: Optional[Note]


DisableAlarmActionRequests = List[DisableAlarmActionRequest]


class BatchDisableAlarmRequest(ServiceRequest):
    disableActionRequests: DisableAlarmActionRequests


class BatchDisableAlarmResponse(TypedDict, total=False):
    errorEntries: Optional[BatchAlarmActionErrorEntries]


class EnableAlarmActionRequest(TypedDict, total=False):
    requestId: RequestId
    alarmModelName: AlarmModelName
    keyValue: Optional[KeyValue]
    note: Optional[Note]


EnableAlarmActionRequests = List[EnableAlarmActionRequest]


class BatchEnableAlarmRequest(ServiceRequest):
    enableActionRequests: EnableAlarmActionRequests


class BatchEnableAlarmResponse(TypedDict, total=False):
    errorEntries: Optional[BatchAlarmActionErrorEntries]


class BatchPutMessageErrorEntry(TypedDict, total=False):
    messageId: Optional[MessageId]
    errorCode: Optional[ErrorCode]
    errorMessage: Optional[ErrorMessage]


BatchPutMessageErrorEntries = List[BatchPutMessageErrorEntry]
EpochMilliTimestamp = int


class TimestampValue(TypedDict, total=False):
    timeInMillis: Optional[EpochMilliTimestamp]


Payload = bytes


class Message(TypedDict, total=False):
    messageId: MessageId
    inputName: EphemeralInputName
    payload: Payload
    timestamp: Optional[TimestampValue]


Messages = List[Message]


class BatchPutMessageRequest(ServiceRequest):
    messages: Messages


class BatchPutMessageResponse(TypedDict, total=False):
    BatchPutMessageErrorEntries: Optional[BatchPutMessageErrorEntries]


class ResetAlarmActionRequest(TypedDict, total=False):
    requestId: RequestId
    alarmModelName: AlarmModelName
    keyValue: Optional[KeyValue]
    note: Optional[Note]


ResetAlarmActionRequests = List[ResetAlarmActionRequest]


class BatchResetAlarmRequest(ServiceRequest):
    resetActionRequests: ResetAlarmActionRequests


class BatchResetAlarmResponse(TypedDict, total=False):
    errorEntries: Optional[BatchAlarmActionErrorEntries]


class SnoozeAlarmActionRequest(TypedDict, total=False):
    requestId: RequestId
    alarmModelName: AlarmModelName
    keyValue: Optional[KeyValue]
    note: Optional[Note]
    snoozeDuration: SnoozeDuration


SnoozeAlarmActionRequests = List[SnoozeAlarmActionRequest]


class BatchSnoozeAlarmRequest(ServiceRequest):
    snoozeActionRequests: SnoozeAlarmActionRequests


class BatchSnoozeAlarmResponse(TypedDict, total=False):
    errorEntries: Optional[BatchAlarmActionErrorEntries]


class BatchUpdateDetectorErrorEntry(TypedDict, total=False):
    messageId: Optional[MessageId]
    errorCode: Optional[ErrorCode]
    errorMessage: Optional[ErrorMessage]


BatchUpdateDetectorErrorEntries = List[BatchUpdateDetectorErrorEntry]


class TimerDefinition(TypedDict, total=False):
    name: TimerName
    seconds: Seconds


TimerDefinitions = List[TimerDefinition]


class VariableDefinition(TypedDict, total=False):
    name: VariableName
    value: VariableValue


VariableDefinitions = List[VariableDefinition]


class DetectorStateDefinition(TypedDict, total=False):
    stateName: StateName
    variables: VariableDefinitions
    timers: TimerDefinitions


class UpdateDetectorRequest(TypedDict, total=False):
    messageId: MessageId
    detectorModelName: DetectorModelName
    keyValue: Optional[KeyValue]
    state: DetectorStateDefinition


UpdateDetectorRequests = List[UpdateDetectorRequest]


class BatchUpdateDetectorRequest(ServiceRequest):
    detectors: UpdateDetectorRequests


class BatchUpdateDetectorResponse(TypedDict, total=False):
    batchUpdateDetectorErrorEntries: Optional[BatchUpdateDetectorErrorEntries]


class DescribeAlarmRequest(ServiceRequest):
    alarmModelName: AlarmModelName
    keyValue: Optional[KeyValue]


class DescribeAlarmResponse(TypedDict, total=False):
    alarm: Optional[Alarm]


class DescribeDetectorRequest(ServiceRequest):
    detectorModelName: DetectorModelName
    keyValue: Optional[KeyValue]


class Timer(TypedDict, total=False):
    name: TimerName
    timestamp: Timestamp


Timers = List[Timer]


class Variable(TypedDict, total=False):
    name: VariableName
    value: VariableValue


Variables = List[Variable]


class DetectorState(TypedDict, total=False):
    stateName: StateName
    variables: Variables
    timers: Timers


class Detector(TypedDict, total=False):
    detectorModelName: Optional[DetectorModelName]
    keyValue: Optional[KeyValue]
    detectorModelVersion: Optional[DetectorModelVersion]
    state: Optional[DetectorState]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]


class DescribeDetectorResponse(TypedDict, total=False):
    detector: Optional[Detector]


class DetectorStateSummary(TypedDict, total=False):
    stateName: Optional[StateName]


class DetectorSummary(TypedDict, total=False):
    detectorModelName: Optional[DetectorModelName]
    keyValue: Optional[KeyValue]
    detectorModelVersion: Optional[DetectorModelVersion]
    state: Optional[DetectorStateSummary]
    creationTime: Optional[Timestamp]
    lastUpdateTime: Optional[Timestamp]


DetectorSummaries = List[DetectorSummary]


class ListAlarmsRequest(ServiceRequest):
    alarmModelName: AlarmModelName
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListAlarmsResponse(TypedDict, total=False):
    alarmSummaries: Optional[AlarmSummaries]
    nextToken: Optional[NextToken]


class ListDetectorsRequest(ServiceRequest):
    detectorModelName: DetectorModelName
    stateName: Optional[StateName]
    nextToken: Optional[NextToken]
    maxResults: Optional[MaxResults]


class ListDetectorsResponse(TypedDict, total=False):
    detectorSummaries: Optional[DetectorSummaries]
    nextToken: Optional[NextToken]


class IoteventsDataApi:

    service = "iotevents-data"
    version = "2018-10-23"

    @handler("BatchAcknowledgeAlarm")
    def batch_acknowledge_alarm(
        self, context: RequestContext, acknowledge_action_requests: AcknowledgeAlarmActionRequests
    ) -> BatchAcknowledgeAlarmResponse:
        raise NotImplementedError

    @handler("BatchDisableAlarm")
    def batch_disable_alarm(
        self, context: RequestContext, disable_action_requests: DisableAlarmActionRequests
    ) -> BatchDisableAlarmResponse:
        raise NotImplementedError

    @handler("BatchEnableAlarm")
    def batch_enable_alarm(
        self, context: RequestContext, enable_action_requests: EnableAlarmActionRequests
    ) -> BatchEnableAlarmResponse:
        raise NotImplementedError

    @handler("BatchPutMessage")
    def batch_put_message(
        self, context: RequestContext, messages: Messages
    ) -> BatchPutMessageResponse:
        raise NotImplementedError

    @handler("BatchResetAlarm")
    def batch_reset_alarm(
        self, context: RequestContext, reset_action_requests: ResetAlarmActionRequests
    ) -> BatchResetAlarmResponse:
        raise NotImplementedError

    @handler("BatchSnoozeAlarm")
    def batch_snooze_alarm(
        self, context: RequestContext, snooze_action_requests: SnoozeAlarmActionRequests
    ) -> BatchSnoozeAlarmResponse:
        raise NotImplementedError

    @handler("BatchUpdateDetector")
    def batch_update_detector(
        self, context: RequestContext, detectors: UpdateDetectorRequests
    ) -> BatchUpdateDetectorResponse:
        raise NotImplementedError

    @handler("DescribeAlarm")
    def describe_alarm(
        self, context: RequestContext, alarm_model_name: AlarmModelName, key_value: KeyValue = None
    ) -> DescribeAlarmResponse:
        raise NotImplementedError

    @handler("DescribeDetector")
    def describe_detector(
        self,
        context: RequestContext,
        detector_model_name: DetectorModelName,
        key_value: KeyValue = None,
    ) -> DescribeDetectorResponse:
        raise NotImplementedError

    @handler("ListAlarms")
    def list_alarms(
        self,
        context: RequestContext,
        alarm_model_name: AlarmModelName,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListAlarmsResponse:
        raise NotImplementedError

    @handler("ListDetectors")
    def list_detectors(
        self,
        context: RequestContext,
        detector_model_name: DetectorModelName,
        state_name: StateName = None,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListDetectorsResponse:
        raise NotImplementedError
