import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Cooldown = int
DisableScaleIn = bool
ErrorMessage = str
MaxResults = int
MetricDimensionName = str
MetricDimensionValue = str
MetricName = str
MetricNamespace = str
MetricScale = float
MetricUnit = str
MinAdjustmentMagnitude = int
PolicyName = str
ResourceCapacity = int
ResourceId = str
ResourceIdMaxLen1600 = str
ResourceLabel = str
ScalingAdjustment = int
ScalingSuspended = bool
ScheduledActionName = str
XmlString = str


class AdjustmentType(str):
    ChangeInCapacity = "ChangeInCapacity"
    PercentChangeInCapacity = "PercentChangeInCapacity"
    ExactCapacity = "ExactCapacity"


class MetricAggregationType(str):
    Average = "Average"
    Minimum = "Minimum"
    Maximum = "Maximum"


class MetricStatistic(str):
    Average = "Average"
    Minimum = "Minimum"
    Maximum = "Maximum"
    SampleCount = "SampleCount"
    Sum = "Sum"


class MetricType(str):
    DynamoDBReadCapacityUtilization = "DynamoDBReadCapacityUtilization"
    DynamoDBWriteCapacityUtilization = "DynamoDBWriteCapacityUtilization"
    ALBRequestCountPerTarget = "ALBRequestCountPerTarget"
    RDSReaderAverageCPUUtilization = "RDSReaderAverageCPUUtilization"
    RDSReaderAverageDatabaseConnections = "RDSReaderAverageDatabaseConnections"
    EC2SpotFleetRequestAverageCPUUtilization = "EC2SpotFleetRequestAverageCPUUtilization"
    EC2SpotFleetRequestAverageNetworkIn = "EC2SpotFleetRequestAverageNetworkIn"
    EC2SpotFleetRequestAverageNetworkOut = "EC2SpotFleetRequestAverageNetworkOut"
    SageMakerVariantInvocationsPerInstance = "SageMakerVariantInvocationsPerInstance"
    ECSServiceAverageCPUUtilization = "ECSServiceAverageCPUUtilization"
    ECSServiceAverageMemoryUtilization = "ECSServiceAverageMemoryUtilization"
    AppStreamAverageCapacityUtilization = "AppStreamAverageCapacityUtilization"
    ComprehendInferenceUtilization = "ComprehendInferenceUtilization"
    LambdaProvisionedConcurrencyUtilization = "LambdaProvisionedConcurrencyUtilization"
    CassandraReadCapacityUtilization = "CassandraReadCapacityUtilization"
    CassandraWriteCapacityUtilization = "CassandraWriteCapacityUtilization"
    KafkaBrokerStorageUtilization = "KafkaBrokerStorageUtilization"
    ElastiCachePrimaryEngineCPUUtilization = "ElastiCachePrimaryEngineCPUUtilization"
    ElastiCacheReplicaEngineCPUUtilization = "ElastiCacheReplicaEngineCPUUtilization"
    ElastiCacheDatabaseMemoryUsageCountedForEvictPercentage = (
        "ElastiCacheDatabaseMemoryUsageCountedForEvictPercentage"
    )
    NeptuneReaderAverageCPUUtilization = "NeptuneReaderAverageCPUUtilization"


class PolicyType(str):
    StepScaling = "StepScaling"
    TargetTrackingScaling = "TargetTrackingScaling"


class ScalableDimension(str):
    ecs_service_DesiredCount = "ecs:service:DesiredCount"
    ec2_spot_fleet_request_TargetCapacity = "ec2:spot-fleet-request:TargetCapacity"
    elasticmapreduce_instancegroup_InstanceCount = "elasticmapreduce:instancegroup:InstanceCount"
    appstream_fleet_DesiredCapacity = "appstream:fleet:DesiredCapacity"
    dynamodb_table_ReadCapacityUnits = "dynamodb:table:ReadCapacityUnits"
    dynamodb_table_WriteCapacityUnits = "dynamodb:table:WriteCapacityUnits"
    dynamodb_index_ReadCapacityUnits = "dynamodb:index:ReadCapacityUnits"
    dynamodb_index_WriteCapacityUnits = "dynamodb:index:WriteCapacityUnits"
    rds_cluster_ReadReplicaCount = "rds:cluster:ReadReplicaCount"
    sagemaker_variant_DesiredInstanceCount = "sagemaker:variant:DesiredInstanceCount"
    custom_resource_ResourceType_Property = "custom-resource:ResourceType:Property"
    comprehend_document_classifier_endpoint_DesiredInferenceUnits = (
        "comprehend:document-classifier-endpoint:DesiredInferenceUnits"
    )
    comprehend_entity_recognizer_endpoint_DesiredInferenceUnits = (
        "comprehend:entity-recognizer-endpoint:DesiredInferenceUnits"
    )
    lambda_function_ProvisionedConcurrency = "lambda:function:ProvisionedConcurrency"
    cassandra_table_ReadCapacityUnits = "cassandra:table:ReadCapacityUnits"
    cassandra_table_WriteCapacityUnits = "cassandra:table:WriteCapacityUnits"
    kafka_broker_storage_VolumeSize = "kafka:broker-storage:VolumeSize"
    elasticache_replication_group_NodeGroups = "elasticache:replication-group:NodeGroups"
    elasticache_replication_group_Replicas = "elasticache:replication-group:Replicas"
    neptune_cluster_ReadReplicaCount = "neptune:cluster:ReadReplicaCount"


class ScalingActivityStatusCode(str):
    Pending = "Pending"
    InProgress = "InProgress"
    Successful = "Successful"
    Overridden = "Overridden"
    Unfulfilled = "Unfulfilled"
    Failed = "Failed"


class ServiceNamespace(str):
    ecs = "ecs"
    elasticmapreduce = "elasticmapreduce"
    ec2 = "ec2"
    appstream = "appstream"
    dynamodb = "dynamodb"
    rds = "rds"
    sagemaker = "sagemaker"
    custom_resource = "custom-resource"
    comprehend = "comprehend"
    lambda_ = "lambda"
    cassandra = "cassandra"
    kafka = "kafka"
    elasticache = "elasticache"
    neptune = "neptune"


class ConcurrentUpdateException(ServiceException):
    Message: Optional[ErrorMessage]


class FailedResourceAccessException(ServiceException):
    Message: Optional[ErrorMessage]


class InternalServiceException(ServiceException):
    Message: Optional[ErrorMessage]


class InvalidNextTokenException(ServiceException):
    Message: Optional[ErrorMessage]


class LimitExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class ObjectNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class ValidationException(ServiceException):
    Message: Optional[ErrorMessage]


class Alarm(TypedDict, total=False):
    AlarmName: ResourceId
    AlarmARN: ResourceId


Alarms = List[Alarm]


class MetricDimension(TypedDict, total=False):
    Name: MetricDimensionName
    Value: MetricDimensionValue


MetricDimensions = List[MetricDimension]


class CustomizedMetricSpecification(TypedDict, total=False):
    MetricName: MetricName
    Namespace: MetricNamespace
    Dimensions: Optional[MetricDimensions]
    Statistic: MetricStatistic
    Unit: Optional[MetricUnit]


class DeleteScalingPolicyRequest(ServiceRequest):
    PolicyName: ResourceIdMaxLen1600
    ServiceNamespace: ServiceNamespace
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension


class DeleteScalingPolicyResponse(TypedDict, total=False):
    pass


class DeleteScheduledActionRequest(ServiceRequest):
    ServiceNamespace: ServiceNamespace
    ScheduledActionName: ResourceIdMaxLen1600
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension


class DeleteScheduledActionResponse(TypedDict, total=False):
    pass


class DeregisterScalableTargetRequest(ServiceRequest):
    ServiceNamespace: ServiceNamespace
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension


class DeregisterScalableTargetResponse(TypedDict, total=False):
    pass


ResourceIdsMaxLen1600 = List[ResourceIdMaxLen1600]


class DescribeScalableTargetsRequest(ServiceRequest):
    ServiceNamespace: ServiceNamespace
    ResourceIds: Optional[ResourceIdsMaxLen1600]
    ScalableDimension: Optional[ScalableDimension]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[XmlString]


class SuspendedState(TypedDict, total=False):
    DynamicScalingInSuspended: Optional[ScalingSuspended]
    DynamicScalingOutSuspended: Optional[ScalingSuspended]
    ScheduledScalingSuspended: Optional[ScalingSuspended]


TimestampType = datetime


class ScalableTarget(TypedDict, total=False):
    ServiceNamespace: ServiceNamespace
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension
    MinCapacity: ResourceCapacity
    MaxCapacity: ResourceCapacity
    RoleARN: ResourceIdMaxLen1600
    CreationTime: TimestampType
    SuspendedState: Optional[SuspendedState]


ScalableTargets = List[ScalableTarget]


class DescribeScalableTargetsResponse(TypedDict, total=False):
    ScalableTargets: Optional[ScalableTargets]
    NextToken: Optional[XmlString]


class DescribeScalingActivitiesRequest(ServiceRequest):
    ServiceNamespace: ServiceNamespace
    ResourceId: Optional[ResourceIdMaxLen1600]
    ScalableDimension: Optional[ScalableDimension]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[XmlString]


class ScalingActivity(TypedDict, total=False):
    ActivityId: ResourceId
    ServiceNamespace: ServiceNamespace
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension
    Description: XmlString
    Cause: XmlString
    StartTime: TimestampType
    EndTime: Optional[TimestampType]
    StatusCode: ScalingActivityStatusCode
    StatusMessage: Optional[XmlString]
    Details: Optional[XmlString]


ScalingActivities = List[ScalingActivity]


class DescribeScalingActivitiesResponse(TypedDict, total=False):
    ScalingActivities: Optional[ScalingActivities]
    NextToken: Optional[XmlString]


class DescribeScalingPoliciesRequest(ServiceRequest):
    PolicyNames: Optional[ResourceIdsMaxLen1600]
    ServiceNamespace: ServiceNamespace
    ResourceId: Optional[ResourceIdMaxLen1600]
    ScalableDimension: Optional[ScalableDimension]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[XmlString]


class PredefinedMetricSpecification(TypedDict, total=False):
    PredefinedMetricType: MetricType
    ResourceLabel: Optional[ResourceLabel]


class TargetTrackingScalingPolicyConfiguration(TypedDict, total=False):
    TargetValue: MetricScale
    PredefinedMetricSpecification: Optional[PredefinedMetricSpecification]
    CustomizedMetricSpecification: Optional[CustomizedMetricSpecification]
    ScaleOutCooldown: Optional[Cooldown]
    ScaleInCooldown: Optional[Cooldown]
    DisableScaleIn: Optional[DisableScaleIn]


class StepAdjustment(TypedDict, total=False):
    MetricIntervalLowerBound: Optional[MetricScale]
    MetricIntervalUpperBound: Optional[MetricScale]
    ScalingAdjustment: ScalingAdjustment


StepAdjustments = List[StepAdjustment]


class StepScalingPolicyConfiguration(TypedDict, total=False):
    AdjustmentType: Optional[AdjustmentType]
    StepAdjustments: Optional[StepAdjustments]
    MinAdjustmentMagnitude: Optional[MinAdjustmentMagnitude]
    Cooldown: Optional[Cooldown]
    MetricAggregationType: Optional[MetricAggregationType]


class ScalingPolicy(TypedDict, total=False):
    PolicyARN: ResourceIdMaxLen1600
    PolicyName: PolicyName
    ServiceNamespace: ServiceNamespace
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension
    PolicyType: PolicyType
    StepScalingPolicyConfiguration: Optional[StepScalingPolicyConfiguration]
    TargetTrackingScalingPolicyConfiguration: Optional[TargetTrackingScalingPolicyConfiguration]
    Alarms: Optional[Alarms]
    CreationTime: TimestampType


ScalingPolicies = List[ScalingPolicy]


class DescribeScalingPoliciesResponse(TypedDict, total=False):
    ScalingPolicies: Optional[ScalingPolicies]
    NextToken: Optional[XmlString]


class DescribeScheduledActionsRequest(ServiceRequest):
    ScheduledActionNames: Optional[ResourceIdsMaxLen1600]
    ServiceNamespace: ServiceNamespace
    ResourceId: Optional[ResourceIdMaxLen1600]
    ScalableDimension: Optional[ScalableDimension]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[XmlString]


class ScalableTargetAction(TypedDict, total=False):
    MinCapacity: Optional[ResourceCapacity]
    MaxCapacity: Optional[ResourceCapacity]


class ScheduledAction(TypedDict, total=False):
    ScheduledActionName: ScheduledActionName
    ScheduledActionARN: ResourceIdMaxLen1600
    ServiceNamespace: ServiceNamespace
    Schedule: ResourceIdMaxLen1600
    Timezone: Optional[ResourceIdMaxLen1600]
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: Optional[ScalableDimension]
    StartTime: Optional[TimestampType]
    EndTime: Optional[TimestampType]
    ScalableTargetAction: Optional[ScalableTargetAction]
    CreationTime: TimestampType


ScheduledActions = List[ScheduledAction]


class DescribeScheduledActionsResponse(TypedDict, total=False):
    ScheduledActions: Optional[ScheduledActions]
    NextToken: Optional[XmlString]


class PutScalingPolicyRequest(ServiceRequest):
    PolicyName: PolicyName
    ServiceNamespace: ServiceNamespace
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension
    PolicyType: Optional[PolicyType]
    StepScalingPolicyConfiguration: Optional[StepScalingPolicyConfiguration]
    TargetTrackingScalingPolicyConfiguration: Optional[TargetTrackingScalingPolicyConfiguration]


class PutScalingPolicyResponse(TypedDict, total=False):
    PolicyARN: ResourceIdMaxLen1600
    Alarms: Optional[Alarms]


class PutScheduledActionRequest(ServiceRequest):
    ServiceNamespace: ServiceNamespace
    Schedule: Optional[ResourceIdMaxLen1600]
    Timezone: Optional[ResourceIdMaxLen1600]
    ScheduledActionName: ScheduledActionName
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension
    StartTime: Optional[TimestampType]
    EndTime: Optional[TimestampType]
    ScalableTargetAction: Optional[ScalableTargetAction]


class PutScheduledActionResponse(TypedDict, total=False):
    pass


class RegisterScalableTargetRequest(ServiceRequest):
    ServiceNamespace: ServiceNamespace
    ResourceId: ResourceIdMaxLen1600
    ScalableDimension: ScalableDimension
    MinCapacity: Optional[ResourceCapacity]
    MaxCapacity: Optional[ResourceCapacity]
    RoleARN: Optional[ResourceIdMaxLen1600]
    SuspendedState: Optional[SuspendedState]


class RegisterScalableTargetResponse(TypedDict, total=False):
    pass


class ApplicationAutoscalingApi:

    service = "application-autoscaling"
    version = "2016-02-06"

    @handler("DeleteScalingPolicy")
    def delete_scaling_policy(
        self,
        context: RequestContext,
        policy_name: ResourceIdMaxLen1600,
        service_namespace: ServiceNamespace,
        resource_id: ResourceIdMaxLen1600,
        scalable_dimension: ScalableDimension,
    ) -> DeleteScalingPolicyResponse:
        raise NotImplementedError

    @handler("DeleteScheduledAction")
    def delete_scheduled_action(
        self,
        context: RequestContext,
        service_namespace: ServiceNamespace,
        scheduled_action_name: ResourceIdMaxLen1600,
        resource_id: ResourceIdMaxLen1600,
        scalable_dimension: ScalableDimension,
    ) -> DeleteScheduledActionResponse:
        raise NotImplementedError

    @handler("DeregisterScalableTarget")
    def deregister_scalable_target(
        self,
        context: RequestContext,
        service_namespace: ServiceNamespace,
        resource_id: ResourceIdMaxLen1600,
        scalable_dimension: ScalableDimension,
    ) -> DeregisterScalableTargetResponse:
        raise NotImplementedError

    @handler("DescribeScalableTargets")
    def describe_scalable_targets(
        self,
        context: RequestContext,
        service_namespace: ServiceNamespace,
        resource_ids: ResourceIdsMaxLen1600 = None,
        scalable_dimension: ScalableDimension = None,
        max_results: MaxResults = None,
        next_token: XmlString = None,
    ) -> DescribeScalableTargetsResponse:
        raise NotImplementedError

    @handler("DescribeScalingActivities")
    def describe_scaling_activities(
        self,
        context: RequestContext,
        service_namespace: ServiceNamespace,
        resource_id: ResourceIdMaxLen1600 = None,
        scalable_dimension: ScalableDimension = None,
        max_results: MaxResults = None,
        next_token: XmlString = None,
    ) -> DescribeScalingActivitiesResponse:
        raise NotImplementedError

    @handler("DescribeScalingPolicies")
    def describe_scaling_policies(
        self,
        context: RequestContext,
        service_namespace: ServiceNamespace,
        policy_names: ResourceIdsMaxLen1600 = None,
        resource_id: ResourceIdMaxLen1600 = None,
        scalable_dimension: ScalableDimension = None,
        max_results: MaxResults = None,
        next_token: XmlString = None,
    ) -> DescribeScalingPoliciesResponse:
        raise NotImplementedError

    @handler("DescribeScheduledActions")
    def describe_scheduled_actions(
        self,
        context: RequestContext,
        service_namespace: ServiceNamespace,
        scheduled_action_names: ResourceIdsMaxLen1600 = None,
        resource_id: ResourceIdMaxLen1600 = None,
        scalable_dimension: ScalableDimension = None,
        max_results: MaxResults = None,
        next_token: XmlString = None,
    ) -> DescribeScheduledActionsResponse:
        raise NotImplementedError

    @handler("PutScalingPolicy")
    def put_scaling_policy(
        self,
        context: RequestContext,
        policy_name: PolicyName,
        service_namespace: ServiceNamespace,
        resource_id: ResourceIdMaxLen1600,
        scalable_dimension: ScalableDimension,
        policy_type: PolicyType = None,
        step_scaling_policy_configuration: StepScalingPolicyConfiguration = None,
        target_tracking_scaling_policy_configuration: TargetTrackingScalingPolicyConfiguration = None,
    ) -> PutScalingPolicyResponse:
        raise NotImplementedError

    @handler("PutScheduledAction")
    def put_scheduled_action(
        self,
        context: RequestContext,
        service_namespace: ServiceNamespace,
        scheduled_action_name: ScheduledActionName,
        resource_id: ResourceIdMaxLen1600,
        scalable_dimension: ScalableDimension,
        schedule: ResourceIdMaxLen1600 = None,
        timezone: ResourceIdMaxLen1600 = None,
        start_time: TimestampType = None,
        end_time: TimestampType = None,
        scalable_target_action: ScalableTargetAction = None,
    ) -> PutScheduledActionResponse:
        raise NotImplementedError

    @handler("RegisterScalableTarget")
    def register_scalable_target(
        self,
        context: RequestContext,
        service_namespace: ServiceNamespace,
        resource_id: ResourceIdMaxLen1600,
        scalable_dimension: ScalableDimension,
        min_capacity: ResourceCapacity = None,
        max_capacity: ResourceCapacity = None,
        role_arn: ResourceIdMaxLen1600 = None,
        suspended_state: SuspendedState = None,
    ) -> RegisterScalableTargetResponse:
        raise NotImplementedError
