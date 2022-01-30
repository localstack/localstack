import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

Arn = str
ConfigurationProfileType = str
DeploymentStrategyId = str
Description = str
Float = float
GrowthFactor = float
Id = str
Integer = int
MaxResults = int
MinutesBetween0And24Hours = int
Name = str
NextToken = str
Percentage = float
RoleArn = str
String = str
StringWithLengthBetween0And32768 = str
StringWithLengthBetween1And2048 = str
StringWithLengthBetween1And255 = str
StringWithLengthBetween1And64 = str
TagKey = str
TagValue = str
Uri = str
Version = str


class BadRequestReason(str):
    InvalidConfiguration = "InvalidConfiguration"


class BytesMeasure(str):
    KILOBYTES = "KILOBYTES"


class DeploymentEventType(str):
    PERCENTAGE_UPDATED = "PERCENTAGE_UPDATED"
    ROLLBACK_STARTED = "ROLLBACK_STARTED"
    ROLLBACK_COMPLETED = "ROLLBACK_COMPLETED"
    BAKE_TIME_STARTED = "BAKE_TIME_STARTED"
    DEPLOYMENT_STARTED = "DEPLOYMENT_STARTED"
    DEPLOYMENT_COMPLETED = "DEPLOYMENT_COMPLETED"


class DeploymentState(str):
    BAKING = "BAKING"
    VALIDATING = "VALIDATING"
    DEPLOYING = "DEPLOYING"
    COMPLETE = "COMPLETE"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"


class EnvironmentState(str):
    READY_FOR_DEPLOYMENT = "READY_FOR_DEPLOYMENT"
    DEPLOYING = "DEPLOYING"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"


class GrowthType(str):
    LINEAR = "LINEAR"
    EXPONENTIAL = "EXPONENTIAL"


class ReplicateTo(str):
    NONE = "NONE"
    SSM_DOCUMENT = "SSM_DOCUMENT"


class TriggeredBy(str):
    USER = "USER"
    APPCONFIG = "APPCONFIG"
    CLOUDWATCH_ALARM = "CLOUDWATCH_ALARM"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ValidatorType(str):
    JSON_SCHEMA = "JSON_SCHEMA"
    LAMBDA = "LAMBDA"


class InvalidConfigurationDetail(TypedDict, total=False):
    Constraint: Optional[String]
    Location: Optional[String]
    Reason: Optional[String]
    Type: Optional[String]


InvalidConfigurationDetailList = List[InvalidConfigurationDetail]


class BadRequestDetails(TypedDict, total=False):
    InvalidConfiguration: Optional[InvalidConfigurationDetailList]


class BadRequestException(ServiceException):
    Message: Optional[String]
    Reason: Optional[BadRequestReason]
    Details: Optional[BadRequestDetails]


class ConflictException(ServiceException):
    Message: Optional[String]


class InternalServerException(ServiceException):
    Message: Optional[String]


class PayloadTooLargeException(ServiceException):
    Message: Optional[String]
    Measure: Optional[BytesMeasure]
    Limit: Optional[Float]
    Size: Optional[Float]


class ResourceNotFoundException(ServiceException):
    Message: Optional[String]
    ResourceName: Optional[String]


class ServiceQuotaExceededException(ServiceException):
    Message: Optional[String]


class Application(TypedDict, total=False):
    Id: Optional[Id]
    Name: Optional[Name]
    Description: Optional[Description]


ApplicationList = List[Application]


class Applications(TypedDict, total=False):
    Items: Optional[ApplicationList]
    NextToken: Optional[NextToken]


Blob = bytes


class Configuration(TypedDict, total=False):
    Content: Optional[Blob]
    ConfigurationVersion: Optional[Version]
    ContentType: Optional[String]


class Validator(TypedDict, total=False):
    Type: ValidatorType
    Content: StringWithLengthBetween0And32768


ValidatorList = List[Validator]


class ConfigurationProfile(TypedDict, total=False):
    ApplicationId: Optional[Id]
    Id: Optional[Id]
    Name: Optional[Name]
    Description: Optional[Description]
    LocationUri: Optional[Uri]
    RetrievalRoleArn: Optional[RoleArn]
    Validators: Optional[ValidatorList]
    Type: Optional[ConfigurationProfileType]


ValidatorTypeList = List[ValidatorType]


class ConfigurationProfileSummary(TypedDict, total=False):
    ApplicationId: Optional[Id]
    Id: Optional[Id]
    Name: Optional[Name]
    LocationUri: Optional[Uri]
    ValidatorTypes: Optional[ValidatorTypeList]
    Type: Optional[ConfigurationProfileType]


ConfigurationProfileSummaryList = List[ConfigurationProfileSummary]


class ConfigurationProfiles(TypedDict, total=False):
    Items: Optional[ConfigurationProfileSummaryList]
    NextToken: Optional[NextToken]


TagMap = Dict[TagKey, TagValue]


class CreateApplicationRequest(ServiceRequest):
    Name: Name
    Description: Optional[Description]
    Tags: Optional[TagMap]


class CreateConfigurationProfileRequest(ServiceRequest):
    ApplicationId: Id
    Name: Name
    Description: Optional[Description]
    LocationUri: Uri
    RetrievalRoleArn: Optional[RoleArn]
    Validators: Optional[ValidatorList]
    Tags: Optional[TagMap]
    Type: Optional[ConfigurationProfileType]


class CreateDeploymentStrategyRequest(ServiceRequest):
    Name: Name
    Description: Optional[Description]
    DeploymentDurationInMinutes: MinutesBetween0And24Hours
    FinalBakeTimeInMinutes: Optional[MinutesBetween0And24Hours]
    GrowthFactor: GrowthFactor
    GrowthType: Optional[GrowthType]
    ReplicateTo: ReplicateTo
    Tags: Optional[TagMap]


class Monitor(TypedDict, total=False):
    AlarmArn: StringWithLengthBetween1And2048
    AlarmRoleArn: Optional[RoleArn]


MonitorList = List[Monitor]


class CreateEnvironmentRequest(ServiceRequest):
    ApplicationId: Id
    Name: Name
    Description: Optional[Description]
    Monitors: Optional[MonitorList]
    Tags: Optional[TagMap]


class CreateHostedConfigurationVersionRequest(ServiceRequest):
    ApplicationId: Id
    ConfigurationProfileId: Id
    Description: Optional[Description]
    Content: Blob
    ContentType: StringWithLengthBetween1And255
    LatestVersionNumber: Optional[Integer]


class DeleteApplicationRequest(ServiceRequest):
    ApplicationId: Id


class DeleteConfigurationProfileRequest(ServiceRequest):
    ApplicationId: Id
    ConfigurationProfileId: Id


class DeleteDeploymentStrategyRequest(ServiceRequest):
    DeploymentStrategyId: DeploymentStrategyId


class DeleteEnvironmentRequest(ServiceRequest):
    ApplicationId: Id
    EnvironmentId: Id


class DeleteHostedConfigurationVersionRequest(ServiceRequest):
    ApplicationId: Id
    ConfigurationProfileId: Id
    VersionNumber: Integer


Iso8601DateTime = datetime


class DeploymentEvent(TypedDict, total=False):
    EventType: Optional[DeploymentEventType]
    TriggeredBy: Optional[TriggeredBy]
    Description: Optional[Description]
    OccurredAt: Optional[Iso8601DateTime]


DeploymentEvents = List[DeploymentEvent]


class Deployment(TypedDict, total=False):
    ApplicationId: Optional[Id]
    EnvironmentId: Optional[Id]
    DeploymentStrategyId: Optional[Id]
    ConfigurationProfileId: Optional[Id]
    DeploymentNumber: Optional[Integer]
    ConfigurationName: Optional[Name]
    ConfigurationLocationUri: Optional[Uri]
    ConfigurationVersion: Optional[Version]
    Description: Optional[Description]
    DeploymentDurationInMinutes: Optional[MinutesBetween0And24Hours]
    GrowthType: Optional[GrowthType]
    GrowthFactor: Optional[Percentage]
    FinalBakeTimeInMinutes: Optional[MinutesBetween0And24Hours]
    State: Optional[DeploymentState]
    EventLog: Optional[DeploymentEvents]
    PercentageComplete: Optional[Percentage]
    StartedAt: Optional[Iso8601DateTime]
    CompletedAt: Optional[Iso8601DateTime]


class DeploymentSummary(TypedDict, total=False):
    DeploymentNumber: Optional[Integer]
    ConfigurationName: Optional[Name]
    ConfigurationVersion: Optional[Version]
    DeploymentDurationInMinutes: Optional[MinutesBetween0And24Hours]
    GrowthType: Optional[GrowthType]
    GrowthFactor: Optional[Percentage]
    FinalBakeTimeInMinutes: Optional[MinutesBetween0And24Hours]
    State: Optional[DeploymentState]
    PercentageComplete: Optional[Percentage]
    StartedAt: Optional[Iso8601DateTime]
    CompletedAt: Optional[Iso8601DateTime]


DeploymentList = List[DeploymentSummary]


class DeploymentStrategy(TypedDict, total=False):
    Id: Optional[Id]
    Name: Optional[Name]
    Description: Optional[Description]
    DeploymentDurationInMinutes: Optional[MinutesBetween0And24Hours]
    GrowthType: Optional[GrowthType]
    GrowthFactor: Optional[Percentage]
    FinalBakeTimeInMinutes: Optional[MinutesBetween0And24Hours]
    ReplicateTo: Optional[ReplicateTo]


DeploymentStrategyList = List[DeploymentStrategy]


class DeploymentStrategies(TypedDict, total=False):
    Items: Optional[DeploymentStrategyList]
    NextToken: Optional[NextToken]


class Deployments(TypedDict, total=False):
    Items: Optional[DeploymentList]
    NextToken: Optional[NextToken]


class Environment(TypedDict, total=False):
    ApplicationId: Optional[Id]
    Id: Optional[Id]
    Name: Optional[Name]
    Description: Optional[Description]
    State: Optional[EnvironmentState]
    Monitors: Optional[MonitorList]


EnvironmentList = List[Environment]


class Environments(TypedDict, total=False):
    Items: Optional[EnvironmentList]
    NextToken: Optional[NextToken]


class GetApplicationRequest(ServiceRequest):
    ApplicationId: Id


class GetConfigurationProfileRequest(ServiceRequest):
    ApplicationId: Id
    ConfigurationProfileId: Id


class GetConfigurationRequest(ServiceRequest):
    Application: StringWithLengthBetween1And64
    Environment: StringWithLengthBetween1And64
    Configuration: StringWithLengthBetween1And64
    ClientId: StringWithLengthBetween1And64
    ClientConfigurationVersion: Optional[Version]


class GetDeploymentRequest(ServiceRequest):
    ApplicationId: Id
    EnvironmentId: Id
    DeploymentNumber: Integer


class GetDeploymentStrategyRequest(ServiceRequest):
    DeploymentStrategyId: DeploymentStrategyId


class GetEnvironmentRequest(ServiceRequest):
    ApplicationId: Id
    EnvironmentId: Id


class GetHostedConfigurationVersionRequest(ServiceRequest):
    ApplicationId: Id
    ConfigurationProfileId: Id
    VersionNumber: Integer


class HostedConfigurationVersion(TypedDict, total=False):
    ApplicationId: Optional[Id]
    ConfigurationProfileId: Optional[Id]
    VersionNumber: Optional[Integer]
    Description: Optional[Description]
    Content: Optional[Blob]
    ContentType: Optional[StringWithLengthBetween1And255]


class HostedConfigurationVersionSummary(TypedDict, total=False):
    ApplicationId: Optional[Id]
    ConfigurationProfileId: Optional[Id]
    VersionNumber: Optional[Integer]
    Description: Optional[Description]
    ContentType: Optional[StringWithLengthBetween1And255]


HostedConfigurationVersionSummaryList = List[HostedConfigurationVersionSummary]


class HostedConfigurationVersions(TypedDict, total=False):
    Items: Optional[HostedConfigurationVersionSummaryList]
    NextToken: Optional[NextToken]


class ListApplicationsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListConfigurationProfilesRequest(ServiceRequest):
    ApplicationId: Id
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    Type: Optional[ConfigurationProfileType]


class ListDeploymentStrategiesRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListDeploymentsRequest(ServiceRequest):
    ApplicationId: Id
    EnvironmentId: Id
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListEnvironmentsRequest(ServiceRequest):
    ApplicationId: Id
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListHostedConfigurationVersionsRequest(ServiceRequest):
    ApplicationId: Id
    ConfigurationProfileId: Id
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: Arn


class ResourceTags(TypedDict, total=False):
    Tags: Optional[TagMap]


class StartDeploymentRequest(ServiceRequest):
    ApplicationId: Id
    EnvironmentId: Id
    DeploymentStrategyId: DeploymentStrategyId
    ConfigurationProfileId: Id
    ConfigurationVersion: Version
    Description: Optional[Description]
    Tags: Optional[TagMap]


class StopDeploymentRequest(ServiceRequest):
    ApplicationId: Id
    EnvironmentId: Id
    DeploymentNumber: Integer


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: Arn
    Tags: TagMap


class UntagResourceRequest(ServiceRequest):
    ResourceArn: Arn
    TagKeys: TagKeyList


class UpdateApplicationRequest(ServiceRequest):
    ApplicationId: Id
    Name: Optional[Name]
    Description: Optional[Description]


class UpdateConfigurationProfileRequest(ServiceRequest):
    ApplicationId: Id
    ConfigurationProfileId: Id
    Name: Optional[Name]
    Description: Optional[Description]
    RetrievalRoleArn: Optional[RoleArn]
    Validators: Optional[ValidatorList]


class UpdateDeploymentStrategyRequest(ServiceRequest):
    DeploymentStrategyId: DeploymentStrategyId
    Description: Optional[Description]
    DeploymentDurationInMinutes: Optional[MinutesBetween0And24Hours]
    FinalBakeTimeInMinutes: Optional[MinutesBetween0And24Hours]
    GrowthFactor: Optional[GrowthFactor]
    GrowthType: Optional[GrowthType]


class UpdateEnvironmentRequest(ServiceRequest):
    ApplicationId: Id
    EnvironmentId: Id
    Name: Optional[Name]
    Description: Optional[Description]
    Monitors: Optional[MonitorList]


class ValidateConfigurationRequest(ServiceRequest):
    ApplicationId: Id
    ConfigurationProfileId: Id
    ConfigurationVersion: Version


class AppconfigApi:

    service = "appconfig"
    version = "2019-10-09"

    @handler("CreateApplication")
    def create_application(
        self,
        context: RequestContext,
        name: Name,
        description: Description = None,
        tags: TagMap = None,
    ) -> Application:
        raise NotImplementedError

    @handler("CreateConfigurationProfile", expand=False)
    def create_configuration_profile(
        self, context: RequestContext, request: CreateConfigurationProfileRequest
    ) -> ConfigurationProfile:
        raise NotImplementedError

    @handler("CreateDeploymentStrategy")
    def create_deployment_strategy(
        self,
        context: RequestContext,
        name: Name,
        deployment_duration_in_minutes: MinutesBetween0And24Hours,
        growth_factor: GrowthFactor,
        replicate_to: ReplicateTo,
        description: Description = None,
        final_bake_time_in_minutes: MinutesBetween0And24Hours = None,
        growth_type: GrowthType = None,
        tags: TagMap = None,
    ) -> DeploymentStrategy:
        raise NotImplementedError

    @handler("CreateEnvironment")
    def create_environment(
        self,
        context: RequestContext,
        application_id: Id,
        name: Name,
        description: Description = None,
        monitors: MonitorList = None,
        tags: TagMap = None,
    ) -> Environment:
        raise NotImplementedError

    @handler("CreateHostedConfigurationVersion")
    def create_hosted_configuration_version(
        self,
        context: RequestContext,
        application_id: Id,
        configuration_profile_id: Id,
        content: Blob,
        content_type: StringWithLengthBetween1And255,
        description: Description = None,
        latest_version_number: Integer = None,
    ) -> HostedConfigurationVersion:
        raise NotImplementedError

    @handler("DeleteApplication")
    def delete_application(self, context: RequestContext, application_id: Id) -> None:
        raise NotImplementedError

    @handler("DeleteConfigurationProfile")
    def delete_configuration_profile(
        self, context: RequestContext, application_id: Id, configuration_profile_id: Id
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDeploymentStrategy")
    def delete_deployment_strategy(
        self, context: RequestContext, deployment_strategy_id: DeploymentStrategyId
    ) -> None:
        raise NotImplementedError

    @handler("DeleteEnvironment")
    def delete_environment(
        self, context: RequestContext, application_id: Id, environment_id: Id
    ) -> None:
        raise NotImplementedError

    @handler("DeleteHostedConfigurationVersion")
    def delete_hosted_configuration_version(
        self,
        context: RequestContext,
        application_id: Id,
        configuration_profile_id: Id,
        version_number: Integer,
    ) -> None:
        raise NotImplementedError

    @handler("GetApplication")
    def get_application(self, context: RequestContext, application_id: Id) -> Application:
        raise NotImplementedError

    @handler("GetConfiguration")
    def get_configuration(
        self,
        context: RequestContext,
        application: StringWithLengthBetween1And64,
        environment: StringWithLengthBetween1And64,
        configuration: StringWithLengthBetween1And64,
        client_id: StringWithLengthBetween1And64,
        client_configuration_version: Version = None,
    ) -> Configuration:
        raise NotImplementedError

    @handler("GetConfigurationProfile")
    def get_configuration_profile(
        self, context: RequestContext, application_id: Id, configuration_profile_id: Id
    ) -> ConfigurationProfile:
        raise NotImplementedError

    @handler("GetDeployment")
    def get_deployment(
        self,
        context: RequestContext,
        application_id: Id,
        environment_id: Id,
        deployment_number: Integer,
    ) -> Deployment:
        raise NotImplementedError

    @handler("GetDeploymentStrategy")
    def get_deployment_strategy(
        self, context: RequestContext, deployment_strategy_id: DeploymentStrategyId
    ) -> DeploymentStrategy:
        raise NotImplementedError

    @handler("GetEnvironment")
    def get_environment(
        self, context: RequestContext, application_id: Id, environment_id: Id
    ) -> Environment:
        raise NotImplementedError

    @handler("GetHostedConfigurationVersion")
    def get_hosted_configuration_version(
        self,
        context: RequestContext,
        application_id: Id,
        configuration_profile_id: Id,
        version_number: Integer,
    ) -> HostedConfigurationVersion:
        raise NotImplementedError

    @handler("ListApplications")
    def list_applications(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> Applications:
        raise NotImplementedError

    @handler("ListConfigurationProfiles", expand=False)
    def list_configuration_profiles(
        self, context: RequestContext, request: ListConfigurationProfilesRequest
    ) -> ConfigurationProfiles:
        raise NotImplementedError

    @handler("ListDeploymentStrategies")
    def list_deployment_strategies(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> DeploymentStrategies:
        raise NotImplementedError

    @handler("ListDeployments")
    def list_deployments(
        self,
        context: RequestContext,
        application_id: Id,
        environment_id: Id,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> Deployments:
        raise NotImplementedError

    @handler("ListEnvironments")
    def list_environments(
        self,
        context: RequestContext,
        application_id: Id,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> Environments:
        raise NotImplementedError

    @handler("ListHostedConfigurationVersions")
    def list_hosted_configuration_versions(
        self,
        context: RequestContext,
        application_id: Id,
        configuration_profile_id: Id,
        max_results: MaxResults = None,
        next_token: NextToken = None,
    ) -> HostedConfigurationVersions:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(self, context: RequestContext, resource_arn: Arn) -> ResourceTags:
        raise NotImplementedError

    @handler("StartDeployment")
    def start_deployment(
        self,
        context: RequestContext,
        application_id: Id,
        environment_id: Id,
        deployment_strategy_id: DeploymentStrategyId,
        configuration_profile_id: Id,
        configuration_version: Version,
        description: Description = None,
        tags: TagMap = None,
    ) -> Deployment:
        raise NotImplementedError

    @handler("StopDeployment")
    def stop_deployment(
        self,
        context: RequestContext,
        application_id: Id,
        environment_id: Id,
        deployment_number: Integer,
    ) -> Deployment:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource_arn: Arn, tags: TagMap) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList
    ) -> None:
        raise NotImplementedError

    @handler("UpdateApplication")
    def update_application(
        self,
        context: RequestContext,
        application_id: Id,
        name: Name = None,
        description: Description = None,
    ) -> Application:
        raise NotImplementedError

    @handler("UpdateConfigurationProfile")
    def update_configuration_profile(
        self,
        context: RequestContext,
        application_id: Id,
        configuration_profile_id: Id,
        name: Name = None,
        description: Description = None,
        retrieval_role_arn: RoleArn = None,
        validators: ValidatorList = None,
    ) -> ConfigurationProfile:
        raise NotImplementedError

    @handler("UpdateDeploymentStrategy")
    def update_deployment_strategy(
        self,
        context: RequestContext,
        deployment_strategy_id: DeploymentStrategyId,
        description: Description = None,
        deployment_duration_in_minutes: MinutesBetween0And24Hours = None,
        final_bake_time_in_minutes: MinutesBetween0And24Hours = None,
        growth_factor: GrowthFactor = None,
        growth_type: GrowthType = None,
    ) -> DeploymentStrategy:
        raise NotImplementedError

    @handler("UpdateEnvironment")
    def update_environment(
        self,
        context: RequestContext,
        application_id: Id,
        environment_id: Id,
        name: Name = None,
        description: Description = None,
        monitors: MonitorList = None,
    ) -> Environment:
        raise NotImplementedError

    @handler("ValidateConfiguration")
    def validate_configuration(
        self,
        context: RequestContext,
        application_id: Id,
        configuration_profile_id: Id,
        configuration_version: Version,
    ) -> None:
        raise NotImplementedError
