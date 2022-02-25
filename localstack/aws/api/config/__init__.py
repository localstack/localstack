import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ARN = str
AccountId = str
AllSupported = bool
AmazonResourceName = str
Annotation = str
AutoRemediationAttempts = int
AvailabilityZone = str
AwsRegion = str
BaseResourceId = str
Boolean = bool
ChannelName = str
ConfigRuleName = str
Configuration = str
ConfigurationAggregatorArn = str
ConfigurationAggregatorName = str
ConfigurationItemMD5Hash = str
ConfigurationStateId = str
ConformancePackArn = str
ConformancePackId = str
ConformancePackName = str
ConformancePackStatusReason = str
CosmosPageLimit = int
DeliveryS3Bucket = str
DeliveryS3KeyPrefix = str
DescribeConformancePackComplianceLimit = int
DescribePendingAggregationRequestsLimit = int
EmptiableStringWithCharLimit256 = str
ErrorMessage = str
Expression = str
FieldName = str
GetConformancePackComplianceDetailsLimit = int
GroupByAPILimit = int
IncludeGlobalResourceTypes = bool
Integer = int
Limit = int
Name = str
NextToken = str
OrganizationConfigRuleName = str
OrganizationConformancePackName = str
PageSizeLimit = int
ParameterName = str
ParameterValue = str
Percentage = int
QueryArn = str
QueryDescription = str
QueryExpression = str
QueryId = str
QueryName = str
RecorderName = str
RelatedEvent = str
RelationshipName = str
ResourceId = str
ResourceName = str
ResourceTypeString = str
RetentionConfigurationName = str
RetentionPeriodInDays = int
RuleLimit = int
SchemaVersionId = str
StackArn = str
String = str
StringWithCharLimit1024 = str
StringWithCharLimit128 = str
StringWithCharLimit2048 = str
StringWithCharLimit256 = str
StringWithCharLimit256Min0 = str
StringWithCharLimit64 = str
StringWithCharLimit768 = str
SupplementaryConfigurationName = str
SupplementaryConfigurationValue = str
TagKey = str
TagValue = str
TemplateBody = str
TemplateS3Uri = str
Value = str
Version = str


class AggregateConformancePackComplianceSummaryGroupKey(str):
    ACCOUNT_ID = "ACCOUNT_ID"
    AWS_REGION = "AWS_REGION"


class AggregatedSourceStatusType(str):
    FAILED = "FAILED"
    SUCCEEDED = "SUCCEEDED"
    OUTDATED = "OUTDATED"


class AggregatedSourceType(str):
    ACCOUNT = "ACCOUNT"
    ORGANIZATION = "ORGANIZATION"


class ChronologicalOrder(str):
    Reverse = "Reverse"
    Forward = "Forward"


class ComplianceType(str):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ConfigRuleComplianceSummaryGroupKey(str):
    ACCOUNT_ID = "ACCOUNT_ID"
    AWS_REGION = "AWS_REGION"


class ConfigRuleState(str):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    DELETING_RESULTS = "DELETING_RESULTS"
    EVALUATING = "EVALUATING"


class ConfigurationItemStatus(str):
    OK = "OK"
    ResourceDiscovered = "ResourceDiscovered"
    ResourceNotRecorded = "ResourceNotRecorded"
    ResourceDeleted = "ResourceDeleted"
    ResourceDeletedNotRecorded = "ResourceDeletedNotRecorded"


class ConformancePackComplianceType(str):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ConformancePackState(str):
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_COMPLETE = "CREATE_COMPLETE"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    DELETE_FAILED = "DELETE_FAILED"


class DeliveryStatus(str):
    Success = "Success"
    Failure = "Failure"
    Not_Applicable = "Not_Applicable"


class EventSource(str):
    aws_config = "aws.config"


class MaximumExecutionFrequency(str):
    One_Hour = "One_Hour"
    Three_Hours = "Three_Hours"
    Six_Hours = "Six_Hours"
    Twelve_Hours = "Twelve_Hours"
    TwentyFour_Hours = "TwentyFour_Hours"


class MemberAccountRuleStatus(str):
    CREATE_SUCCESSFUL = "CREATE_SUCCESSFUL"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_SUCCESSFUL = "DELETE_SUCCESSFUL"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"


class MessageType(str):
    ConfigurationItemChangeNotification = "ConfigurationItemChangeNotification"
    ConfigurationSnapshotDeliveryCompleted = "ConfigurationSnapshotDeliveryCompleted"
    ScheduledNotification = "ScheduledNotification"
    OversizedConfigurationItemChangeNotification = "OversizedConfigurationItemChangeNotification"


class OrganizationConfigRuleTriggerType(str):
    ConfigurationItemChangeNotification = "ConfigurationItemChangeNotification"
    OversizedConfigurationItemChangeNotification = "OversizedConfigurationItemChangeNotification"
    ScheduledNotification = "ScheduledNotification"


class OrganizationResourceDetailedStatus(str):
    CREATE_SUCCESSFUL = "CREATE_SUCCESSFUL"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_SUCCESSFUL = "DELETE_SUCCESSFUL"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"


class OrganizationResourceStatus(str):
    CREATE_SUCCESSFUL = "CREATE_SUCCESSFUL"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_SUCCESSFUL = "DELETE_SUCCESSFUL"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"


class OrganizationRuleStatus(str):
    CREATE_SUCCESSFUL = "CREATE_SUCCESSFUL"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_SUCCESSFUL = "DELETE_SUCCESSFUL"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"


class Owner(str):
    CUSTOM_LAMBDA = "CUSTOM_LAMBDA"
    AWS = "AWS"


class RecorderStatus(str):
    Pending = "Pending"
    Success = "Success"
    Failure = "Failure"


class RemediationExecutionState(str):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class RemediationExecutionStepState(str):
    SUCCEEDED = "SUCCEEDED"
    PENDING = "PENDING"
    FAILED = "FAILED"


class RemediationTargetType(str):
    SSM_DOCUMENT = "SSM_DOCUMENT"


class ResourceCountGroupKey(str):
    RESOURCE_TYPE = "RESOURCE_TYPE"
    ACCOUNT_ID = "ACCOUNT_ID"
    AWS_REGION = "AWS_REGION"


class ResourceType(str):
    AWS_EC2_CustomerGateway = "AWS::EC2::CustomerGateway"
    AWS_EC2_EIP = "AWS::EC2::EIP"
    AWS_EC2_Host = "AWS::EC2::Host"
    AWS_EC2_Instance = "AWS::EC2::Instance"
    AWS_EC2_InternetGateway = "AWS::EC2::InternetGateway"
    AWS_EC2_NetworkAcl = "AWS::EC2::NetworkAcl"
    AWS_EC2_NetworkInterface = "AWS::EC2::NetworkInterface"
    AWS_EC2_RouteTable = "AWS::EC2::RouteTable"
    AWS_EC2_SecurityGroup = "AWS::EC2::SecurityGroup"
    AWS_EC2_Subnet = "AWS::EC2::Subnet"
    AWS_CloudTrail_Trail = "AWS::CloudTrail::Trail"
    AWS_EC2_Volume = "AWS::EC2::Volume"
    AWS_EC2_VPC = "AWS::EC2::VPC"
    AWS_EC2_VPNConnection = "AWS::EC2::VPNConnection"
    AWS_EC2_VPNGateway = "AWS::EC2::VPNGateway"
    AWS_EC2_RegisteredHAInstance = "AWS::EC2::RegisteredHAInstance"
    AWS_EC2_NatGateway = "AWS::EC2::NatGateway"
    AWS_EC2_EgressOnlyInternetGateway = "AWS::EC2::EgressOnlyInternetGateway"
    AWS_EC2_VPCEndpoint = "AWS::EC2::VPCEndpoint"
    AWS_EC2_VPCEndpointService = "AWS::EC2::VPCEndpointService"
    AWS_EC2_FlowLog = "AWS::EC2::FlowLog"
    AWS_EC2_VPCPeeringConnection = "AWS::EC2::VPCPeeringConnection"
    AWS_Elasticsearch_Domain = "AWS::Elasticsearch::Domain"
    AWS_IAM_Group = "AWS::IAM::Group"
    AWS_IAM_Policy = "AWS::IAM::Policy"
    AWS_IAM_Role = "AWS::IAM::Role"
    AWS_IAM_User = "AWS::IAM::User"
    AWS_ElasticLoadBalancingV2_LoadBalancer = "AWS::ElasticLoadBalancingV2::LoadBalancer"
    AWS_ACM_Certificate = "AWS::ACM::Certificate"
    AWS_RDS_DBInstance = "AWS::RDS::DBInstance"
    AWS_RDS_DBSubnetGroup = "AWS::RDS::DBSubnetGroup"
    AWS_RDS_DBSecurityGroup = "AWS::RDS::DBSecurityGroup"
    AWS_RDS_DBSnapshot = "AWS::RDS::DBSnapshot"
    AWS_RDS_DBCluster = "AWS::RDS::DBCluster"
    AWS_RDS_DBClusterSnapshot = "AWS::RDS::DBClusterSnapshot"
    AWS_RDS_EventSubscription = "AWS::RDS::EventSubscription"
    AWS_S3_Bucket = "AWS::S3::Bucket"
    AWS_S3_AccountPublicAccessBlock = "AWS::S3::AccountPublicAccessBlock"
    AWS_Redshift_Cluster = "AWS::Redshift::Cluster"
    AWS_Redshift_ClusterSnapshot = "AWS::Redshift::ClusterSnapshot"
    AWS_Redshift_ClusterParameterGroup = "AWS::Redshift::ClusterParameterGroup"
    AWS_Redshift_ClusterSecurityGroup = "AWS::Redshift::ClusterSecurityGroup"
    AWS_Redshift_ClusterSubnetGroup = "AWS::Redshift::ClusterSubnetGroup"
    AWS_Redshift_EventSubscription = "AWS::Redshift::EventSubscription"
    AWS_SSM_ManagedInstanceInventory = "AWS::SSM::ManagedInstanceInventory"
    AWS_CloudWatch_Alarm = "AWS::CloudWatch::Alarm"
    AWS_CloudFormation_Stack = "AWS::CloudFormation::Stack"
    AWS_ElasticLoadBalancing_LoadBalancer = "AWS::ElasticLoadBalancing::LoadBalancer"
    AWS_AutoScaling_AutoScalingGroup = "AWS::AutoScaling::AutoScalingGroup"
    AWS_AutoScaling_LaunchConfiguration = "AWS::AutoScaling::LaunchConfiguration"
    AWS_AutoScaling_ScalingPolicy = "AWS::AutoScaling::ScalingPolicy"
    AWS_AutoScaling_ScheduledAction = "AWS::AutoScaling::ScheduledAction"
    AWS_DynamoDB_Table = "AWS::DynamoDB::Table"
    AWS_CodeBuild_Project = "AWS::CodeBuild::Project"
    AWS_WAF_RateBasedRule = "AWS::WAF::RateBasedRule"
    AWS_WAF_Rule = "AWS::WAF::Rule"
    AWS_WAF_RuleGroup = "AWS::WAF::RuleGroup"
    AWS_WAF_WebACL = "AWS::WAF::WebACL"
    AWS_WAFRegional_RateBasedRule = "AWS::WAFRegional::RateBasedRule"
    AWS_WAFRegional_Rule = "AWS::WAFRegional::Rule"
    AWS_WAFRegional_RuleGroup = "AWS::WAFRegional::RuleGroup"
    AWS_WAFRegional_WebACL = "AWS::WAFRegional::WebACL"
    AWS_CloudFront_Distribution = "AWS::CloudFront::Distribution"
    AWS_CloudFront_StreamingDistribution = "AWS::CloudFront::StreamingDistribution"
    AWS_Lambda_Function = "AWS::Lambda::Function"
    AWS_NetworkFirewall_Firewall = "AWS::NetworkFirewall::Firewall"
    AWS_NetworkFirewall_FirewallPolicy = "AWS::NetworkFirewall::FirewallPolicy"
    AWS_NetworkFirewall_RuleGroup = "AWS::NetworkFirewall::RuleGroup"
    AWS_ElasticBeanstalk_Application = "AWS::ElasticBeanstalk::Application"
    AWS_ElasticBeanstalk_ApplicationVersion = "AWS::ElasticBeanstalk::ApplicationVersion"
    AWS_ElasticBeanstalk_Environment = "AWS::ElasticBeanstalk::Environment"
    AWS_WAFv2_WebACL = "AWS::WAFv2::WebACL"
    AWS_WAFv2_RuleGroup = "AWS::WAFv2::RuleGroup"
    AWS_WAFv2_IPSet = "AWS::WAFv2::IPSet"
    AWS_WAFv2_RegexPatternSet = "AWS::WAFv2::RegexPatternSet"
    AWS_WAFv2_ManagedRuleSet = "AWS::WAFv2::ManagedRuleSet"
    AWS_XRay_EncryptionConfig = "AWS::XRay::EncryptionConfig"
    AWS_SSM_AssociationCompliance = "AWS::SSM::AssociationCompliance"
    AWS_SSM_PatchCompliance = "AWS::SSM::PatchCompliance"
    AWS_Shield_Protection = "AWS::Shield::Protection"
    AWS_ShieldRegional_Protection = "AWS::ShieldRegional::Protection"
    AWS_Config_ConformancePackCompliance = "AWS::Config::ConformancePackCompliance"
    AWS_Config_ResourceCompliance = "AWS::Config::ResourceCompliance"
    AWS_ApiGateway_Stage = "AWS::ApiGateway::Stage"
    AWS_ApiGateway_RestApi = "AWS::ApiGateway::RestApi"
    AWS_ApiGatewayV2_Stage = "AWS::ApiGatewayV2::Stage"
    AWS_ApiGatewayV2_Api = "AWS::ApiGatewayV2::Api"
    AWS_CodePipeline_Pipeline = "AWS::CodePipeline::Pipeline"
    AWS_ServiceCatalog_CloudFormationProvisionedProduct = (
        "AWS::ServiceCatalog::CloudFormationProvisionedProduct"
    )
    AWS_ServiceCatalog_CloudFormationProduct = "AWS::ServiceCatalog::CloudFormationProduct"
    AWS_ServiceCatalog_Portfolio = "AWS::ServiceCatalog::Portfolio"
    AWS_SQS_Queue = "AWS::SQS::Queue"
    AWS_KMS_Key = "AWS::KMS::Key"
    AWS_QLDB_Ledger = "AWS::QLDB::Ledger"
    AWS_SecretsManager_Secret = "AWS::SecretsManager::Secret"
    AWS_SNS_Topic = "AWS::SNS::Topic"
    AWS_SSM_FileData = "AWS::SSM::FileData"
    AWS_Backup_BackupPlan = "AWS::Backup::BackupPlan"
    AWS_Backup_BackupSelection = "AWS::Backup::BackupSelection"
    AWS_Backup_BackupVault = "AWS::Backup::BackupVault"
    AWS_Backup_RecoveryPoint = "AWS::Backup::RecoveryPoint"
    AWS_ECR_Repository = "AWS::ECR::Repository"
    AWS_ECS_Cluster = "AWS::ECS::Cluster"
    AWS_ECS_Service = "AWS::ECS::Service"
    AWS_ECS_TaskDefinition = "AWS::ECS::TaskDefinition"
    AWS_EFS_AccessPoint = "AWS::EFS::AccessPoint"
    AWS_EFS_FileSystem = "AWS::EFS::FileSystem"
    AWS_EKS_Cluster = "AWS::EKS::Cluster"
    AWS_OpenSearch_Domain = "AWS::OpenSearch::Domain"
    AWS_EC2_TransitGateway = "AWS::EC2::TransitGateway"
    AWS_Kinesis_Stream = "AWS::Kinesis::Stream"
    AWS_Kinesis_StreamConsumer = "AWS::Kinesis::StreamConsumer"
    AWS_CodeDeploy_Application = "AWS::CodeDeploy::Application"
    AWS_CodeDeploy_DeploymentConfig = "AWS::CodeDeploy::DeploymentConfig"
    AWS_CodeDeploy_DeploymentGroup = "AWS::CodeDeploy::DeploymentGroup"


class ResourceValueType(str):
    RESOURCE_ID = "RESOURCE_ID"


class ConformancePackTemplateValidationException(ServiceException):
    pass


class InsufficientDeliveryPolicyException(ServiceException):
    pass


class InsufficientPermissionsException(ServiceException):
    pass


class InvalidConfigurationRecorderNameException(ServiceException):
    pass


class InvalidDeliveryChannelNameException(ServiceException):
    pass


class InvalidExpressionException(ServiceException):
    pass


class InvalidLimitException(ServiceException):
    pass


class InvalidNextTokenException(ServiceException):
    pass


class InvalidParameterValueException(ServiceException):
    pass


class InvalidRecordingGroupException(ServiceException):
    pass


class InvalidResultTokenException(ServiceException):
    pass


class InvalidRoleException(ServiceException):
    pass


class InvalidS3KeyPrefixException(ServiceException):
    pass


class InvalidS3KmsKeyArnException(ServiceException):
    pass


class InvalidSNSTopicARNException(ServiceException):
    pass


class InvalidTimeRangeException(ServiceException):
    pass


class LastDeliveryChannelDeleteFailedException(ServiceException):
    pass


class LimitExceededException(ServiceException):
    pass


class MaxActiveResourcesExceededException(ServiceException):
    pass


class MaxNumberOfConfigRulesExceededException(ServiceException):
    pass


class MaxNumberOfConfigurationRecordersExceededException(ServiceException):
    pass


class MaxNumberOfConformancePacksExceededException(ServiceException):
    pass


class MaxNumberOfDeliveryChannelsExceededException(ServiceException):
    pass


class MaxNumberOfOrganizationConfigRulesExceededException(ServiceException):
    pass


class MaxNumberOfOrganizationConformancePacksExceededException(ServiceException):
    pass


class MaxNumberOfRetentionConfigurationsExceededException(ServiceException):
    pass


class NoAvailableConfigurationRecorderException(ServiceException):
    pass


class NoAvailableDeliveryChannelException(ServiceException):
    pass


class NoAvailableOrganizationException(ServiceException):
    pass


class NoRunningConfigurationRecorderException(ServiceException):
    pass


class NoSuchBucketException(ServiceException):
    pass


class NoSuchConfigRuleException(ServiceException):
    pass


class NoSuchConfigRuleInConformancePackException(ServiceException):
    pass


class NoSuchConfigurationAggregatorException(ServiceException):
    pass


class NoSuchConfigurationRecorderException(ServiceException):
    pass


class NoSuchConformancePackException(ServiceException):
    pass


class NoSuchDeliveryChannelException(ServiceException):
    pass


class NoSuchOrganizationConfigRuleException(ServiceException):
    pass


class NoSuchOrganizationConformancePackException(ServiceException):
    pass


class NoSuchRemediationConfigurationException(ServiceException):
    pass


class NoSuchRemediationExceptionException(ServiceException):
    pass


class NoSuchRetentionConfigurationException(ServiceException):
    pass


class OrganizationAccessDeniedException(ServiceException):
    pass


class OrganizationAllFeaturesNotEnabledException(ServiceException):
    pass


class OrganizationConformancePackTemplateValidationException(ServiceException):
    pass


class OversizedConfigurationItemException(ServiceException):
    pass


class RemediationInProgressException(ServiceException):
    pass


class ResourceConcurrentModificationException(ServiceException):
    message: Optional[ErrorMessage]


class ResourceInUseException(ServiceException):
    pass


class ResourceNotDiscoveredException(ServiceException):
    pass


class ResourceNotFoundException(ServiceException):
    pass


class TooManyTagsException(ServiceException):
    pass


class ValidationException(ServiceException):
    pass


AggregatorRegionList = List[String]
AccountAggregationSourceAccountList = List[AccountId]


class AccountAggregationSource(TypedDict, total=False):
    AccountIds: AccountAggregationSourceAccountList
    AllAwsRegions: Optional[Boolean]
    AwsRegions: Optional[AggregatorRegionList]


AccountAggregationSourceList = List[AccountAggregationSource]


class ComplianceContributorCount(TypedDict, total=False):
    CappedCount: Optional[Integer]
    CapExceeded: Optional[Boolean]


class Compliance(TypedDict, total=False):
    ComplianceType: Optional[ComplianceType]
    ComplianceContributorCount: Optional[ComplianceContributorCount]


class AggregateComplianceByConfigRule(TypedDict, total=False):
    ConfigRuleName: Optional[ConfigRuleName]
    Compliance: Optional[Compliance]
    AccountId: Optional[AccountId]
    AwsRegion: Optional[AwsRegion]


AggregateComplianceByConfigRuleList = List[AggregateComplianceByConfigRule]


class AggregateConformancePackCompliance(TypedDict, total=False):
    ComplianceType: Optional[ConformancePackComplianceType]
    CompliantRuleCount: Optional[Integer]
    NonCompliantRuleCount: Optional[Integer]
    TotalRuleCount: Optional[Integer]


class AggregateComplianceByConformancePack(TypedDict, total=False):
    ConformancePackName: Optional[ConformancePackName]
    Compliance: Optional[AggregateConformancePackCompliance]
    AccountId: Optional[AccountId]
    AwsRegion: Optional[AwsRegion]


AggregateComplianceByConformancePackList = List[AggregateComplianceByConformancePack]
Date = datetime


class ComplianceSummary(TypedDict, total=False):
    CompliantResourceCount: Optional[ComplianceContributorCount]
    NonCompliantResourceCount: Optional[ComplianceContributorCount]
    ComplianceSummaryTimestamp: Optional[Date]


class AggregateComplianceCount(TypedDict, total=False):
    GroupName: Optional[StringWithCharLimit256]
    ComplianceSummary: Optional[ComplianceSummary]


AggregateComplianceCountList = List[AggregateComplianceCount]


class AggregateConformancePackComplianceCount(TypedDict, total=False):
    CompliantConformancePackCount: Optional[Integer]
    NonCompliantConformancePackCount: Optional[Integer]


class AggregateConformancePackComplianceFilters(TypedDict, total=False):
    ConformancePackName: Optional[ConformancePackName]
    ComplianceType: Optional[ConformancePackComplianceType]
    AccountId: Optional[AccountId]
    AwsRegion: Optional[AwsRegion]


class AggregateConformancePackComplianceSummary(TypedDict, total=False):
    ComplianceSummary: Optional[AggregateConformancePackComplianceCount]
    GroupName: Optional[StringWithCharLimit256]


class AggregateConformancePackComplianceSummaryFilters(TypedDict, total=False):
    AccountId: Optional[AccountId]
    AwsRegion: Optional[AwsRegion]


AggregateConformancePackComplianceSummaryList = List[AggregateConformancePackComplianceSummary]


class EvaluationResultQualifier(TypedDict, total=False):
    ConfigRuleName: Optional[ConfigRuleName]
    ResourceType: Optional[StringWithCharLimit256]
    ResourceId: Optional[BaseResourceId]


class EvaluationResultIdentifier(TypedDict, total=False):
    EvaluationResultQualifier: Optional[EvaluationResultQualifier]
    OrderingTimestamp: Optional[Date]


class AggregateEvaluationResult(TypedDict, total=False):
    EvaluationResultIdentifier: Optional[EvaluationResultIdentifier]
    ComplianceType: Optional[ComplianceType]
    ResultRecordedTime: Optional[Date]
    ConfigRuleInvokedTime: Optional[Date]
    Annotation: Optional[StringWithCharLimit256]
    AccountId: Optional[AccountId]
    AwsRegion: Optional[AwsRegion]


AggregateEvaluationResultList = List[AggregateEvaluationResult]


class AggregateResourceIdentifier(TypedDict, total=False):
    SourceAccountId: AccountId
    SourceRegion: AwsRegion
    ResourceId: ResourceId
    ResourceType: ResourceType
    ResourceName: Optional[ResourceName]


class AggregatedSourceStatus(TypedDict, total=False):
    SourceId: Optional[String]
    SourceType: Optional[AggregatedSourceType]
    AwsRegion: Optional[AwsRegion]
    LastUpdateStatus: Optional[AggregatedSourceStatusType]
    LastUpdateTime: Optional[Date]
    LastErrorCode: Optional[String]
    LastErrorMessage: Optional[String]


AggregatedSourceStatusList = List[AggregatedSourceStatus]
AggregatedSourceStatusTypeList = List[AggregatedSourceStatusType]


class AggregationAuthorization(TypedDict, total=False):
    AggregationAuthorizationArn: Optional[String]
    AuthorizedAccountId: Optional[AccountId]
    AuthorizedAwsRegion: Optional[AwsRegion]
    CreationTime: Optional[Date]


AggregationAuthorizationList = List[AggregationAuthorization]
AutoRemediationAttemptSeconds = int
SupplementaryConfiguration = Dict[SupplementaryConfigurationName, SupplementaryConfigurationValue]
ResourceCreationTime = datetime
ConfigurationItemCaptureTime = datetime


class BaseConfigurationItem(TypedDict, total=False):
    version: Optional[Version]
    accountId: Optional[AccountId]
    configurationItemCaptureTime: Optional[ConfigurationItemCaptureTime]
    configurationItemStatus: Optional[ConfigurationItemStatus]
    configurationStateId: Optional[ConfigurationStateId]
    arn: Optional[ARN]
    resourceType: Optional[ResourceType]
    resourceId: Optional[ResourceId]
    resourceName: Optional[ResourceName]
    awsRegion: Optional[AwsRegion]
    availabilityZone: Optional[AvailabilityZone]
    resourceCreationTime: Optional[ResourceCreationTime]
    configuration: Optional[Configuration]
    supplementaryConfiguration: Optional[SupplementaryConfiguration]


BaseConfigurationItems = List[BaseConfigurationItem]
ResourceIdentifiersList = List[AggregateResourceIdentifier]


class BatchGetAggregateResourceConfigRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    ResourceIdentifiers: ResourceIdentifiersList


UnprocessedResourceIdentifierList = List[AggregateResourceIdentifier]


class BatchGetAggregateResourceConfigResponse(TypedDict, total=False):
    BaseConfigurationItems: Optional[BaseConfigurationItems]
    UnprocessedResourceIdentifiers: Optional[UnprocessedResourceIdentifierList]


class ResourceKey(TypedDict, total=False):
    resourceType: ResourceType
    resourceId: ResourceId


ResourceKeys = List[ResourceKey]


class BatchGetResourceConfigRequest(ServiceRequest):
    resourceKeys: ResourceKeys


class BatchGetResourceConfigResponse(TypedDict, total=False):
    baseConfigurationItems: Optional[BaseConfigurationItems]
    unprocessedResourceKeys: Optional[ResourceKeys]


class ComplianceByConfigRule(TypedDict, total=False):
    ConfigRuleName: Optional[StringWithCharLimit64]
    Compliance: Optional[Compliance]


ComplianceByConfigRules = List[ComplianceByConfigRule]


class ComplianceByResource(TypedDict, total=False):
    ResourceType: Optional[StringWithCharLimit256]
    ResourceId: Optional[BaseResourceId]
    Compliance: Optional[Compliance]


ComplianceByResources = List[ComplianceByResource]
ComplianceResourceTypes = List[StringWithCharLimit256]


class ComplianceSummaryByResourceType(TypedDict, total=False):
    ResourceType: Optional[StringWithCharLimit256]
    ComplianceSummary: Optional[ComplianceSummary]


ComplianceSummariesByResourceType = List[ComplianceSummaryByResourceType]
ComplianceTypes = List[ComplianceType]


class ConfigExportDeliveryInfo(TypedDict, total=False):
    lastStatus: Optional[DeliveryStatus]
    lastErrorCode: Optional[String]
    lastErrorMessage: Optional[String]
    lastAttemptTime: Optional[Date]
    lastSuccessfulTime: Optional[Date]
    nextDeliveryTime: Optional[Date]


class SourceDetail(TypedDict, total=False):
    EventSource: Optional[EventSource]
    MessageType: Optional[MessageType]
    MaximumExecutionFrequency: Optional[MaximumExecutionFrequency]


SourceDetails = List[SourceDetail]


class Source(TypedDict, total=False):
    Owner: Owner
    SourceIdentifier: StringWithCharLimit256
    SourceDetails: Optional[SourceDetails]


class Scope(TypedDict, total=False):
    ComplianceResourceTypes: Optional[ComplianceResourceTypes]
    TagKey: Optional[StringWithCharLimit128]
    TagValue: Optional[StringWithCharLimit256]
    ComplianceResourceId: Optional[BaseResourceId]


class ConfigRule(TypedDict, total=False):
    ConfigRuleName: Optional[ConfigRuleName]
    ConfigRuleArn: Optional[StringWithCharLimit256]
    ConfigRuleId: Optional[StringWithCharLimit64]
    Description: Optional[EmptiableStringWithCharLimit256]
    Scope: Optional[Scope]
    Source: Source
    InputParameters: Optional[StringWithCharLimit1024]
    MaximumExecutionFrequency: Optional[MaximumExecutionFrequency]
    ConfigRuleState: Optional[ConfigRuleState]
    CreatedBy: Optional[StringWithCharLimit256]


class ConfigRuleComplianceFilters(TypedDict, total=False):
    ConfigRuleName: Optional[ConfigRuleName]
    ComplianceType: Optional[ComplianceType]
    AccountId: Optional[AccountId]
    AwsRegion: Optional[AwsRegion]


class ConfigRuleComplianceSummaryFilters(TypedDict, total=False):
    AccountId: Optional[AccountId]
    AwsRegion: Optional[AwsRegion]


class ConfigRuleEvaluationStatus(TypedDict, total=False):
    ConfigRuleName: Optional[ConfigRuleName]
    ConfigRuleArn: Optional[String]
    ConfigRuleId: Optional[String]
    LastSuccessfulInvocationTime: Optional[Date]
    LastFailedInvocationTime: Optional[Date]
    LastSuccessfulEvaluationTime: Optional[Date]
    LastFailedEvaluationTime: Optional[Date]
    FirstActivatedTime: Optional[Date]
    LastDeactivatedTime: Optional[Date]
    LastErrorCode: Optional[String]
    LastErrorMessage: Optional[String]
    FirstEvaluationStarted: Optional[Boolean]


ConfigRuleEvaluationStatusList = List[ConfigRuleEvaluationStatus]
ConfigRuleNames = List[ConfigRuleName]
ConfigRules = List[ConfigRule]


class ConfigSnapshotDeliveryProperties(TypedDict, total=False):
    deliveryFrequency: Optional[MaximumExecutionFrequency]


class ConfigStreamDeliveryInfo(TypedDict, total=False):
    lastStatus: Optional[DeliveryStatus]
    lastErrorCode: Optional[String]
    lastErrorMessage: Optional[String]
    lastStatusChangeTime: Optional[Date]


class OrganizationAggregationSource(TypedDict, total=False):
    RoleArn: String
    AwsRegions: Optional[AggregatorRegionList]
    AllAwsRegions: Optional[Boolean]


class ConfigurationAggregator(TypedDict, total=False):
    ConfigurationAggregatorName: Optional[ConfigurationAggregatorName]
    ConfigurationAggregatorArn: Optional[ConfigurationAggregatorArn]
    AccountAggregationSources: Optional[AccountAggregationSourceList]
    OrganizationAggregationSource: Optional[OrganizationAggregationSource]
    CreationTime: Optional[Date]
    LastUpdatedTime: Optional[Date]
    CreatedBy: Optional[StringWithCharLimit256]


ConfigurationAggregatorList = List[ConfigurationAggregator]
ConfigurationAggregatorNameList = List[ConfigurationAggregatorName]


class Relationship(TypedDict, total=False):
    resourceType: Optional[ResourceType]
    resourceId: Optional[ResourceId]
    resourceName: Optional[ResourceName]
    relationshipName: Optional[RelationshipName]


RelationshipList = List[Relationship]
RelatedEventList = List[RelatedEvent]
Tags = Dict[Name, Value]


class ConfigurationItem(TypedDict, total=False):
    version: Optional[Version]
    accountId: Optional[AccountId]
    configurationItemCaptureTime: Optional[ConfigurationItemCaptureTime]
    configurationItemStatus: Optional[ConfigurationItemStatus]
    configurationStateId: Optional[ConfigurationStateId]
    configurationItemMD5Hash: Optional[ConfigurationItemMD5Hash]
    arn: Optional[ARN]
    resourceType: Optional[ResourceType]
    resourceId: Optional[ResourceId]
    resourceName: Optional[ResourceName]
    awsRegion: Optional[AwsRegion]
    availabilityZone: Optional[AvailabilityZone]
    resourceCreationTime: Optional[ResourceCreationTime]
    tags: Optional[Tags]
    relatedEvents: Optional[RelatedEventList]
    relationships: Optional[RelationshipList]
    configuration: Optional[Configuration]
    supplementaryConfiguration: Optional[SupplementaryConfiguration]


ConfigurationItemList = List[ConfigurationItem]
ResourceTypeList = List[ResourceType]


class RecordingGroup(TypedDict, total=False):
    allSupported: Optional[AllSupported]
    includeGlobalResourceTypes: Optional[IncludeGlobalResourceTypes]
    resourceTypes: Optional[ResourceTypeList]


class ConfigurationRecorder(TypedDict, total=False):
    name: Optional[RecorderName]
    roleARN: Optional[String]
    recordingGroup: Optional[RecordingGroup]


ConfigurationRecorderList = List[ConfigurationRecorder]
ConfigurationRecorderNameList = List[RecorderName]


class ConfigurationRecorderStatus(TypedDict, total=False):
    name: Optional[String]
    lastStartTime: Optional[Date]
    lastStopTime: Optional[Date]
    recording: Optional[Boolean]
    lastStatus: Optional[RecorderStatus]
    lastErrorCode: Optional[String]
    lastErrorMessage: Optional[String]
    lastStatusChangeTime: Optional[Date]


ConfigurationRecorderStatusList = List[ConfigurationRecorderStatus]
ConformancePackConfigRuleNames = List[StringWithCharLimit64]


class ConformancePackComplianceFilters(TypedDict, total=False):
    ConfigRuleNames: Optional[ConformancePackConfigRuleNames]
    ComplianceType: Optional[ConformancePackComplianceType]


ConformancePackComplianceResourceIds = List[StringWithCharLimit256]


class ConformancePackComplianceSummary(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackComplianceStatus: ConformancePackComplianceType


ConformancePackComplianceSummaryList = List[ConformancePackComplianceSummary]


class ConformancePackInputParameter(TypedDict, total=False):
    ParameterName: ParameterName
    ParameterValue: ParameterValue


ConformancePackInputParameters = List[ConformancePackInputParameter]


class ConformancePackDetail(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackArn: ConformancePackArn
    ConformancePackId: ConformancePackId
    DeliveryS3Bucket: Optional[DeliveryS3Bucket]
    DeliveryS3KeyPrefix: Optional[DeliveryS3KeyPrefix]
    ConformancePackInputParameters: Optional[ConformancePackInputParameters]
    LastUpdateRequestedTime: Optional[Date]
    CreatedBy: Optional[StringWithCharLimit256]


ConformancePackDetailList = List[ConformancePackDetail]


class ConformancePackEvaluationFilters(TypedDict, total=False):
    ConfigRuleNames: Optional[ConformancePackConfigRuleNames]
    ComplianceType: Optional[ConformancePackComplianceType]
    ResourceType: Optional[StringWithCharLimit256]
    ResourceIds: Optional[ConformancePackComplianceResourceIds]


class ConformancePackEvaluationResult(TypedDict, total=False):
    ComplianceType: ConformancePackComplianceType
    EvaluationResultIdentifier: EvaluationResultIdentifier
    ConfigRuleInvokedTime: Date
    ResultRecordedTime: Date
    Annotation: Optional[Annotation]


ConformancePackNamesList = List[ConformancePackName]
ConformancePackNamesToSummarizeList = List[ConformancePackName]
ControlsList = List[StringWithCharLimit128]


class ConformancePackRuleCompliance(TypedDict, total=False):
    ConfigRuleName: Optional[ConfigRuleName]
    ComplianceType: Optional[ConformancePackComplianceType]
    Controls: Optional[ControlsList]


ConformancePackRuleComplianceList = List[ConformancePackRuleCompliance]
ConformancePackRuleEvaluationResultsList = List[ConformancePackEvaluationResult]


class ConformancePackStatusDetail(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackId: ConformancePackId
    ConformancePackArn: ConformancePackArn
    ConformancePackState: ConformancePackState
    StackArn: StackArn
    ConformancePackStatusReason: Optional[ConformancePackStatusReason]
    LastUpdateRequestedTime: Date
    LastUpdateCompletedTime: Optional[Date]


ConformancePackStatusDetailsList = List[ConformancePackStatusDetail]


class DeleteAggregationAuthorizationRequest(ServiceRequest):
    AuthorizedAccountId: AccountId
    AuthorizedAwsRegion: AwsRegion


class DeleteConfigRuleRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName


class DeleteConfigurationAggregatorRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName


class DeleteConfigurationRecorderRequest(ServiceRequest):
    ConfigurationRecorderName: RecorderName


class DeleteConformancePackRequest(ServiceRequest):
    ConformancePackName: ConformancePackName


class DeleteDeliveryChannelRequest(ServiceRequest):
    DeliveryChannelName: ChannelName


class DeleteEvaluationResultsRequest(ServiceRequest):
    ConfigRuleName: StringWithCharLimit64


class DeleteEvaluationResultsResponse(TypedDict, total=False):
    pass


class DeleteOrganizationConfigRuleRequest(ServiceRequest):
    OrganizationConfigRuleName: OrganizationConfigRuleName


class DeleteOrganizationConformancePackRequest(ServiceRequest):
    OrganizationConformancePackName: OrganizationConformancePackName


class DeletePendingAggregationRequestRequest(ServiceRequest):
    RequesterAccountId: AccountId
    RequesterAwsRegion: AwsRegion


class DeleteRemediationConfigurationRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceType: Optional[String]


class DeleteRemediationConfigurationResponse(TypedDict, total=False):
    pass


class RemediationExceptionResourceKey(TypedDict, total=False):
    ResourceType: Optional[StringWithCharLimit256]
    ResourceId: Optional[StringWithCharLimit1024]


RemediationExceptionResourceKeys = List[RemediationExceptionResourceKey]


class DeleteRemediationExceptionsRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: RemediationExceptionResourceKeys


class FailedDeleteRemediationExceptionsBatch(TypedDict, total=False):
    FailureMessage: Optional[String]
    FailedItems: Optional[RemediationExceptionResourceKeys]


FailedDeleteRemediationExceptionsBatches = List[FailedDeleteRemediationExceptionsBatch]


class DeleteRemediationExceptionsResponse(TypedDict, total=False):
    FailedBatches: Optional[FailedDeleteRemediationExceptionsBatches]


class DeleteResourceConfigRequest(ServiceRequest):
    ResourceType: ResourceTypeString
    ResourceId: ResourceId


class DeleteRetentionConfigurationRequest(ServiceRequest):
    RetentionConfigurationName: RetentionConfigurationName


class DeleteStoredQueryRequest(ServiceRequest):
    QueryName: QueryName


class DeleteStoredQueryResponse(TypedDict, total=False):
    pass


class DeliverConfigSnapshotRequest(ServiceRequest):
    deliveryChannelName: ChannelName


class DeliverConfigSnapshotResponse(TypedDict, total=False):
    configSnapshotId: Optional[String]


class DeliveryChannel(TypedDict, total=False):
    name: Optional[ChannelName]
    s3BucketName: Optional[String]
    s3KeyPrefix: Optional[String]
    s3KmsKeyArn: Optional[String]
    snsTopicARN: Optional[String]
    configSnapshotDeliveryProperties: Optional[ConfigSnapshotDeliveryProperties]


DeliveryChannelList = List[DeliveryChannel]
DeliveryChannelNameList = List[ChannelName]


class DeliveryChannelStatus(TypedDict, total=False):
    name: Optional[String]
    configSnapshotDeliveryInfo: Optional[ConfigExportDeliveryInfo]
    configHistoryDeliveryInfo: Optional[ConfigExportDeliveryInfo]
    configStreamDeliveryInfo: Optional[ConfigStreamDeliveryInfo]


DeliveryChannelStatusList = List[DeliveryChannelStatus]


class DescribeAggregateComplianceByConfigRulesRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: Optional[ConfigRuleComplianceFilters]
    Limit: Optional[GroupByAPILimit]
    NextToken: Optional[NextToken]


class DescribeAggregateComplianceByConfigRulesResponse(TypedDict, total=False):
    AggregateComplianceByConfigRules: Optional[AggregateComplianceByConfigRuleList]
    NextToken: Optional[NextToken]


class DescribeAggregateComplianceByConformancePacksRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: Optional[AggregateConformancePackComplianceFilters]
    Limit: Optional[Limit]
    NextToken: Optional[NextToken]


class DescribeAggregateComplianceByConformancePacksResponse(TypedDict, total=False):
    AggregateComplianceByConformancePacks: Optional[AggregateComplianceByConformancePackList]
    NextToken: Optional[NextToken]


class DescribeAggregationAuthorizationsRequest(ServiceRequest):
    Limit: Optional[Limit]
    NextToken: Optional[String]


class DescribeAggregationAuthorizationsResponse(TypedDict, total=False):
    AggregationAuthorizations: Optional[AggregationAuthorizationList]
    NextToken: Optional[String]


class DescribeComplianceByConfigRuleRequest(ServiceRequest):
    ConfigRuleNames: Optional[ConfigRuleNames]
    ComplianceTypes: Optional[ComplianceTypes]
    NextToken: Optional[String]


class DescribeComplianceByConfigRuleResponse(TypedDict, total=False):
    ComplianceByConfigRules: Optional[ComplianceByConfigRules]
    NextToken: Optional[String]


class DescribeComplianceByResourceRequest(ServiceRequest):
    ResourceType: Optional[StringWithCharLimit256]
    ResourceId: Optional[BaseResourceId]
    ComplianceTypes: Optional[ComplianceTypes]
    Limit: Optional[Limit]
    NextToken: Optional[NextToken]


class DescribeComplianceByResourceResponse(TypedDict, total=False):
    ComplianceByResources: Optional[ComplianceByResources]
    NextToken: Optional[NextToken]


class DescribeConfigRuleEvaluationStatusRequest(ServiceRequest):
    ConfigRuleNames: Optional[ConfigRuleNames]
    NextToken: Optional[String]
    Limit: Optional[RuleLimit]


class DescribeConfigRuleEvaluationStatusResponse(TypedDict, total=False):
    ConfigRulesEvaluationStatus: Optional[ConfigRuleEvaluationStatusList]
    NextToken: Optional[String]


class DescribeConfigRulesRequest(ServiceRequest):
    ConfigRuleNames: Optional[ConfigRuleNames]
    NextToken: Optional[String]


class DescribeConfigRulesResponse(TypedDict, total=False):
    ConfigRules: Optional[ConfigRules]
    NextToken: Optional[String]


class DescribeConfigurationAggregatorSourcesStatusRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    UpdateStatus: Optional[AggregatedSourceStatusTypeList]
    NextToken: Optional[String]
    Limit: Optional[Limit]


class DescribeConfigurationAggregatorSourcesStatusResponse(TypedDict, total=False):
    AggregatedSourceStatusList: Optional[AggregatedSourceStatusList]
    NextToken: Optional[String]


class DescribeConfigurationAggregatorsRequest(ServiceRequest):
    ConfigurationAggregatorNames: Optional[ConfigurationAggregatorNameList]
    NextToken: Optional[String]
    Limit: Optional[Limit]


class DescribeConfigurationAggregatorsResponse(TypedDict, total=False):
    ConfigurationAggregators: Optional[ConfigurationAggregatorList]
    NextToken: Optional[String]


class DescribeConfigurationRecorderStatusRequest(ServiceRequest):
    ConfigurationRecorderNames: Optional[ConfigurationRecorderNameList]


class DescribeConfigurationRecorderStatusResponse(TypedDict, total=False):
    ConfigurationRecordersStatus: Optional[ConfigurationRecorderStatusList]


class DescribeConfigurationRecordersRequest(ServiceRequest):
    ConfigurationRecorderNames: Optional[ConfigurationRecorderNameList]


class DescribeConfigurationRecordersResponse(TypedDict, total=False):
    ConfigurationRecorders: Optional[ConfigurationRecorderList]


class DescribeConformancePackComplianceRequest(ServiceRequest):
    ConformancePackName: ConformancePackName
    Filters: Optional[ConformancePackComplianceFilters]
    Limit: Optional[DescribeConformancePackComplianceLimit]
    NextToken: Optional[NextToken]


class DescribeConformancePackComplianceResponse(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackRuleComplianceList: ConformancePackRuleComplianceList
    NextToken: Optional[NextToken]


class DescribeConformancePackStatusRequest(ServiceRequest):
    ConformancePackNames: Optional[ConformancePackNamesList]
    Limit: Optional[PageSizeLimit]
    NextToken: Optional[NextToken]


class DescribeConformancePackStatusResponse(TypedDict, total=False):
    ConformancePackStatusDetails: Optional[ConformancePackStatusDetailsList]
    NextToken: Optional[NextToken]


class DescribeConformancePacksRequest(ServiceRequest):
    ConformancePackNames: Optional[ConformancePackNamesList]
    Limit: Optional[PageSizeLimit]
    NextToken: Optional[NextToken]


class DescribeConformancePacksResponse(TypedDict, total=False):
    ConformancePackDetails: Optional[ConformancePackDetailList]
    NextToken: Optional[NextToken]


class DescribeDeliveryChannelStatusRequest(ServiceRequest):
    DeliveryChannelNames: Optional[DeliveryChannelNameList]


class DescribeDeliveryChannelStatusResponse(TypedDict, total=False):
    DeliveryChannelsStatus: Optional[DeliveryChannelStatusList]


class DescribeDeliveryChannelsRequest(ServiceRequest):
    DeliveryChannelNames: Optional[DeliveryChannelNameList]


class DescribeDeliveryChannelsResponse(TypedDict, total=False):
    DeliveryChannels: Optional[DeliveryChannelList]


OrganizationConfigRuleNames = List[StringWithCharLimit64]


class DescribeOrganizationConfigRuleStatusesRequest(ServiceRequest):
    OrganizationConfigRuleNames: Optional[OrganizationConfigRuleNames]
    Limit: Optional[CosmosPageLimit]
    NextToken: Optional[String]


class OrganizationConfigRuleStatus(TypedDict, total=False):
    OrganizationConfigRuleName: OrganizationConfigRuleName
    OrganizationRuleStatus: OrganizationRuleStatus
    ErrorCode: Optional[String]
    ErrorMessage: Optional[String]
    LastUpdateTime: Optional[Date]


OrganizationConfigRuleStatuses = List[OrganizationConfigRuleStatus]


class DescribeOrganizationConfigRuleStatusesResponse(TypedDict, total=False):
    OrganizationConfigRuleStatuses: Optional[OrganizationConfigRuleStatuses]
    NextToken: Optional[String]


class DescribeOrganizationConfigRulesRequest(ServiceRequest):
    OrganizationConfigRuleNames: Optional[OrganizationConfigRuleNames]
    Limit: Optional[CosmosPageLimit]
    NextToken: Optional[String]


ExcludedAccounts = List[AccountId]
ResourceTypesScope = List[StringWithCharLimit256]
OrganizationConfigRuleTriggerTypes = List[OrganizationConfigRuleTriggerType]


class OrganizationCustomRuleMetadata(TypedDict, total=False):
    Description: Optional[StringWithCharLimit256Min0]
    LambdaFunctionArn: StringWithCharLimit256
    OrganizationConfigRuleTriggerTypes: OrganizationConfigRuleTriggerTypes
    InputParameters: Optional[StringWithCharLimit2048]
    MaximumExecutionFrequency: Optional[MaximumExecutionFrequency]
    ResourceTypesScope: Optional[ResourceTypesScope]
    ResourceIdScope: Optional[StringWithCharLimit768]
    TagKeyScope: Optional[StringWithCharLimit128]
    TagValueScope: Optional[StringWithCharLimit256]


class OrganizationManagedRuleMetadata(TypedDict, total=False):
    Description: Optional[StringWithCharLimit256Min0]
    RuleIdentifier: StringWithCharLimit256
    InputParameters: Optional[StringWithCharLimit2048]
    MaximumExecutionFrequency: Optional[MaximumExecutionFrequency]
    ResourceTypesScope: Optional[ResourceTypesScope]
    ResourceIdScope: Optional[StringWithCharLimit768]
    TagKeyScope: Optional[StringWithCharLimit128]
    TagValueScope: Optional[StringWithCharLimit256]


class OrganizationConfigRule(TypedDict, total=False):
    OrganizationConfigRuleName: OrganizationConfigRuleName
    OrganizationConfigRuleArn: StringWithCharLimit256
    OrganizationManagedRuleMetadata: Optional[OrganizationManagedRuleMetadata]
    OrganizationCustomRuleMetadata: Optional[OrganizationCustomRuleMetadata]
    ExcludedAccounts: Optional[ExcludedAccounts]
    LastUpdateTime: Optional[Date]


OrganizationConfigRules = List[OrganizationConfigRule]


class DescribeOrganizationConfigRulesResponse(TypedDict, total=False):
    OrganizationConfigRules: Optional[OrganizationConfigRules]
    NextToken: Optional[String]


OrganizationConformancePackNames = List[OrganizationConformancePackName]


class DescribeOrganizationConformancePackStatusesRequest(ServiceRequest):
    OrganizationConformancePackNames: Optional[OrganizationConformancePackNames]
    Limit: Optional[CosmosPageLimit]
    NextToken: Optional[String]


class OrganizationConformancePackStatus(TypedDict, total=False):
    OrganizationConformancePackName: OrganizationConformancePackName
    Status: OrganizationResourceStatus
    ErrorCode: Optional[String]
    ErrorMessage: Optional[String]
    LastUpdateTime: Optional[Date]


OrganizationConformancePackStatuses = List[OrganizationConformancePackStatus]


class DescribeOrganizationConformancePackStatusesResponse(TypedDict, total=False):
    OrganizationConformancePackStatuses: Optional[OrganizationConformancePackStatuses]
    NextToken: Optional[String]


class DescribeOrganizationConformancePacksRequest(ServiceRequest):
    OrganizationConformancePackNames: Optional[OrganizationConformancePackNames]
    Limit: Optional[CosmosPageLimit]
    NextToken: Optional[String]


class OrganizationConformancePack(TypedDict, total=False):
    OrganizationConformancePackName: OrganizationConformancePackName
    OrganizationConformancePackArn: StringWithCharLimit256
    DeliveryS3Bucket: Optional[DeliveryS3Bucket]
    DeliveryS3KeyPrefix: Optional[DeliveryS3KeyPrefix]
    ConformancePackInputParameters: Optional[ConformancePackInputParameters]
    ExcludedAccounts: Optional[ExcludedAccounts]
    LastUpdateTime: Date


OrganizationConformancePacks = List[OrganizationConformancePack]


class DescribeOrganizationConformancePacksResponse(TypedDict, total=False):
    OrganizationConformancePacks: Optional[OrganizationConformancePacks]
    NextToken: Optional[String]


class DescribePendingAggregationRequestsRequest(ServiceRequest):
    Limit: Optional[DescribePendingAggregationRequestsLimit]
    NextToken: Optional[String]


class PendingAggregationRequest(TypedDict, total=False):
    RequesterAccountId: Optional[AccountId]
    RequesterAwsRegion: Optional[AwsRegion]


PendingAggregationRequestList = List[PendingAggregationRequest]


class DescribePendingAggregationRequestsResponse(TypedDict, total=False):
    PendingAggregationRequests: Optional[PendingAggregationRequestList]
    NextToken: Optional[String]


class DescribeRemediationConfigurationsRequest(ServiceRequest):
    ConfigRuleNames: ConfigRuleNames


class SsmControls(TypedDict, total=False):
    ConcurrentExecutionRatePercentage: Optional[Percentage]
    ErrorPercentage: Optional[Percentage]


class ExecutionControls(TypedDict, total=False):
    SsmControls: Optional[SsmControls]


StaticParameterValues = List[StringWithCharLimit256]


class StaticValue(TypedDict, total=False):
    Values: StaticParameterValues


class ResourceValue(TypedDict, total=False):
    Value: ResourceValueType


class RemediationParameterValue(TypedDict, total=False):
    ResourceValue: Optional[ResourceValue]
    StaticValue: Optional[StaticValue]


RemediationParameters = Dict[StringWithCharLimit256, RemediationParameterValue]


class RemediationConfiguration(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName
    TargetType: RemediationTargetType
    TargetId: StringWithCharLimit256
    TargetVersion: Optional[String]
    Parameters: Optional[RemediationParameters]
    ResourceType: Optional[String]
    Automatic: Optional[Boolean]
    ExecutionControls: Optional[ExecutionControls]
    MaximumAutomaticAttempts: Optional[AutoRemediationAttempts]
    RetryAttemptSeconds: Optional[AutoRemediationAttemptSeconds]
    Arn: Optional[StringWithCharLimit1024]
    CreatedByService: Optional[StringWithCharLimit1024]


RemediationConfigurations = List[RemediationConfiguration]


class DescribeRemediationConfigurationsResponse(TypedDict, total=False):
    RemediationConfigurations: Optional[RemediationConfigurations]


class DescribeRemediationExceptionsRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: Optional[RemediationExceptionResourceKeys]
    Limit: Optional[Limit]
    NextToken: Optional[String]


class RemediationException(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName
    ResourceType: StringWithCharLimit256
    ResourceId: StringWithCharLimit1024
    Message: Optional[StringWithCharLimit1024]
    ExpirationTime: Optional[Date]


RemediationExceptions = List[RemediationException]


class DescribeRemediationExceptionsResponse(TypedDict, total=False):
    RemediationExceptions: Optional[RemediationExceptions]
    NextToken: Optional[String]


class DescribeRemediationExecutionStatusRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: Optional[ResourceKeys]
    Limit: Optional[Limit]
    NextToken: Optional[String]


class RemediationExecutionStep(TypedDict, total=False):
    Name: Optional[String]
    State: Optional[RemediationExecutionStepState]
    ErrorMessage: Optional[String]
    StartTime: Optional[Date]
    StopTime: Optional[Date]


RemediationExecutionSteps = List[RemediationExecutionStep]


class RemediationExecutionStatus(TypedDict, total=False):
    ResourceKey: Optional[ResourceKey]
    State: Optional[RemediationExecutionState]
    StepDetails: Optional[RemediationExecutionSteps]
    InvocationTime: Optional[Date]
    LastUpdatedTime: Optional[Date]


RemediationExecutionStatuses = List[RemediationExecutionStatus]


class DescribeRemediationExecutionStatusResponse(TypedDict, total=False):
    RemediationExecutionStatuses: Optional[RemediationExecutionStatuses]
    NextToken: Optional[String]


RetentionConfigurationNameList = List[RetentionConfigurationName]


class DescribeRetentionConfigurationsRequest(ServiceRequest):
    RetentionConfigurationNames: Optional[RetentionConfigurationNameList]
    NextToken: Optional[NextToken]


class RetentionConfiguration(TypedDict, total=False):
    Name: RetentionConfigurationName
    RetentionPeriodInDays: RetentionPeriodInDays


RetentionConfigurationList = List[RetentionConfiguration]


class DescribeRetentionConfigurationsResponse(TypedDict, total=False):
    RetentionConfigurations: Optional[RetentionConfigurationList]
    NextToken: Optional[NextToken]


DiscoveredResourceIdentifierList = List[AggregateResourceIdentifier]
EarlierTime = datetime
OrderingTimestamp = datetime


class Evaluation(TypedDict, total=False):
    ComplianceResourceType: StringWithCharLimit256
    ComplianceResourceId: BaseResourceId
    ComplianceType: ComplianceType
    Annotation: Optional[StringWithCharLimit256]
    OrderingTimestamp: OrderingTimestamp


class EvaluationResult(TypedDict, total=False):
    EvaluationResultIdentifier: Optional[EvaluationResultIdentifier]
    ComplianceType: Optional[ComplianceType]
    ResultRecordedTime: Optional[Date]
    ConfigRuleInvokedTime: Optional[Date]
    Annotation: Optional[StringWithCharLimit256]
    ResultToken: Optional[String]


EvaluationResults = List[EvaluationResult]
Evaluations = List[Evaluation]


class ExternalEvaluation(TypedDict, total=False):
    ComplianceResourceType: StringWithCharLimit256
    ComplianceResourceId: BaseResourceId
    ComplianceType: ComplianceType
    Annotation: Optional[StringWithCharLimit256]
    OrderingTimestamp: OrderingTimestamp


class FailedRemediationBatch(TypedDict, total=False):
    FailureMessage: Optional[String]
    FailedItems: Optional[RemediationConfigurations]


FailedRemediationBatches = List[FailedRemediationBatch]


class FailedRemediationExceptionBatch(TypedDict, total=False):
    FailureMessage: Optional[String]
    FailedItems: Optional[RemediationExceptions]


FailedRemediationExceptionBatches = List[FailedRemediationExceptionBatch]


class FieldInfo(TypedDict, total=False):
    Name: Optional[FieldName]


FieldInfoList = List[FieldInfo]


class GetAggregateComplianceDetailsByConfigRuleRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    ConfigRuleName: ConfigRuleName
    AccountId: AccountId
    AwsRegion: AwsRegion
    ComplianceType: Optional[ComplianceType]
    Limit: Optional[Limit]
    NextToken: Optional[NextToken]


class GetAggregateComplianceDetailsByConfigRuleResponse(TypedDict, total=False):
    AggregateEvaluationResults: Optional[AggregateEvaluationResultList]
    NextToken: Optional[NextToken]


class GetAggregateConfigRuleComplianceSummaryRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: Optional[ConfigRuleComplianceSummaryFilters]
    GroupByKey: Optional[ConfigRuleComplianceSummaryGroupKey]
    Limit: Optional[GroupByAPILimit]
    NextToken: Optional[NextToken]


class GetAggregateConfigRuleComplianceSummaryResponse(TypedDict, total=False):
    GroupByKey: Optional[StringWithCharLimit256]
    AggregateComplianceCounts: Optional[AggregateComplianceCountList]
    NextToken: Optional[NextToken]


class GetAggregateConformancePackComplianceSummaryRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: Optional[AggregateConformancePackComplianceSummaryFilters]
    GroupByKey: Optional[AggregateConformancePackComplianceSummaryGroupKey]
    Limit: Optional[Limit]
    NextToken: Optional[NextToken]


class GetAggregateConformancePackComplianceSummaryResponse(TypedDict, total=False):
    AggregateConformancePackComplianceSummaries: Optional[
        AggregateConformancePackComplianceSummaryList
    ]
    GroupByKey: Optional[StringWithCharLimit256]
    NextToken: Optional[NextToken]


class ResourceCountFilters(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    AccountId: Optional[AccountId]
    Region: Optional[AwsRegion]


class GetAggregateDiscoveredResourceCountsRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: Optional[ResourceCountFilters]
    GroupByKey: Optional[ResourceCountGroupKey]
    Limit: Optional[GroupByAPILimit]
    NextToken: Optional[NextToken]


Long = int


class GroupedResourceCount(TypedDict, total=False):
    GroupName: StringWithCharLimit256
    ResourceCount: Long


GroupedResourceCountList = List[GroupedResourceCount]


class GetAggregateDiscoveredResourceCountsResponse(TypedDict, total=False):
    TotalDiscoveredResources: Long
    GroupByKey: Optional[StringWithCharLimit256]
    GroupedResourceCounts: Optional[GroupedResourceCountList]
    NextToken: Optional[NextToken]


class GetAggregateResourceConfigRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    ResourceIdentifier: AggregateResourceIdentifier


class GetAggregateResourceConfigResponse(TypedDict, total=False):
    ConfigurationItem: Optional[ConfigurationItem]


class GetComplianceDetailsByConfigRuleRequest(ServiceRequest):
    ConfigRuleName: StringWithCharLimit64
    ComplianceTypes: Optional[ComplianceTypes]
    Limit: Optional[Limit]
    NextToken: Optional[NextToken]


class GetComplianceDetailsByConfigRuleResponse(TypedDict, total=False):
    EvaluationResults: Optional[EvaluationResults]
    NextToken: Optional[NextToken]


class GetComplianceDetailsByResourceRequest(ServiceRequest):
    ResourceType: StringWithCharLimit256
    ResourceId: BaseResourceId
    ComplianceTypes: Optional[ComplianceTypes]
    NextToken: Optional[String]


class GetComplianceDetailsByResourceResponse(TypedDict, total=False):
    EvaluationResults: Optional[EvaluationResults]
    NextToken: Optional[String]


class GetComplianceSummaryByConfigRuleResponse(TypedDict, total=False):
    ComplianceSummary: Optional[ComplianceSummary]


ResourceTypes = List[StringWithCharLimit256]


class GetComplianceSummaryByResourceTypeRequest(ServiceRequest):
    ResourceTypes: Optional[ResourceTypes]


class GetComplianceSummaryByResourceTypeResponse(TypedDict, total=False):
    ComplianceSummariesByResourceType: Optional[ComplianceSummariesByResourceType]


class GetConformancePackComplianceDetailsRequest(ServiceRequest):
    ConformancePackName: ConformancePackName
    Filters: Optional[ConformancePackEvaluationFilters]
    Limit: Optional[GetConformancePackComplianceDetailsLimit]
    NextToken: Optional[NextToken]


class GetConformancePackComplianceDetailsResponse(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackRuleEvaluationResults: Optional[ConformancePackRuleEvaluationResultsList]
    NextToken: Optional[NextToken]


class GetConformancePackComplianceSummaryRequest(ServiceRequest):
    ConformancePackNames: ConformancePackNamesToSummarizeList
    Limit: Optional[PageSizeLimit]
    NextToken: Optional[NextToken]


class GetConformancePackComplianceSummaryResponse(TypedDict, total=False):
    ConformancePackComplianceSummaryList: Optional[ConformancePackComplianceSummaryList]
    NextToken: Optional[NextToken]


class GetDiscoveredResourceCountsRequest(ServiceRequest):
    resourceTypes: Optional[ResourceTypes]
    limit: Optional[Limit]
    nextToken: Optional[NextToken]


class ResourceCount(TypedDict, total=False):
    resourceType: Optional[ResourceType]
    count: Optional[Long]


ResourceCounts = List[ResourceCount]


class GetDiscoveredResourceCountsResponse(TypedDict, total=False):
    totalDiscoveredResources: Optional[Long]
    resourceCounts: Optional[ResourceCounts]
    nextToken: Optional[NextToken]


class StatusDetailFilters(TypedDict, total=False):
    AccountId: Optional[AccountId]
    MemberAccountRuleStatus: Optional[MemberAccountRuleStatus]


class GetOrganizationConfigRuleDetailedStatusRequest(ServiceRequest):
    OrganizationConfigRuleName: OrganizationConfigRuleName
    Filters: Optional[StatusDetailFilters]
    Limit: Optional[CosmosPageLimit]
    NextToken: Optional[String]


class MemberAccountStatus(TypedDict, total=False):
    AccountId: AccountId
    ConfigRuleName: StringWithCharLimit64
    MemberAccountRuleStatus: MemberAccountRuleStatus
    ErrorCode: Optional[String]
    ErrorMessage: Optional[String]
    LastUpdateTime: Optional[Date]


OrganizationConfigRuleDetailedStatus = List[MemberAccountStatus]


class GetOrganizationConfigRuleDetailedStatusResponse(TypedDict, total=False):
    OrganizationConfigRuleDetailedStatus: Optional[OrganizationConfigRuleDetailedStatus]
    NextToken: Optional[String]


class OrganizationResourceDetailedStatusFilters(TypedDict, total=False):
    AccountId: Optional[AccountId]
    Status: Optional[OrganizationResourceDetailedStatus]


class GetOrganizationConformancePackDetailedStatusRequest(ServiceRequest):
    OrganizationConformancePackName: OrganizationConformancePackName
    Filters: Optional[OrganizationResourceDetailedStatusFilters]
    Limit: Optional[CosmosPageLimit]
    NextToken: Optional[String]


class OrganizationConformancePackDetailedStatus(TypedDict, total=False):
    AccountId: AccountId
    ConformancePackName: StringWithCharLimit256
    Status: OrganizationResourceDetailedStatus
    ErrorCode: Optional[String]
    ErrorMessage: Optional[String]
    LastUpdateTime: Optional[Date]


OrganizationConformancePackDetailedStatuses = List[OrganizationConformancePackDetailedStatus]


class GetOrganizationConformancePackDetailedStatusResponse(TypedDict, total=False):
    OrganizationConformancePackDetailedStatuses: Optional[
        OrganizationConformancePackDetailedStatuses
    ]
    NextToken: Optional[String]


LaterTime = datetime


class GetResourceConfigHistoryRequest(ServiceRequest):
    resourceType: ResourceType
    resourceId: ResourceId
    laterTime: Optional[LaterTime]
    earlierTime: Optional[EarlierTime]
    chronologicalOrder: Optional[ChronologicalOrder]
    limit: Optional[Limit]
    nextToken: Optional[NextToken]


class GetResourceConfigHistoryResponse(TypedDict, total=False):
    configurationItems: Optional[ConfigurationItemList]
    nextToken: Optional[NextToken]


class GetStoredQueryRequest(ServiceRequest):
    QueryName: QueryName


class StoredQuery(TypedDict, total=False):
    QueryId: Optional[QueryId]
    QueryArn: Optional[QueryArn]
    QueryName: QueryName
    Description: Optional[QueryDescription]
    Expression: Optional[QueryExpression]


class GetStoredQueryResponse(TypedDict, total=False):
    StoredQuery: Optional[StoredQuery]


class ResourceFilters(TypedDict, total=False):
    AccountId: Optional[AccountId]
    ResourceId: Optional[ResourceId]
    ResourceName: Optional[ResourceName]
    Region: Optional[AwsRegion]


class ListAggregateDiscoveredResourcesRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    ResourceType: ResourceType
    Filters: Optional[ResourceFilters]
    Limit: Optional[Limit]
    NextToken: Optional[NextToken]


class ListAggregateDiscoveredResourcesResponse(TypedDict, total=False):
    ResourceIdentifiers: Optional[DiscoveredResourceIdentifierList]
    NextToken: Optional[NextToken]


ResourceIdList = List[ResourceId]


class ListDiscoveredResourcesRequest(ServiceRequest):
    resourceType: ResourceType
    resourceIds: Optional[ResourceIdList]
    resourceName: Optional[ResourceName]
    limit: Optional[Limit]
    includeDeletedResources: Optional[Boolean]
    nextToken: Optional[NextToken]


ResourceDeletionTime = datetime


class ResourceIdentifier(TypedDict, total=False):
    resourceType: Optional[ResourceType]
    resourceId: Optional[ResourceId]
    resourceName: Optional[ResourceName]
    resourceDeletionTime: Optional[ResourceDeletionTime]


ResourceIdentifierList = List[ResourceIdentifier]


class ListDiscoveredResourcesResponse(TypedDict, total=False):
    resourceIdentifiers: Optional[ResourceIdentifierList]
    nextToken: Optional[NextToken]


class ListStoredQueriesRequest(ServiceRequest):
    NextToken: Optional[String]
    MaxResults: Optional[Limit]


class StoredQueryMetadata(TypedDict, total=False):
    QueryId: QueryId
    QueryArn: QueryArn
    QueryName: QueryName
    Description: Optional[QueryDescription]


StoredQueryMetadataList = List[StoredQueryMetadata]


class ListStoredQueriesResponse(TypedDict, total=False):
    StoredQueryMetadata: Optional[StoredQueryMetadataList]
    NextToken: Optional[String]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    Limit: Optional[Limit]
    NextToken: Optional[NextToken]


class Tag(TypedDict, total=False):
    Key: Optional[TagKey]
    Value: Optional[TagValue]


TagList = List[Tag]


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[TagList]
    NextToken: Optional[NextToken]


TagsList = List[Tag]


class PutAggregationAuthorizationRequest(ServiceRequest):
    AuthorizedAccountId: AccountId
    AuthorizedAwsRegion: AwsRegion
    Tags: Optional[TagsList]


class PutAggregationAuthorizationResponse(TypedDict, total=False):
    AggregationAuthorization: Optional[AggregationAuthorization]


class PutConfigRuleRequest(ServiceRequest):
    ConfigRule: ConfigRule
    Tags: Optional[TagsList]


class PutConfigurationAggregatorRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    AccountAggregationSources: Optional[AccountAggregationSourceList]
    OrganizationAggregationSource: Optional[OrganizationAggregationSource]
    Tags: Optional[TagsList]


class PutConfigurationAggregatorResponse(TypedDict, total=False):
    ConfigurationAggregator: Optional[ConfigurationAggregator]


class PutConfigurationRecorderRequest(ServiceRequest):
    ConfigurationRecorder: ConfigurationRecorder


class PutConformancePackRequest(ServiceRequest):
    ConformancePackName: ConformancePackName
    TemplateS3Uri: Optional[TemplateS3Uri]
    TemplateBody: Optional[TemplateBody]
    DeliveryS3Bucket: Optional[DeliveryS3Bucket]
    DeliveryS3KeyPrefix: Optional[DeliveryS3KeyPrefix]
    ConformancePackInputParameters: Optional[ConformancePackInputParameters]


class PutConformancePackResponse(TypedDict, total=False):
    ConformancePackArn: Optional[ConformancePackArn]


class PutDeliveryChannelRequest(ServiceRequest):
    DeliveryChannel: DeliveryChannel


class PutEvaluationsRequest(ServiceRequest):
    Evaluations: Optional[Evaluations]
    ResultToken: String
    TestMode: Optional[Boolean]


class PutEvaluationsResponse(TypedDict, total=False):
    FailedEvaluations: Optional[Evaluations]


class PutExternalEvaluationRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ExternalEvaluation: ExternalEvaluation


class PutExternalEvaluationResponse(TypedDict, total=False):
    pass


class PutOrganizationConfigRuleRequest(ServiceRequest):
    OrganizationConfigRuleName: OrganizationConfigRuleName
    OrganizationManagedRuleMetadata: Optional[OrganizationManagedRuleMetadata]
    OrganizationCustomRuleMetadata: Optional[OrganizationCustomRuleMetadata]
    ExcludedAccounts: Optional[ExcludedAccounts]


class PutOrganizationConfigRuleResponse(TypedDict, total=False):
    OrganizationConfigRuleArn: Optional[StringWithCharLimit256]


class PutOrganizationConformancePackRequest(ServiceRequest):
    OrganizationConformancePackName: OrganizationConformancePackName
    TemplateS3Uri: Optional[TemplateS3Uri]
    TemplateBody: Optional[TemplateBody]
    DeliveryS3Bucket: Optional[DeliveryS3Bucket]
    DeliveryS3KeyPrefix: Optional[DeliveryS3KeyPrefix]
    ConformancePackInputParameters: Optional[ConformancePackInputParameters]
    ExcludedAccounts: Optional[ExcludedAccounts]


class PutOrganizationConformancePackResponse(TypedDict, total=False):
    OrganizationConformancePackArn: Optional[StringWithCharLimit256]


class PutRemediationConfigurationsRequest(ServiceRequest):
    RemediationConfigurations: RemediationConfigurations


class PutRemediationConfigurationsResponse(TypedDict, total=False):
    FailedBatches: Optional[FailedRemediationBatches]


class PutRemediationExceptionsRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: RemediationExceptionResourceKeys
    Message: Optional[StringWithCharLimit1024]
    ExpirationTime: Optional[Date]


class PutRemediationExceptionsResponse(TypedDict, total=False):
    FailedBatches: Optional[FailedRemediationExceptionBatches]


class PutResourceConfigRequest(ServiceRequest):
    ResourceType: ResourceTypeString
    SchemaVersionId: SchemaVersionId
    ResourceId: ResourceId
    ResourceName: Optional[ResourceName]
    Configuration: Configuration
    Tags: Optional[Tags]


class PutRetentionConfigurationRequest(ServiceRequest):
    RetentionPeriodInDays: RetentionPeriodInDays


class PutRetentionConfigurationResponse(TypedDict, total=False):
    RetentionConfiguration: Optional[RetentionConfiguration]


class PutStoredQueryRequest(ServiceRequest):
    StoredQuery: StoredQuery
    Tags: Optional[TagsList]


class PutStoredQueryResponse(TypedDict, total=False):
    QueryArn: Optional[QueryArn]


class QueryInfo(TypedDict, total=False):
    SelectFields: Optional[FieldInfoList]


ReevaluateConfigRuleNames = List[ConfigRuleName]
Results = List[String]


class SelectAggregateResourceConfigRequest(ServiceRequest):
    Expression: Expression
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Limit: Optional[Limit]
    MaxResults: Optional[Limit]
    NextToken: Optional[NextToken]


class SelectAggregateResourceConfigResponse(TypedDict, total=False):
    Results: Optional[Results]
    QueryInfo: Optional[QueryInfo]
    NextToken: Optional[NextToken]


class SelectResourceConfigRequest(ServiceRequest):
    Expression: Expression
    Limit: Optional[Limit]
    NextToken: Optional[NextToken]


class SelectResourceConfigResponse(TypedDict, total=False):
    Results: Optional[Results]
    QueryInfo: Optional[QueryInfo]
    NextToken: Optional[NextToken]


class StartConfigRulesEvaluationRequest(ServiceRequest):
    ConfigRuleNames: Optional[ReevaluateConfigRuleNames]


class StartConfigRulesEvaluationResponse(TypedDict, total=False):
    pass


class StartConfigurationRecorderRequest(ServiceRequest):
    ConfigurationRecorderName: RecorderName


class StartRemediationExecutionRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: ResourceKeys


class StartRemediationExecutionResponse(TypedDict, total=False):
    FailureMessage: Optional[String]
    FailedItems: Optional[ResourceKeys]


class StopConfigurationRecorderRequest(ServiceRequest):
    ConfigurationRecorderName: RecorderName


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    Tags: TagList


class UntagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    TagKeys: TagKeyList


class ConfigApi:

    service = "config"
    version = "2014-11-12"

    @handler("BatchGetAggregateResourceConfig")
    def batch_get_aggregate_resource_config(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        resource_identifiers: ResourceIdentifiersList,
    ) -> BatchGetAggregateResourceConfigResponse:
        raise NotImplementedError

    @handler("BatchGetResourceConfig")
    def batch_get_resource_config(
        self, context: RequestContext, resource_keys: ResourceKeys
    ) -> BatchGetResourceConfigResponse:
        raise NotImplementedError

    @handler("DeleteAggregationAuthorization")
    def delete_aggregation_authorization(
        self,
        context: RequestContext,
        authorized_account_id: AccountId,
        authorized_aws_region: AwsRegion,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteConfigRule")
    def delete_config_rule(self, context: RequestContext, config_rule_name: ConfigRuleName) -> None:
        raise NotImplementedError

    @handler("DeleteConfigurationAggregator")
    def delete_configuration_aggregator(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteConfigurationRecorder")
    def delete_configuration_recorder(
        self, context: RequestContext, configuration_recorder_name: RecorderName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteConformancePack")
    def delete_conformance_pack(
        self, context: RequestContext, conformance_pack_name: ConformancePackName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDeliveryChannel")
    def delete_delivery_channel(
        self, context: RequestContext, delivery_channel_name: ChannelName
    ) -> None:
        raise NotImplementedError

    @handler("DeleteEvaluationResults")
    def delete_evaluation_results(
        self, context: RequestContext, config_rule_name: StringWithCharLimit64
    ) -> DeleteEvaluationResultsResponse:
        raise NotImplementedError

    @handler("DeleteOrganizationConfigRule")
    def delete_organization_config_rule(
        self,
        context: RequestContext,
        organization_config_rule_name: OrganizationConfigRuleName,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteOrganizationConformancePack")
    def delete_organization_conformance_pack(
        self,
        context: RequestContext,
        organization_conformance_pack_name: OrganizationConformancePackName,
    ) -> None:
        raise NotImplementedError

    @handler("DeletePendingAggregationRequest")
    def delete_pending_aggregation_request(
        self,
        context: RequestContext,
        requester_account_id: AccountId,
        requester_aws_region: AwsRegion,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRemediationConfiguration")
    def delete_remediation_configuration(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_type: String = None,
    ) -> DeleteRemediationConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteRemediationExceptions")
    def delete_remediation_exceptions(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: RemediationExceptionResourceKeys,
    ) -> DeleteRemediationExceptionsResponse:
        raise NotImplementedError

    @handler("DeleteResourceConfig")
    def delete_resource_config(
        self,
        context: RequestContext,
        resource_type: ResourceTypeString,
        resource_id: ResourceId,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRetentionConfiguration")
    def delete_retention_configuration(
        self,
        context: RequestContext,
        retention_configuration_name: RetentionConfigurationName,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteStoredQuery")
    def delete_stored_query(
        self, context: RequestContext, query_name: QueryName
    ) -> DeleteStoredQueryResponse:
        raise NotImplementedError

    @handler("DeliverConfigSnapshot")
    def deliver_config_snapshot(
        self, context: RequestContext, delivery_channel_name: ChannelName
    ) -> DeliverConfigSnapshotResponse:
        raise NotImplementedError

    @handler("DescribeAggregateComplianceByConfigRules")
    def describe_aggregate_compliance_by_config_rules(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: ConfigRuleComplianceFilters = None,
        limit: GroupByAPILimit = None,
        next_token: NextToken = None,
    ) -> DescribeAggregateComplianceByConfigRulesResponse:
        raise NotImplementedError

    @handler("DescribeAggregateComplianceByConformancePacks")
    def describe_aggregate_compliance_by_conformance_packs(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: AggregateConformancePackComplianceFilters = None,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> DescribeAggregateComplianceByConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribeAggregationAuthorizations")
    def describe_aggregation_authorizations(
        self, context: RequestContext, limit: Limit = None, next_token: String = None
    ) -> DescribeAggregationAuthorizationsResponse:
        raise NotImplementedError

    @handler("DescribeComplianceByConfigRule")
    def describe_compliance_by_config_rule(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames = None,
        compliance_types: ComplianceTypes = None,
        next_token: String = None,
    ) -> DescribeComplianceByConfigRuleResponse:
        raise NotImplementedError

    @handler("DescribeComplianceByResource")
    def describe_compliance_by_resource(
        self,
        context: RequestContext,
        resource_type: StringWithCharLimit256 = None,
        resource_id: BaseResourceId = None,
        compliance_types: ComplianceTypes = None,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> DescribeComplianceByResourceResponse:
        raise NotImplementedError

    @handler("DescribeConfigRuleEvaluationStatus")
    def describe_config_rule_evaluation_status(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames = None,
        next_token: String = None,
        limit: RuleLimit = None,
    ) -> DescribeConfigRuleEvaluationStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigRules")
    def describe_config_rules(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames = None,
        next_token: String = None,
    ) -> DescribeConfigRulesResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationAggregatorSourcesStatus")
    def describe_configuration_aggregator_sources_status(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        update_status: AggregatedSourceStatusTypeList = None,
        next_token: String = None,
        limit: Limit = None,
    ) -> DescribeConfigurationAggregatorSourcesStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationAggregators")
    def describe_configuration_aggregators(
        self,
        context: RequestContext,
        configuration_aggregator_names: ConfigurationAggregatorNameList = None,
        next_token: String = None,
        limit: Limit = None,
    ) -> DescribeConfigurationAggregatorsResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRecorderStatus")
    def describe_configuration_recorder_status(
        self,
        context: RequestContext,
        configuration_recorder_names: ConfigurationRecorderNameList = None,
    ) -> DescribeConfigurationRecorderStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRecorders")
    def describe_configuration_recorders(
        self,
        context: RequestContext,
        configuration_recorder_names: ConfigurationRecorderNameList = None,
    ) -> DescribeConfigurationRecordersResponse:
        raise NotImplementedError

    @handler("DescribeConformancePackCompliance")
    def describe_conformance_pack_compliance(
        self,
        context: RequestContext,
        conformance_pack_name: ConformancePackName,
        filters: ConformancePackComplianceFilters = None,
        limit: DescribeConformancePackComplianceLimit = None,
        next_token: NextToken = None,
    ) -> DescribeConformancePackComplianceResponse:
        raise NotImplementedError

    @handler("DescribeConformancePackStatus")
    def describe_conformance_pack_status(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesList = None,
        limit: PageSizeLimit = None,
        next_token: NextToken = None,
    ) -> DescribeConformancePackStatusResponse:
        raise NotImplementedError

    @handler("DescribeConformancePacks")
    def describe_conformance_packs(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesList = None,
        limit: PageSizeLimit = None,
        next_token: NextToken = None,
    ) -> DescribeConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribeDeliveryChannelStatus")
    def describe_delivery_channel_status(
        self,
        context: RequestContext,
        delivery_channel_names: DeliveryChannelNameList = None,
    ) -> DescribeDeliveryChannelStatusResponse:
        raise NotImplementedError

    @handler("DescribeDeliveryChannels")
    def describe_delivery_channels(
        self,
        context: RequestContext,
        delivery_channel_names: DeliveryChannelNameList = None,
    ) -> DescribeDeliveryChannelsResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConfigRuleStatuses")
    def describe_organization_config_rule_statuses(
        self,
        context: RequestContext,
        organization_config_rule_names: OrganizationConfigRuleNames = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
    ) -> DescribeOrganizationConfigRuleStatusesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConfigRules")
    def describe_organization_config_rules(
        self,
        context: RequestContext,
        organization_config_rule_names: OrganizationConfigRuleNames = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
    ) -> DescribeOrganizationConfigRulesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConformancePackStatuses")
    def describe_organization_conformance_pack_statuses(
        self,
        context: RequestContext,
        organization_conformance_pack_names: OrganizationConformancePackNames = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
    ) -> DescribeOrganizationConformancePackStatusesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConformancePacks")
    def describe_organization_conformance_packs(
        self,
        context: RequestContext,
        organization_conformance_pack_names: OrganizationConformancePackNames = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
    ) -> DescribeOrganizationConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribePendingAggregationRequests")
    def describe_pending_aggregation_requests(
        self,
        context: RequestContext,
        limit: DescribePendingAggregationRequestsLimit = None,
        next_token: String = None,
    ) -> DescribePendingAggregationRequestsResponse:
        raise NotImplementedError

    @handler("DescribeRemediationConfigurations")
    def describe_remediation_configurations(
        self, context: RequestContext, config_rule_names: ConfigRuleNames
    ) -> DescribeRemediationConfigurationsResponse:
        raise NotImplementedError

    @handler("DescribeRemediationExceptions")
    def describe_remediation_exceptions(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: RemediationExceptionResourceKeys = None,
        limit: Limit = None,
        next_token: String = None,
    ) -> DescribeRemediationExceptionsResponse:
        raise NotImplementedError

    @handler("DescribeRemediationExecutionStatus")
    def describe_remediation_execution_status(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: ResourceKeys = None,
        limit: Limit = None,
        next_token: String = None,
    ) -> DescribeRemediationExecutionStatusResponse:
        raise NotImplementedError

    @handler("DescribeRetentionConfigurations")
    def describe_retention_configurations(
        self,
        context: RequestContext,
        retention_configuration_names: RetentionConfigurationNameList = None,
        next_token: NextToken = None,
    ) -> DescribeRetentionConfigurationsResponse:
        raise NotImplementedError

    @handler("GetAggregateComplianceDetailsByConfigRule")
    def get_aggregate_compliance_details_by_config_rule(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        config_rule_name: ConfigRuleName,
        account_id: AccountId,
        aws_region: AwsRegion,
        compliance_type: ComplianceType = None,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> GetAggregateComplianceDetailsByConfigRuleResponse:
        raise NotImplementedError

    @handler("GetAggregateConfigRuleComplianceSummary")
    def get_aggregate_config_rule_compliance_summary(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: ConfigRuleComplianceSummaryFilters = None,
        group_by_key: ConfigRuleComplianceSummaryGroupKey = None,
        limit: GroupByAPILimit = None,
        next_token: NextToken = None,
    ) -> GetAggregateConfigRuleComplianceSummaryResponse:
        raise NotImplementedError

    @handler("GetAggregateConformancePackComplianceSummary")
    def get_aggregate_conformance_pack_compliance_summary(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: AggregateConformancePackComplianceSummaryFilters = None,
        group_by_key: AggregateConformancePackComplianceSummaryGroupKey = None,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> GetAggregateConformancePackComplianceSummaryResponse:
        raise NotImplementedError

    @handler("GetAggregateDiscoveredResourceCounts")
    def get_aggregate_discovered_resource_counts(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: ResourceCountFilters = None,
        group_by_key: ResourceCountGroupKey = None,
        limit: GroupByAPILimit = None,
        next_token: NextToken = None,
    ) -> GetAggregateDiscoveredResourceCountsResponse:
        raise NotImplementedError

    @handler("GetAggregateResourceConfig")
    def get_aggregate_resource_config(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        resource_identifier: AggregateResourceIdentifier,
    ) -> GetAggregateResourceConfigResponse:
        raise NotImplementedError

    @handler("GetComplianceDetailsByConfigRule")
    def get_compliance_details_by_config_rule(
        self,
        context: RequestContext,
        config_rule_name: StringWithCharLimit64,
        compliance_types: ComplianceTypes = None,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> GetComplianceDetailsByConfigRuleResponse:
        raise NotImplementedError

    @handler("GetComplianceDetailsByResource")
    def get_compliance_details_by_resource(
        self,
        context: RequestContext,
        resource_type: StringWithCharLimit256,
        resource_id: BaseResourceId,
        compliance_types: ComplianceTypes = None,
        next_token: String = None,
    ) -> GetComplianceDetailsByResourceResponse:
        raise NotImplementedError

    @handler("GetComplianceSummaryByConfigRule")
    def get_compliance_summary_by_config_rule(
        self,
        context: RequestContext,
    ) -> GetComplianceSummaryByConfigRuleResponse:
        raise NotImplementedError

    @handler("GetComplianceSummaryByResourceType")
    def get_compliance_summary_by_resource_type(
        self, context: RequestContext, resource_types: ResourceTypes = None
    ) -> GetComplianceSummaryByResourceTypeResponse:
        raise NotImplementedError

    @handler("GetConformancePackComplianceDetails")
    def get_conformance_pack_compliance_details(
        self,
        context: RequestContext,
        conformance_pack_name: ConformancePackName,
        filters: ConformancePackEvaluationFilters = None,
        limit: GetConformancePackComplianceDetailsLimit = None,
        next_token: NextToken = None,
    ) -> GetConformancePackComplianceDetailsResponse:
        raise NotImplementedError

    @handler("GetConformancePackComplianceSummary")
    def get_conformance_pack_compliance_summary(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesToSummarizeList,
        limit: PageSizeLimit = None,
        next_token: NextToken = None,
    ) -> GetConformancePackComplianceSummaryResponse:
        raise NotImplementedError

    @handler("GetDiscoveredResourceCounts")
    def get_discovered_resource_counts(
        self,
        context: RequestContext,
        resource_types: ResourceTypes = None,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> GetDiscoveredResourceCountsResponse:
        raise NotImplementedError

    @handler("GetOrganizationConfigRuleDetailedStatus")
    def get_organization_config_rule_detailed_status(
        self,
        context: RequestContext,
        organization_config_rule_name: OrganizationConfigRuleName,
        filters: StatusDetailFilters = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
    ) -> GetOrganizationConfigRuleDetailedStatusResponse:
        raise NotImplementedError

    @handler("GetOrganizationConformancePackDetailedStatus")
    def get_organization_conformance_pack_detailed_status(
        self,
        context: RequestContext,
        organization_conformance_pack_name: OrganizationConformancePackName,
        filters: OrganizationResourceDetailedStatusFilters = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
    ) -> GetOrganizationConformancePackDetailedStatusResponse:
        raise NotImplementedError

    @handler("GetResourceConfigHistory")
    def get_resource_config_history(
        self,
        context: RequestContext,
        resource_type: ResourceType,
        resource_id: ResourceId,
        later_time: LaterTime = None,
        earlier_time: EarlierTime = None,
        chronological_order: ChronologicalOrder = None,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> GetResourceConfigHistoryResponse:
        raise NotImplementedError

    @handler("GetStoredQuery")
    def get_stored_query(
        self, context: RequestContext, query_name: QueryName
    ) -> GetStoredQueryResponse:
        raise NotImplementedError

    @handler("ListAggregateDiscoveredResources")
    def list_aggregate_discovered_resources(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        resource_type: ResourceType,
        filters: ResourceFilters = None,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> ListAggregateDiscoveredResourcesResponse:
        raise NotImplementedError

    @handler("ListDiscoveredResources")
    def list_discovered_resources(
        self,
        context: RequestContext,
        resource_type: ResourceType,
        resource_ids: ResourceIdList = None,
        resource_name: ResourceName = None,
        limit: Limit = None,
        include_deleted_resources: Boolean = None,
        next_token: NextToken = None,
    ) -> ListDiscoveredResourcesResponse:
        raise NotImplementedError

    @handler("ListStoredQueries")
    def list_stored_queries(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: Limit = None,
    ) -> ListStoredQueriesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutAggregationAuthorization")
    def put_aggregation_authorization(
        self,
        context: RequestContext,
        authorized_account_id: AccountId,
        authorized_aws_region: AwsRegion,
        tags: TagsList = None,
    ) -> PutAggregationAuthorizationResponse:
        raise NotImplementedError

    @handler("PutConfigRule")
    def put_config_rule(
        self, context: RequestContext, config_rule: ConfigRule, tags: TagsList = None
    ) -> None:
        raise NotImplementedError

    @handler("PutConfigurationAggregator")
    def put_configuration_aggregator(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        account_aggregation_sources: AccountAggregationSourceList = None,
        organization_aggregation_source: OrganizationAggregationSource = None,
        tags: TagsList = None,
    ) -> PutConfigurationAggregatorResponse:
        raise NotImplementedError

    @handler("PutConfigurationRecorder")
    def put_configuration_recorder(
        self, context: RequestContext, configuration_recorder: ConfigurationRecorder
    ) -> None:
        raise NotImplementedError

    @handler("PutConformancePack")
    def put_conformance_pack(
        self,
        context: RequestContext,
        conformance_pack_name: ConformancePackName,
        template_s3_uri: TemplateS3Uri = None,
        template_body: TemplateBody = None,
        delivery_s3_bucket: DeliveryS3Bucket = None,
        delivery_s3_key_prefix: DeliveryS3KeyPrefix = None,
        conformance_pack_input_parameters: ConformancePackInputParameters = None,
    ) -> PutConformancePackResponse:
        raise NotImplementedError

    @handler("PutDeliveryChannel")
    def put_delivery_channel(
        self, context: RequestContext, delivery_channel: DeliveryChannel
    ) -> None:
        raise NotImplementedError

    @handler("PutEvaluations")
    def put_evaluations(
        self,
        context: RequestContext,
        result_token: String,
        evaluations: Evaluations = None,
        test_mode: Boolean = None,
    ) -> PutEvaluationsResponse:
        raise NotImplementedError

    @handler("PutExternalEvaluation")
    def put_external_evaluation(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        external_evaluation: ExternalEvaluation,
    ) -> PutExternalEvaluationResponse:
        raise NotImplementedError

    @handler("PutOrganizationConfigRule")
    def put_organization_config_rule(
        self,
        context: RequestContext,
        organization_config_rule_name: OrganizationConfigRuleName,
        organization_managed_rule_metadata: OrganizationManagedRuleMetadata = None,
        organization_custom_rule_metadata: OrganizationCustomRuleMetadata = None,
        excluded_accounts: ExcludedAccounts = None,
    ) -> PutOrganizationConfigRuleResponse:
        raise NotImplementedError

    @handler("PutOrganizationConformancePack")
    def put_organization_conformance_pack(
        self,
        context: RequestContext,
        organization_conformance_pack_name: OrganizationConformancePackName,
        template_s3_uri: TemplateS3Uri = None,
        template_body: TemplateBody = None,
        delivery_s3_bucket: DeliveryS3Bucket = None,
        delivery_s3_key_prefix: DeliveryS3KeyPrefix = None,
        conformance_pack_input_parameters: ConformancePackInputParameters = None,
        excluded_accounts: ExcludedAccounts = None,
    ) -> PutOrganizationConformancePackResponse:
        raise NotImplementedError

    @handler("PutRemediationConfigurations")
    def put_remediation_configurations(
        self,
        context: RequestContext,
        remediation_configurations: RemediationConfigurations,
    ) -> PutRemediationConfigurationsResponse:
        raise NotImplementedError

    @handler("PutRemediationExceptions")
    def put_remediation_exceptions(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: RemediationExceptionResourceKeys,
        message: StringWithCharLimit1024 = None,
        expiration_time: Date = None,
    ) -> PutRemediationExceptionsResponse:
        raise NotImplementedError

    @handler("PutResourceConfig")
    def put_resource_config(
        self,
        context: RequestContext,
        resource_type: ResourceTypeString,
        schema_version_id: SchemaVersionId,
        resource_id: ResourceId,
        configuration: Configuration,
        resource_name: ResourceName = None,
        tags: Tags = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutRetentionConfiguration")
    def put_retention_configuration(
        self, context: RequestContext, retention_period_in_days: RetentionPeriodInDays
    ) -> PutRetentionConfigurationResponse:
        raise NotImplementedError

    @handler("PutStoredQuery")
    def put_stored_query(
        self, context: RequestContext, stored_query: StoredQuery, tags: TagsList = None
    ) -> PutStoredQueryResponse:
        raise NotImplementedError

    @handler("SelectAggregateResourceConfig")
    def select_aggregate_resource_config(
        self,
        context: RequestContext,
        expression: Expression,
        configuration_aggregator_name: ConfigurationAggregatorName,
        limit: Limit = None,
        max_results: Limit = None,
        next_token: NextToken = None,
    ) -> SelectAggregateResourceConfigResponse:
        raise NotImplementedError

    @handler("SelectResourceConfig")
    def select_resource_config(
        self,
        context: RequestContext,
        expression: Expression,
        limit: Limit = None,
        next_token: NextToken = None,
    ) -> SelectResourceConfigResponse:
        raise NotImplementedError

    @handler("StartConfigRulesEvaluation")
    def start_config_rules_evaluation(
        self,
        context: RequestContext,
        config_rule_names: ReevaluateConfigRuleNames = None,
    ) -> StartConfigRulesEvaluationResponse:
        raise NotImplementedError

    @handler("StartConfigurationRecorder")
    def start_configuration_recorder(
        self, context: RequestContext, configuration_recorder_name: RecorderName
    ) -> None:
        raise NotImplementedError

    @handler("StartRemediationExecution")
    def start_remediation_execution(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: ResourceKeys,
    ) -> StartRemediationExecutionResponse:
        raise NotImplementedError

    @handler("StopConfigurationRecorder")
    def stop_configuration_recorder(
        self, context: RequestContext, configuration_recorder_name: RecorderName
    ) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        tag_keys: TagKeyList,
    ) -> None:
        raise NotImplementedError
