from datetime import datetime
from enum import StrEnum
from typing import TypedDict

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
ClientToken = str
ComplianceScore = str
ConfigRuleName = str
Configuration = str
ConfigurationAggregatorArn = str
ConfigurationAggregatorName = str
ConfigurationItemMD5Hash = str
ConfigurationRecorderFilterValue = str
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
Description = str
EmptiableStringWithCharLimit256 = str
ErrorMessage = str
EvaluationContextIdentifier = str
EvaluationTimeout = int
Expression = str
FieldName = str
GetConformancePackComplianceDetailsLimit = int
GroupByAPILimit = int
IncludeGlobalResourceTypes = bool
Integer = int
Limit = int
ListResourceEvaluationsPageItemLimit = int
MaxResults = int
Name = str
NextToken = str
OrganizationConfigRuleName = str
OrganizationConformancePackName = str
PageSizeLimit = int
ParameterName = str
ParameterValue = str
Percentage = int
PolicyRuntime = str
PolicyText = str
QueryArn = str
QueryDescription = str
QueryExpression = str
QueryId = str
QueryName = str
RecorderName = str
RelatedEvent = str
RelationshipName = str
ResourceConfiguration = str
ResourceEvaluationId = str
ResourceId = str
ResourceName = str
ResourceTypeString = str
ResourceTypeValue = str
RetentionConfigurationName = str
RetentionPeriodInDays = int
RuleLimit = int
SSMDocumentName = str
SSMDocumentVersion = str
SchemaVersionId = str
ServicePrincipal = str
ServicePrincipalValue = str
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


class AggregateConformancePackComplianceSummaryGroupKey(StrEnum):
    ACCOUNT_ID = "ACCOUNT_ID"
    AWS_REGION = "AWS_REGION"


class AggregatedSourceStatusType(StrEnum):
    FAILED = "FAILED"
    SUCCEEDED = "SUCCEEDED"
    OUTDATED = "OUTDATED"


class AggregatedSourceType(StrEnum):
    ACCOUNT = "ACCOUNT"
    ORGANIZATION = "ORGANIZATION"


class AggregatorFilterType(StrEnum):
    INCLUDE = "INCLUDE"


class ChronologicalOrder(StrEnum):
    Reverse = "Reverse"
    Forward = "Forward"


class ComplianceType(StrEnum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ConfigRuleComplianceSummaryGroupKey(StrEnum):
    ACCOUNT_ID = "ACCOUNT_ID"
    AWS_REGION = "AWS_REGION"


class ConfigRuleState(StrEnum):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"
    DELETING_RESULTS = "DELETING_RESULTS"
    EVALUATING = "EVALUATING"


class ConfigurationItemStatus(StrEnum):
    OK = "OK"
    ResourceDiscovered = "ResourceDiscovered"
    ResourceNotRecorded = "ResourceNotRecorded"
    ResourceDeleted = "ResourceDeleted"
    ResourceDeletedNotRecorded = "ResourceDeletedNotRecorded"


class ConfigurationRecorderFilterName(StrEnum):
    recordingScope = "recordingScope"


class ConformancePackComplianceType(StrEnum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ConformancePackState(StrEnum):
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_COMPLETE = "CREATE_COMPLETE"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    DELETE_FAILED = "DELETE_FAILED"


class DeliveryStatus(StrEnum):
    Success = "Success"
    Failure = "Failure"
    Not_Applicable = "Not_Applicable"


class EvaluationMode(StrEnum):
    DETECTIVE = "DETECTIVE"
    PROACTIVE = "PROACTIVE"


class EventSource(StrEnum):
    aws_config = "aws.config"


class MaximumExecutionFrequency(StrEnum):
    One_Hour = "One_Hour"
    Three_Hours = "Three_Hours"
    Six_Hours = "Six_Hours"
    Twelve_Hours = "Twelve_Hours"
    TwentyFour_Hours = "TwentyFour_Hours"


class MemberAccountRuleStatus(StrEnum):
    CREATE_SUCCESSFUL = "CREATE_SUCCESSFUL"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_SUCCESSFUL = "DELETE_SUCCESSFUL"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"


class MessageType(StrEnum):
    ConfigurationItemChangeNotification = "ConfigurationItemChangeNotification"
    ConfigurationSnapshotDeliveryCompleted = "ConfigurationSnapshotDeliveryCompleted"
    ScheduledNotification = "ScheduledNotification"
    OversizedConfigurationItemChangeNotification = "OversizedConfigurationItemChangeNotification"


class OrganizationConfigRuleTriggerType(StrEnum):
    ConfigurationItemChangeNotification = "ConfigurationItemChangeNotification"
    OversizedConfigurationItemChangeNotification = "OversizedConfigurationItemChangeNotification"
    ScheduledNotification = "ScheduledNotification"


class OrganizationConfigRuleTriggerTypeNoSN(StrEnum):
    ConfigurationItemChangeNotification = "ConfigurationItemChangeNotification"
    OversizedConfigurationItemChangeNotification = "OversizedConfigurationItemChangeNotification"


class OrganizationResourceDetailedStatus(StrEnum):
    CREATE_SUCCESSFUL = "CREATE_SUCCESSFUL"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_SUCCESSFUL = "DELETE_SUCCESSFUL"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"


class OrganizationResourceStatus(StrEnum):
    CREATE_SUCCESSFUL = "CREATE_SUCCESSFUL"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_SUCCESSFUL = "DELETE_SUCCESSFUL"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"


class OrganizationRuleStatus(StrEnum):
    CREATE_SUCCESSFUL = "CREATE_SUCCESSFUL"
    CREATE_IN_PROGRESS = "CREATE_IN_PROGRESS"
    CREATE_FAILED = "CREATE_FAILED"
    DELETE_SUCCESSFUL = "DELETE_SUCCESSFUL"
    DELETE_FAILED = "DELETE_FAILED"
    DELETE_IN_PROGRESS = "DELETE_IN_PROGRESS"
    UPDATE_SUCCESSFUL = "UPDATE_SUCCESSFUL"
    UPDATE_IN_PROGRESS = "UPDATE_IN_PROGRESS"
    UPDATE_FAILED = "UPDATE_FAILED"


class Owner(StrEnum):
    CUSTOM_LAMBDA = "CUSTOM_LAMBDA"
    AWS = "AWS"
    CUSTOM_POLICY = "CUSTOM_POLICY"


class RecorderStatus(StrEnum):
    Pending = "Pending"
    Success = "Success"
    Failure = "Failure"
    NotApplicable = "NotApplicable"


class RecordingFrequency(StrEnum):
    CONTINUOUS = "CONTINUOUS"
    DAILY = "DAILY"


class RecordingScope(StrEnum):
    INTERNAL = "INTERNAL"
    PAID = "PAID"


class RecordingStrategyType(StrEnum):
    ALL_SUPPORTED_RESOURCE_TYPES = "ALL_SUPPORTED_RESOURCE_TYPES"
    INCLUSION_BY_RESOURCE_TYPES = "INCLUSION_BY_RESOURCE_TYPES"
    EXCLUSION_BY_RESOURCE_TYPES = "EXCLUSION_BY_RESOURCE_TYPES"


class RemediationExecutionState(StrEnum):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class RemediationExecutionStepState(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    PENDING = "PENDING"
    FAILED = "FAILED"
    IN_PROGRESS = "IN_PROGRESS"
    EXITED = "EXITED"
    UNKNOWN = "UNKNOWN"


class RemediationTargetType(StrEnum):
    SSM_DOCUMENT = "SSM_DOCUMENT"


class ResourceConfigurationSchemaType(StrEnum):
    CFN_RESOURCE_SCHEMA = "CFN_RESOURCE_SCHEMA"


class ResourceCountGroupKey(StrEnum):
    RESOURCE_TYPE = "RESOURCE_TYPE"
    ACCOUNT_ID = "ACCOUNT_ID"
    AWS_REGION = "AWS_REGION"


class ResourceEvaluationStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    SUCCEEDED = "SUCCEEDED"


class ResourceType(StrEnum):
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
    AWS_EC2_LaunchTemplate = "AWS::EC2::LaunchTemplate"
    AWS_ECR_PublicRepository = "AWS::ECR::PublicRepository"
    AWS_GuardDuty_Detector = "AWS::GuardDuty::Detector"
    AWS_EMR_SecurityConfiguration = "AWS::EMR::SecurityConfiguration"
    AWS_SageMaker_CodeRepository = "AWS::SageMaker::CodeRepository"
    AWS_Route53Resolver_ResolverEndpoint = "AWS::Route53Resolver::ResolverEndpoint"
    AWS_Route53Resolver_ResolverRule = "AWS::Route53Resolver::ResolverRule"
    AWS_Route53Resolver_ResolverRuleAssociation = "AWS::Route53Resolver::ResolverRuleAssociation"
    AWS_DMS_ReplicationSubnetGroup = "AWS::DMS::ReplicationSubnetGroup"
    AWS_DMS_EventSubscription = "AWS::DMS::EventSubscription"
    AWS_MSK_Cluster = "AWS::MSK::Cluster"
    AWS_StepFunctions_Activity = "AWS::StepFunctions::Activity"
    AWS_WorkSpaces_Workspace = "AWS::WorkSpaces::Workspace"
    AWS_WorkSpaces_ConnectionAlias = "AWS::WorkSpaces::ConnectionAlias"
    AWS_SageMaker_Model = "AWS::SageMaker::Model"
    AWS_ElasticLoadBalancingV2_Listener = "AWS::ElasticLoadBalancingV2::Listener"
    AWS_StepFunctions_StateMachine = "AWS::StepFunctions::StateMachine"
    AWS_Batch_JobQueue = "AWS::Batch::JobQueue"
    AWS_Batch_ComputeEnvironment = "AWS::Batch::ComputeEnvironment"
    AWS_AccessAnalyzer_Analyzer = "AWS::AccessAnalyzer::Analyzer"
    AWS_Athena_WorkGroup = "AWS::Athena::WorkGroup"
    AWS_Athena_DataCatalog = "AWS::Athena::DataCatalog"
    AWS_Detective_Graph = "AWS::Detective::Graph"
    AWS_GlobalAccelerator_Accelerator = "AWS::GlobalAccelerator::Accelerator"
    AWS_GlobalAccelerator_EndpointGroup = "AWS::GlobalAccelerator::EndpointGroup"
    AWS_GlobalAccelerator_Listener = "AWS::GlobalAccelerator::Listener"
    AWS_EC2_TransitGatewayAttachment = "AWS::EC2::TransitGatewayAttachment"
    AWS_EC2_TransitGatewayRouteTable = "AWS::EC2::TransitGatewayRouteTable"
    AWS_DMS_Certificate = "AWS::DMS::Certificate"
    AWS_AppConfig_Application = "AWS::AppConfig::Application"
    AWS_AppSync_GraphQLApi = "AWS::AppSync::GraphQLApi"
    AWS_DataSync_LocationSMB = "AWS::DataSync::LocationSMB"
    AWS_DataSync_LocationFSxLustre = "AWS::DataSync::LocationFSxLustre"
    AWS_DataSync_LocationS3 = "AWS::DataSync::LocationS3"
    AWS_DataSync_LocationEFS = "AWS::DataSync::LocationEFS"
    AWS_DataSync_Task = "AWS::DataSync::Task"
    AWS_DataSync_LocationNFS = "AWS::DataSync::LocationNFS"
    AWS_EC2_NetworkInsightsAccessScopeAnalysis = "AWS::EC2::NetworkInsightsAccessScopeAnalysis"
    AWS_EKS_FargateProfile = "AWS::EKS::FargateProfile"
    AWS_Glue_Job = "AWS::Glue::Job"
    AWS_GuardDuty_ThreatIntelSet = "AWS::GuardDuty::ThreatIntelSet"
    AWS_GuardDuty_IPSet = "AWS::GuardDuty::IPSet"
    AWS_SageMaker_Workteam = "AWS::SageMaker::Workteam"
    AWS_SageMaker_NotebookInstanceLifecycleConfig = (
        "AWS::SageMaker::NotebookInstanceLifecycleConfig"
    )
    AWS_ServiceDiscovery_Service = "AWS::ServiceDiscovery::Service"
    AWS_ServiceDiscovery_PublicDnsNamespace = "AWS::ServiceDiscovery::PublicDnsNamespace"
    AWS_SES_ContactList = "AWS::SES::ContactList"
    AWS_SES_ConfigurationSet = "AWS::SES::ConfigurationSet"
    AWS_Route53_HostedZone = "AWS::Route53::HostedZone"
    AWS_IoTEvents_Input = "AWS::IoTEvents::Input"
    AWS_IoTEvents_DetectorModel = "AWS::IoTEvents::DetectorModel"
    AWS_IoTEvents_AlarmModel = "AWS::IoTEvents::AlarmModel"
    AWS_ServiceDiscovery_HttpNamespace = "AWS::ServiceDiscovery::HttpNamespace"
    AWS_Events_EventBus = "AWS::Events::EventBus"
    AWS_ImageBuilder_ContainerRecipe = "AWS::ImageBuilder::ContainerRecipe"
    AWS_ImageBuilder_DistributionConfiguration = "AWS::ImageBuilder::DistributionConfiguration"
    AWS_ImageBuilder_InfrastructureConfiguration = "AWS::ImageBuilder::InfrastructureConfiguration"
    AWS_DataSync_LocationObjectStorage = "AWS::DataSync::LocationObjectStorage"
    AWS_DataSync_LocationHDFS = "AWS::DataSync::LocationHDFS"
    AWS_Glue_Classifier = "AWS::Glue::Classifier"
    AWS_Route53RecoveryReadiness_Cell = "AWS::Route53RecoveryReadiness::Cell"
    AWS_Route53RecoveryReadiness_ReadinessCheck = "AWS::Route53RecoveryReadiness::ReadinessCheck"
    AWS_ECR_RegistryPolicy = "AWS::ECR::RegistryPolicy"
    AWS_Backup_ReportPlan = "AWS::Backup::ReportPlan"
    AWS_Lightsail_Certificate = "AWS::Lightsail::Certificate"
    AWS_RUM_AppMonitor = "AWS::RUM::AppMonitor"
    AWS_Events_Endpoint = "AWS::Events::Endpoint"
    AWS_SES_ReceiptRuleSet = "AWS::SES::ReceiptRuleSet"
    AWS_Events_Archive = "AWS::Events::Archive"
    AWS_Events_ApiDestination = "AWS::Events::ApiDestination"
    AWS_Lightsail_Disk = "AWS::Lightsail::Disk"
    AWS_FIS_ExperimentTemplate = "AWS::FIS::ExperimentTemplate"
    AWS_DataSync_LocationFSxWindows = "AWS::DataSync::LocationFSxWindows"
    AWS_SES_ReceiptFilter = "AWS::SES::ReceiptFilter"
    AWS_GuardDuty_Filter = "AWS::GuardDuty::Filter"
    AWS_SES_Template = "AWS::SES::Template"
    AWS_AmazonMQ_Broker = "AWS::AmazonMQ::Broker"
    AWS_AppConfig_Environment = "AWS::AppConfig::Environment"
    AWS_AppConfig_ConfigurationProfile = "AWS::AppConfig::ConfigurationProfile"
    AWS_Cloud9_EnvironmentEC2 = "AWS::Cloud9::EnvironmentEC2"
    AWS_EventSchemas_Registry = "AWS::EventSchemas::Registry"
    AWS_EventSchemas_RegistryPolicy = "AWS::EventSchemas::RegistryPolicy"
    AWS_EventSchemas_Discoverer = "AWS::EventSchemas::Discoverer"
    AWS_FraudDetector_Label = "AWS::FraudDetector::Label"
    AWS_FraudDetector_EntityType = "AWS::FraudDetector::EntityType"
    AWS_FraudDetector_Variable = "AWS::FraudDetector::Variable"
    AWS_FraudDetector_Outcome = "AWS::FraudDetector::Outcome"
    AWS_IoT_Authorizer = "AWS::IoT::Authorizer"
    AWS_IoT_SecurityProfile = "AWS::IoT::SecurityProfile"
    AWS_IoT_RoleAlias = "AWS::IoT::RoleAlias"
    AWS_IoT_Dimension = "AWS::IoT::Dimension"
    AWS_IoTAnalytics_Datastore = "AWS::IoTAnalytics::Datastore"
    AWS_Lightsail_Bucket = "AWS::Lightsail::Bucket"
    AWS_Lightsail_StaticIp = "AWS::Lightsail::StaticIp"
    AWS_MediaPackage_PackagingGroup = "AWS::MediaPackage::PackagingGroup"
    AWS_Route53RecoveryReadiness_RecoveryGroup = "AWS::Route53RecoveryReadiness::RecoveryGroup"
    AWS_ResilienceHub_ResiliencyPolicy = "AWS::ResilienceHub::ResiliencyPolicy"
    AWS_Transfer_Workflow = "AWS::Transfer::Workflow"
    AWS_EKS_IdentityProviderConfig = "AWS::EKS::IdentityProviderConfig"
    AWS_EKS_Addon = "AWS::EKS::Addon"
    AWS_Glue_MLTransform = "AWS::Glue::MLTransform"
    AWS_IoT_Policy = "AWS::IoT::Policy"
    AWS_IoT_MitigationAction = "AWS::IoT::MitigationAction"
    AWS_IoTTwinMaker_Workspace = "AWS::IoTTwinMaker::Workspace"
    AWS_IoTTwinMaker_Entity = "AWS::IoTTwinMaker::Entity"
    AWS_IoTAnalytics_Dataset = "AWS::IoTAnalytics::Dataset"
    AWS_IoTAnalytics_Pipeline = "AWS::IoTAnalytics::Pipeline"
    AWS_IoTAnalytics_Channel = "AWS::IoTAnalytics::Channel"
    AWS_IoTSiteWise_Dashboard = "AWS::IoTSiteWise::Dashboard"
    AWS_IoTSiteWise_Project = "AWS::IoTSiteWise::Project"
    AWS_IoTSiteWise_Portal = "AWS::IoTSiteWise::Portal"
    AWS_IoTSiteWise_AssetModel = "AWS::IoTSiteWise::AssetModel"
    AWS_IVS_Channel = "AWS::IVS::Channel"
    AWS_IVS_RecordingConfiguration = "AWS::IVS::RecordingConfiguration"
    AWS_IVS_PlaybackKeyPair = "AWS::IVS::PlaybackKeyPair"
    AWS_KinesisAnalyticsV2_Application = "AWS::KinesisAnalyticsV2::Application"
    AWS_RDS_GlobalCluster = "AWS::RDS::GlobalCluster"
    AWS_S3_MultiRegionAccessPoint = "AWS::S3::MultiRegionAccessPoint"
    AWS_DeviceFarm_TestGridProject = "AWS::DeviceFarm::TestGridProject"
    AWS_Budgets_BudgetsAction = "AWS::Budgets::BudgetsAction"
    AWS_Lex_Bot = "AWS::Lex::Bot"
    AWS_CodeGuruReviewer_RepositoryAssociation = "AWS::CodeGuruReviewer::RepositoryAssociation"
    AWS_IoT_CustomMetric = "AWS::IoT::CustomMetric"
    AWS_Route53Resolver_FirewallDomainList = "AWS::Route53Resolver::FirewallDomainList"
    AWS_RoboMaker_RobotApplicationVersion = "AWS::RoboMaker::RobotApplicationVersion"
    AWS_EC2_TrafficMirrorSession = "AWS::EC2::TrafficMirrorSession"
    AWS_IoTSiteWise_Gateway = "AWS::IoTSiteWise::Gateway"
    AWS_Lex_BotAlias = "AWS::Lex::BotAlias"
    AWS_LookoutMetrics_Alert = "AWS::LookoutMetrics::Alert"
    AWS_IoT_AccountAuditConfiguration = "AWS::IoT::AccountAuditConfiguration"
    AWS_EC2_TrafficMirrorTarget = "AWS::EC2::TrafficMirrorTarget"
    AWS_S3_StorageLens = "AWS::S3::StorageLens"
    AWS_IoT_ScheduledAudit = "AWS::IoT::ScheduledAudit"
    AWS_Events_Connection = "AWS::Events::Connection"
    AWS_EventSchemas_Schema = "AWS::EventSchemas::Schema"
    AWS_MediaPackage_PackagingConfiguration = "AWS::MediaPackage::PackagingConfiguration"
    AWS_KinesisVideo_SignalingChannel = "AWS::KinesisVideo::SignalingChannel"
    AWS_AppStream_DirectoryConfig = "AWS::AppStream::DirectoryConfig"
    AWS_LookoutVision_Project = "AWS::LookoutVision::Project"
    AWS_Route53RecoveryControl_Cluster = "AWS::Route53RecoveryControl::Cluster"
    AWS_Route53RecoveryControl_SafetyRule = "AWS::Route53RecoveryControl::SafetyRule"
    AWS_Route53RecoveryControl_ControlPanel = "AWS::Route53RecoveryControl::ControlPanel"
    AWS_Route53RecoveryControl_RoutingControl = "AWS::Route53RecoveryControl::RoutingControl"
    AWS_Route53RecoveryReadiness_ResourceSet = "AWS::Route53RecoveryReadiness::ResourceSet"
    AWS_RoboMaker_SimulationApplication = "AWS::RoboMaker::SimulationApplication"
    AWS_RoboMaker_RobotApplication = "AWS::RoboMaker::RobotApplication"
    AWS_HealthLake_FHIRDatastore = "AWS::HealthLake::FHIRDatastore"
    AWS_Pinpoint_Segment = "AWS::Pinpoint::Segment"
    AWS_Pinpoint_ApplicationSettings = "AWS::Pinpoint::ApplicationSettings"
    AWS_Events_Rule = "AWS::Events::Rule"
    AWS_EC2_DHCPOptions = "AWS::EC2::DHCPOptions"
    AWS_EC2_NetworkInsightsPath = "AWS::EC2::NetworkInsightsPath"
    AWS_EC2_TrafficMirrorFilter = "AWS::EC2::TrafficMirrorFilter"
    AWS_EC2_IPAM = "AWS::EC2::IPAM"
    AWS_IoTTwinMaker_Scene = "AWS::IoTTwinMaker::Scene"
    AWS_NetworkManager_TransitGatewayRegistration = (
        "AWS::NetworkManager::TransitGatewayRegistration"
    )
    AWS_CustomerProfiles_Domain = "AWS::CustomerProfiles::Domain"
    AWS_AutoScaling_WarmPool = "AWS::AutoScaling::WarmPool"
    AWS_Connect_PhoneNumber = "AWS::Connect::PhoneNumber"
    AWS_AppConfig_DeploymentStrategy = "AWS::AppConfig::DeploymentStrategy"
    AWS_AppFlow_Flow = "AWS::AppFlow::Flow"
    AWS_AuditManager_Assessment = "AWS::AuditManager::Assessment"
    AWS_CloudWatch_MetricStream = "AWS::CloudWatch::MetricStream"
    AWS_DeviceFarm_InstanceProfile = "AWS::DeviceFarm::InstanceProfile"
    AWS_DeviceFarm_Project = "AWS::DeviceFarm::Project"
    AWS_EC2_EC2Fleet = "AWS::EC2::EC2Fleet"
    AWS_EC2_SubnetRouteTableAssociation = "AWS::EC2::SubnetRouteTableAssociation"
    AWS_ECR_PullThroughCacheRule = "AWS::ECR::PullThroughCacheRule"
    AWS_GroundStation_Config = "AWS::GroundStation::Config"
    AWS_ImageBuilder_ImagePipeline = "AWS::ImageBuilder::ImagePipeline"
    AWS_IoT_FleetMetric = "AWS::IoT::FleetMetric"
    AWS_IoTWireless_ServiceProfile = "AWS::IoTWireless::ServiceProfile"
    AWS_NetworkManager_Device = "AWS::NetworkManager::Device"
    AWS_NetworkManager_GlobalNetwork = "AWS::NetworkManager::GlobalNetwork"
    AWS_NetworkManager_Link = "AWS::NetworkManager::Link"
    AWS_NetworkManager_Site = "AWS::NetworkManager::Site"
    AWS_Panorama_Package = "AWS::Panorama::Package"
    AWS_Pinpoint_App = "AWS::Pinpoint::App"
    AWS_Redshift_ScheduledAction = "AWS::Redshift::ScheduledAction"
    AWS_Route53Resolver_FirewallRuleGroupAssociation = (
        "AWS::Route53Resolver::FirewallRuleGroupAssociation"
    )
    AWS_SageMaker_AppImageConfig = "AWS::SageMaker::AppImageConfig"
    AWS_SageMaker_Image = "AWS::SageMaker::Image"
    AWS_ECS_TaskSet = "AWS::ECS::TaskSet"
    AWS_Cassandra_Keyspace = "AWS::Cassandra::Keyspace"
    AWS_Signer_SigningProfile = "AWS::Signer::SigningProfile"
    AWS_Amplify_App = "AWS::Amplify::App"
    AWS_AppMesh_VirtualNode = "AWS::AppMesh::VirtualNode"
    AWS_AppMesh_VirtualService = "AWS::AppMesh::VirtualService"
    AWS_AppRunner_VpcConnector = "AWS::AppRunner::VpcConnector"
    AWS_AppStream_Application = "AWS::AppStream::Application"
    AWS_CodeArtifact_Repository = "AWS::CodeArtifact::Repository"
    AWS_EC2_PrefixList = "AWS::EC2::PrefixList"
    AWS_EC2_SpotFleet = "AWS::EC2::SpotFleet"
    AWS_Evidently_Project = "AWS::Evidently::Project"
    AWS_Forecast_Dataset = "AWS::Forecast::Dataset"
    AWS_IAM_SAMLProvider = "AWS::IAM::SAMLProvider"
    AWS_IAM_ServerCertificate = "AWS::IAM::ServerCertificate"
    AWS_Pinpoint_Campaign = "AWS::Pinpoint::Campaign"
    AWS_Pinpoint_InAppTemplate = "AWS::Pinpoint::InAppTemplate"
    AWS_SageMaker_Domain = "AWS::SageMaker::Domain"
    AWS_Transfer_Agreement = "AWS::Transfer::Agreement"
    AWS_Transfer_Connector = "AWS::Transfer::Connector"
    AWS_KinesisFirehose_DeliveryStream = "AWS::KinesisFirehose::DeliveryStream"
    AWS_Amplify_Branch = "AWS::Amplify::Branch"
    AWS_AppIntegrations_EventIntegration = "AWS::AppIntegrations::EventIntegration"
    AWS_AppMesh_Route = "AWS::AppMesh::Route"
    AWS_Athena_PreparedStatement = "AWS::Athena::PreparedStatement"
    AWS_EC2_IPAMScope = "AWS::EC2::IPAMScope"
    AWS_Evidently_Launch = "AWS::Evidently::Launch"
    AWS_Forecast_DatasetGroup = "AWS::Forecast::DatasetGroup"
    AWS_GreengrassV2_ComponentVersion = "AWS::GreengrassV2::ComponentVersion"
    AWS_GroundStation_MissionProfile = "AWS::GroundStation::MissionProfile"
    AWS_MediaConnect_FlowEntitlement = "AWS::MediaConnect::FlowEntitlement"
    AWS_MediaConnect_FlowVpcInterface = "AWS::MediaConnect::FlowVpcInterface"
    AWS_MediaTailor_PlaybackConfiguration = "AWS::MediaTailor::PlaybackConfiguration"
    AWS_MSK_Configuration = "AWS::MSK::Configuration"
    AWS_Personalize_Dataset = "AWS::Personalize::Dataset"
    AWS_Personalize_Schema = "AWS::Personalize::Schema"
    AWS_Personalize_Solution = "AWS::Personalize::Solution"
    AWS_Pinpoint_EmailTemplate = "AWS::Pinpoint::EmailTemplate"
    AWS_Pinpoint_EventStream = "AWS::Pinpoint::EventStream"
    AWS_ResilienceHub_App = "AWS::ResilienceHub::App"
    AWS_ACMPCA_CertificateAuthority = "AWS::ACMPCA::CertificateAuthority"
    AWS_AppConfig_HostedConfigurationVersion = "AWS::AppConfig::HostedConfigurationVersion"
    AWS_AppMesh_VirtualGateway = "AWS::AppMesh::VirtualGateway"
    AWS_AppMesh_VirtualRouter = "AWS::AppMesh::VirtualRouter"
    AWS_AppRunner_Service = "AWS::AppRunner::Service"
    AWS_CustomerProfiles_ObjectType = "AWS::CustomerProfiles::ObjectType"
    AWS_DMS_Endpoint = "AWS::DMS::Endpoint"
    AWS_EC2_CapacityReservation = "AWS::EC2::CapacityReservation"
    AWS_EC2_ClientVpnEndpoint = "AWS::EC2::ClientVpnEndpoint"
    AWS_Kendra_Index = "AWS::Kendra::Index"
    AWS_KinesisVideo_Stream = "AWS::KinesisVideo::Stream"
    AWS_Logs_Destination = "AWS::Logs::Destination"
    AWS_Pinpoint_EmailChannel = "AWS::Pinpoint::EmailChannel"
    AWS_S3_AccessPoint = "AWS::S3::AccessPoint"
    AWS_NetworkManager_CustomerGatewayAssociation = (
        "AWS::NetworkManager::CustomerGatewayAssociation"
    )
    AWS_NetworkManager_LinkAssociation = "AWS::NetworkManager::LinkAssociation"
    AWS_IoTWireless_MulticastGroup = "AWS::IoTWireless::MulticastGroup"
    AWS_Personalize_DatasetGroup = "AWS::Personalize::DatasetGroup"
    AWS_IoTTwinMaker_ComponentType = "AWS::IoTTwinMaker::ComponentType"
    AWS_CodeBuild_ReportGroup = "AWS::CodeBuild::ReportGroup"
    AWS_SageMaker_FeatureGroup = "AWS::SageMaker::FeatureGroup"
    AWS_MSK_BatchScramSecret = "AWS::MSK::BatchScramSecret"
    AWS_AppStream_Stack = "AWS::AppStream::Stack"
    AWS_IoT_JobTemplate = "AWS::IoT::JobTemplate"
    AWS_IoTWireless_FuotaTask = "AWS::IoTWireless::FuotaTask"
    AWS_IoT_ProvisioningTemplate = "AWS::IoT::ProvisioningTemplate"
    AWS_InspectorV2_Filter = "AWS::InspectorV2::Filter"
    AWS_Route53Resolver_ResolverQueryLoggingConfigAssociation = (
        "AWS::Route53Resolver::ResolverQueryLoggingConfigAssociation"
    )
    AWS_ServiceDiscovery_Instance = "AWS::ServiceDiscovery::Instance"
    AWS_Transfer_Certificate = "AWS::Transfer::Certificate"
    AWS_MediaConnect_FlowSource = "AWS::MediaConnect::FlowSource"
    AWS_APS_RuleGroupsNamespace = "AWS::APS::RuleGroupsNamespace"
    AWS_CodeGuruProfiler_ProfilingGroup = "AWS::CodeGuruProfiler::ProfilingGroup"
    AWS_Route53Resolver_ResolverQueryLoggingConfig = (
        "AWS::Route53Resolver::ResolverQueryLoggingConfig"
    )
    AWS_Batch_SchedulingPolicy = "AWS::Batch::SchedulingPolicy"
    AWS_ACMPCA_CertificateAuthorityActivation = "AWS::ACMPCA::CertificateAuthorityActivation"
    AWS_AppMesh_GatewayRoute = "AWS::AppMesh::GatewayRoute"
    AWS_AppMesh_Mesh = "AWS::AppMesh::Mesh"
    AWS_Connect_Instance = "AWS::Connect::Instance"
    AWS_Connect_QuickConnect = "AWS::Connect::QuickConnect"
    AWS_EC2_CarrierGateway = "AWS::EC2::CarrierGateway"
    AWS_EC2_IPAMPool = "AWS::EC2::IPAMPool"
    AWS_EC2_TransitGatewayConnect = "AWS::EC2::TransitGatewayConnect"
    AWS_EC2_TransitGatewayMulticastDomain = "AWS::EC2::TransitGatewayMulticastDomain"
    AWS_ECS_CapacityProvider = "AWS::ECS::CapacityProvider"
    AWS_IAM_InstanceProfile = "AWS::IAM::InstanceProfile"
    AWS_IoT_CACertificate = "AWS::IoT::CACertificate"
    AWS_IoTTwinMaker_SyncJob = "AWS::IoTTwinMaker::SyncJob"
    AWS_KafkaConnect_Connector = "AWS::KafkaConnect::Connector"
    AWS_Lambda_CodeSigningConfig = "AWS::Lambda::CodeSigningConfig"
    AWS_NetworkManager_ConnectPeer = "AWS::NetworkManager::ConnectPeer"
    AWS_ResourceExplorer2_Index = "AWS::ResourceExplorer2::Index"
    AWS_AppStream_Fleet = "AWS::AppStream::Fleet"
    AWS_Cognito_UserPool = "AWS::Cognito::UserPool"
    AWS_Cognito_UserPoolClient = "AWS::Cognito::UserPoolClient"
    AWS_Cognito_UserPoolGroup = "AWS::Cognito::UserPoolGroup"
    AWS_EC2_NetworkInsightsAccessScope = "AWS::EC2::NetworkInsightsAccessScope"
    AWS_EC2_NetworkInsightsAnalysis = "AWS::EC2::NetworkInsightsAnalysis"
    AWS_Grafana_Workspace = "AWS::Grafana::Workspace"
    AWS_GroundStation_DataflowEndpointGroup = "AWS::GroundStation::DataflowEndpointGroup"
    AWS_ImageBuilder_ImageRecipe = "AWS::ImageBuilder::ImageRecipe"
    AWS_KMS_Alias = "AWS::KMS::Alias"
    AWS_M2_Environment = "AWS::M2::Environment"
    AWS_QuickSight_DataSource = "AWS::QuickSight::DataSource"
    AWS_QuickSight_Template = "AWS::QuickSight::Template"
    AWS_QuickSight_Theme = "AWS::QuickSight::Theme"
    AWS_RDS_OptionGroup = "AWS::RDS::OptionGroup"
    AWS_Redshift_EndpointAccess = "AWS::Redshift::EndpointAccess"
    AWS_Route53Resolver_FirewallRuleGroup = "AWS::Route53Resolver::FirewallRuleGroup"
    AWS_SSM_Document = "AWS::SSM::Document"
    AWS_AppConfig_ExtensionAssociation = "AWS::AppConfig::ExtensionAssociation"
    AWS_AppIntegrations_Application = "AWS::AppIntegrations::Application"
    AWS_AppSync_ApiCache = "AWS::AppSync::ApiCache"
    AWS_Bedrock_Guardrail = "AWS::Bedrock::Guardrail"
    AWS_Bedrock_KnowledgeBase = "AWS::Bedrock::KnowledgeBase"
    AWS_Cognito_IdentityPool = "AWS::Cognito::IdentityPool"
    AWS_Connect_Rule = "AWS::Connect::Rule"
    AWS_Connect_User = "AWS::Connect::User"
    AWS_EC2_ClientVpnTargetNetworkAssociation = "AWS::EC2::ClientVpnTargetNetworkAssociation"
    AWS_EC2_EIPAssociation = "AWS::EC2::EIPAssociation"
    AWS_EC2_IPAMResourceDiscovery = "AWS::EC2::IPAMResourceDiscovery"
    AWS_EC2_IPAMResourceDiscoveryAssociation = "AWS::EC2::IPAMResourceDiscoveryAssociation"
    AWS_EC2_InstanceConnectEndpoint = "AWS::EC2::InstanceConnectEndpoint"
    AWS_EC2_SnapshotBlockPublicAccess = "AWS::EC2::SnapshotBlockPublicAccess"
    AWS_EC2_VPCBlockPublicAccessExclusion = "AWS::EC2::VPCBlockPublicAccessExclusion"
    AWS_EC2_VPCBlockPublicAccessOptions = "AWS::EC2::VPCBlockPublicAccessOptions"
    AWS_EC2_VPCEndpointConnectionNotification = "AWS::EC2::VPCEndpointConnectionNotification"
    AWS_EC2_VPNConnectionRoute = "AWS::EC2::VPNConnectionRoute"
    AWS_Evidently_Segment = "AWS::Evidently::Segment"
    AWS_IAM_OIDCProvider = "AWS::IAM::OIDCProvider"
    AWS_InspectorV2_Activation = "AWS::InspectorV2::Activation"
    AWS_MSK_ClusterPolicy = "AWS::MSK::ClusterPolicy"
    AWS_MSK_VpcConnection = "AWS::MSK::VpcConnection"
    AWS_MediaConnect_Gateway = "AWS::MediaConnect::Gateway"
    AWS_MemoryDB_SubnetGroup = "AWS::MemoryDB::SubnetGroup"
    AWS_OpenSearchServerless_Collection = "AWS::OpenSearchServerless::Collection"
    AWS_OpenSearchServerless_VpcEndpoint = "AWS::OpenSearchServerless::VpcEndpoint"
    AWS_Redshift_EndpointAuthorization = "AWS::Redshift::EndpointAuthorization"
    AWS_Route53Profiles_Profile = "AWS::Route53Profiles::Profile"
    AWS_S3_StorageLensGroup = "AWS::S3::StorageLensGroup"
    AWS_S3Express_BucketPolicy = "AWS::S3Express::BucketPolicy"
    AWS_S3Express_DirectoryBucket = "AWS::S3Express::DirectoryBucket"
    AWS_SageMaker_InferenceExperiment = "AWS::SageMaker::InferenceExperiment"
    AWS_SecurityHub_Standard = "AWS::SecurityHub::Standard"
    AWS_Transfer_Profile = "AWS::Transfer::Profile"
    AWS_CloudFormation_StackSet = "AWS::CloudFormation::StackSet"
    AWS_MediaPackageV2_Channel = "AWS::MediaPackageV2::Channel"
    AWS_S3_AccessGrantsLocation = "AWS::S3::AccessGrantsLocation"
    AWS_S3_AccessGrant = "AWS::S3::AccessGrant"
    AWS_S3_AccessGrantsInstance = "AWS::S3::AccessGrantsInstance"
    AWS_EMRServerless_Application = "AWS::EMRServerless::Application"
    AWS_Config_AggregationAuthorization = "AWS::Config::AggregationAuthorization"
    AWS_Bedrock_ApplicationInferenceProfile = "AWS::Bedrock::ApplicationInferenceProfile"
    AWS_ApiGatewayV2_Integration = "AWS::ApiGatewayV2::Integration"
    AWS_SageMaker_MlflowTrackingServer = "AWS::SageMaker::MlflowTrackingServer"
    AWS_SageMaker_ModelBiasJobDefinition = "AWS::SageMaker::ModelBiasJobDefinition"
    AWS_SecretsManager_RotationSchedule = "AWS::SecretsManager::RotationSchedule"
    AWS_Deadline_QueueFleetAssociation = "AWS::Deadline::QueueFleetAssociation"
    AWS_ECR_RepositoryCreationTemplate = "AWS::ECR::RepositoryCreationTemplate"
    AWS_CloudFormation_LambdaHook = "AWS::CloudFormation::LambdaHook"
    AWS_EC2_SubnetNetworkAclAssociation = "AWS::EC2::SubnetNetworkAclAssociation"
    AWS_ApiGateway_UsagePlan = "AWS::ApiGateway::UsagePlan"
    AWS_AppConfig_Extension = "AWS::AppConfig::Extension"
    AWS_Deadline_Fleet = "AWS::Deadline::Fleet"
    AWS_EMR_Studio = "AWS::EMR::Studio"
    AWS_S3Tables_TableBucket = "AWS::S3Tables::TableBucket"
    AWS_CloudFront_RealtimeLogConfig = "AWS::CloudFront::RealtimeLogConfig"
    AWS_BackupGateway_Hypervisor = "AWS::BackupGateway::Hypervisor"
    AWS_BCMDataExports_Export = "AWS::BCMDataExports::Export"
    AWS_CloudFormation_GuardHook = "AWS::CloudFormation::GuardHook"
    AWS_CloudFront_PublicKey = "AWS::CloudFront::PublicKey"
    AWS_CloudTrail_EventDataStore = "AWS::CloudTrail::EventDataStore"
    AWS_EntityResolution_IdMappingWorkflow = "AWS::EntityResolution::IdMappingWorkflow"
    AWS_EntityResolution_SchemaMapping = "AWS::EntityResolution::SchemaMapping"
    AWS_IoT_DomainConfiguration = "AWS::IoT::DomainConfiguration"
    AWS_PCAConnectorAD_DirectoryRegistration = "AWS::PCAConnectorAD::DirectoryRegistration"
    AWS_RDS_Integration = "AWS::RDS::Integration"
    AWS_Config_ConformancePack = "AWS::Config::ConformancePack"
    AWS_RolesAnywhere_Profile = "AWS::RolesAnywhere::Profile"
    AWS_CodeArtifact_Domain = "AWS::CodeArtifact::Domain"
    AWS_Backup_RestoreTestingPlan = "AWS::Backup::RestoreTestingPlan"
    AWS_Config_StoredQuery = "AWS::Config::StoredQuery"
    AWS_SageMaker_DataQualityJobDefinition = "AWS::SageMaker::DataQualityJobDefinition"
    AWS_SageMaker_ModelExplainabilityJobDefinition = (
        "AWS::SageMaker::ModelExplainabilityJobDefinition"
    )
    AWS_SageMaker_ModelQualityJobDefinition = "AWS::SageMaker::ModelQualityJobDefinition"
    AWS_SageMaker_StudioLifecycleConfig = "AWS::SageMaker::StudioLifecycleConfig"
    AWS_SES_DedicatedIpPool = "AWS::SES::DedicatedIpPool"
    AWS_SES_MailManagerTrafficPolicy = "AWS::SES::MailManagerTrafficPolicy"
    AWS_SSM_ResourceDataSync = "AWS::SSM::ResourceDataSync"
    AWS_BedrockAgentCore_Runtime = "AWS::BedrockAgentCore::Runtime"
    AWS_BedrockAgentCore_BrowserCustom = "AWS::BedrockAgentCore::BrowserCustom"
    AWS_ElasticLoadBalancingV2_TargetGroup = "AWS::ElasticLoadBalancingV2::TargetGroup"
    AWS_EMRContainers_VirtualCluster = "AWS::EMRContainers::VirtualCluster"
    AWS_EntityResolution_MatchingWorkflow = "AWS::EntityResolution::MatchingWorkflow"
    AWS_IoTCoreDeviceAdvisor_SuiteDefinition = "AWS::IoTCoreDeviceAdvisor::SuiteDefinition"
    AWS_EC2_SecurityGroupVpcAssociation = "AWS::EC2::SecurityGroupVpcAssociation"
    AWS_EC2_VerifiedAccessInstance = "AWS::EC2::VerifiedAccessInstance"
    AWS_KafkaConnect_CustomPlugin = "AWS::KafkaConnect::CustomPlugin"
    AWS_NetworkManager_TransitGatewayPeering = "AWS::NetworkManager::TransitGatewayPeering"
    AWS_OpenSearchServerless_SecurityConfig = "AWS::OpenSearchServerless::SecurityConfig"
    AWS_Redshift_Integration = "AWS::Redshift::Integration"
    AWS_RolesAnywhere_TrustAnchor = "AWS::RolesAnywhere::TrustAnchor"
    AWS_Route53Profiles_ProfileAssociation = "AWS::Route53Profiles::ProfileAssociation"
    AWS_SSMIncidents_ResponsePlan = "AWS::SSMIncidents::ResponsePlan"
    AWS_Transfer_Server = "AWS::Transfer::Server"
    AWS_Glue_Database = "AWS::Glue::Database"
    AWS_Organizations_OrganizationalUnit = "AWS::Organizations::OrganizationalUnit"
    AWS_EC2_IPAMPoolCidr = "AWS::EC2::IPAMPoolCidr"
    AWS_EC2_VPCGatewayAttachment = "AWS::EC2::VPCGatewayAttachment"
    AWS_Bedrock_Prompt = "AWS::Bedrock::Prompt"
    AWS_Comprehend_Flywheel = "AWS::Comprehend::Flywheel"
    AWS_DataSync_Agent = "AWS::DataSync::Agent"
    AWS_MediaTailor_LiveSource = "AWS::MediaTailor::LiveSource"
    AWS_MSK_ServerlessCluster = "AWS::MSK::ServerlessCluster"
    AWS_IoTSiteWise_Asset = "AWS::IoTSiteWise::Asset"
    AWS_B2BI_Capability = "AWS::B2BI::Capability"
    AWS_CloudFront_KeyValueStore = "AWS::CloudFront::KeyValueStore"
    AWS_Deadline_Monitor = "AWS::Deadline::Monitor"
    AWS_GuardDuty_MalwareProtectionPlan = "AWS::GuardDuty::MalwareProtectionPlan"
    AWS_Location_APIKey = "AWS::Location::APIKey"
    AWS_MediaPackageV2_OriginEndpoint = "AWS::MediaPackageV2::OriginEndpoint"
    AWS_PCAConnectorAD_Connector = "AWS::PCAConnectorAD::Connector"
    AWS_S3Tables_TableBucketPolicy = "AWS::S3Tables::TableBucketPolicy"
    AWS_SecretsManager_ResourcePolicy = "AWS::SecretsManager::ResourcePolicy"
    AWS_SSMContacts_Contact = "AWS::SSMContacts::Contact"
    AWS_IoT_ThingGroup = "AWS::IoT::ThingGroup"
    AWS_ImageBuilder_LifecyclePolicy = "AWS::ImageBuilder::LifecyclePolicy"
    AWS_GameLift_Build = "AWS::GameLift::Build"
    AWS_ECR_ReplicationConfiguration = "AWS::ECR::ReplicationConfiguration"
    AWS_EC2_SubnetCidrBlock = "AWS::EC2::SubnetCidrBlock"
    AWS_Connect_SecurityProfile = "AWS::Connect::SecurityProfile"
    AWS_CleanRoomsML_TrainingDataset = "AWS::CleanRoomsML::TrainingDataset"
    AWS_AppStream_AppBlockBuilder = "AWS::AppStream::AppBlockBuilder"
    AWS_Route53_DNSSEC = "AWS::Route53::DNSSEC"
    AWS_SageMaker_UserProfile = "AWS::SageMaker::UserProfile"
    AWS_ApiGateway_Method = "AWS::ApiGateway::Method"


class ResourceValueType(StrEnum):
    RESOURCE_ID = "RESOURCE_ID"


class SortBy(StrEnum):
    SCORE = "SCORE"


class SortOrder(StrEnum):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


class ConflictException(ServiceException):
    code: str = "ConflictException"
    sender_fault: bool = False
    status_code: int = 400


class ConformancePackTemplateValidationException(ServiceException):
    code: str = "ConformancePackTemplateValidationException"
    sender_fault: bool = False
    status_code: int = 400


class IdempotentParameterMismatch(ServiceException):
    code: str = "IdempotentParameterMismatch"
    sender_fault: bool = False
    status_code: int = 400


class InsufficientDeliveryPolicyException(ServiceException):
    code: str = "InsufficientDeliveryPolicyException"
    sender_fault: bool = False
    status_code: int = 400


class InsufficientPermissionsException(ServiceException):
    code: str = "InsufficientPermissionsException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidConfigurationRecorderNameException(ServiceException):
    code: str = "InvalidConfigurationRecorderNameException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidDeliveryChannelNameException(ServiceException):
    code: str = "InvalidDeliveryChannelNameException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidExpressionException(ServiceException):
    code: str = "InvalidExpressionException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidLimitException(ServiceException):
    code: str = "InvalidLimitException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidNextTokenException(ServiceException):
    code: str = "InvalidNextTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidParameterValueException(ServiceException):
    code: str = "InvalidParameterValueException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRecordingGroupException(ServiceException):
    code: str = "InvalidRecordingGroupException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidResultTokenException(ServiceException):
    code: str = "InvalidResultTokenException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidRoleException(ServiceException):
    code: str = "InvalidRoleException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidS3KeyPrefixException(ServiceException):
    code: str = "InvalidS3KeyPrefixException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidS3KmsKeyArnException(ServiceException):
    code: str = "InvalidS3KmsKeyArnException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidSNSTopicARNException(ServiceException):
    code: str = "InvalidSNSTopicARNException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidTimeRangeException(ServiceException):
    code: str = "InvalidTimeRangeException"
    sender_fault: bool = False
    status_code: int = 400


class LastDeliveryChannelDeleteFailedException(ServiceException):
    code: str = "LastDeliveryChannelDeleteFailedException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MaxActiveResourcesExceededException(ServiceException):
    code: str = "MaxActiveResourcesExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MaxNumberOfConfigRulesExceededException(ServiceException):
    code: str = "MaxNumberOfConfigRulesExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MaxNumberOfConfigurationRecordersExceededException(ServiceException):
    code: str = "MaxNumberOfConfigurationRecordersExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MaxNumberOfConformancePacksExceededException(ServiceException):
    code: str = "MaxNumberOfConformancePacksExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MaxNumberOfDeliveryChannelsExceededException(ServiceException):
    code: str = "MaxNumberOfDeliveryChannelsExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MaxNumberOfOrganizationConfigRulesExceededException(ServiceException):
    code: str = "MaxNumberOfOrganizationConfigRulesExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MaxNumberOfOrganizationConformancePacksExceededException(ServiceException):
    code: str = "MaxNumberOfOrganizationConformancePacksExceededException"
    sender_fault: bool = False
    status_code: int = 400


class MaxNumberOfRetentionConfigurationsExceededException(ServiceException):
    code: str = "MaxNumberOfRetentionConfigurationsExceededException"
    sender_fault: bool = False
    status_code: int = 400


class NoAvailableConfigurationRecorderException(ServiceException):
    code: str = "NoAvailableConfigurationRecorderException"
    sender_fault: bool = False
    status_code: int = 400


class NoAvailableDeliveryChannelException(ServiceException):
    code: str = "NoAvailableDeliveryChannelException"
    sender_fault: bool = False
    status_code: int = 400


class NoAvailableOrganizationException(ServiceException):
    code: str = "NoAvailableOrganizationException"
    sender_fault: bool = False
    status_code: int = 400


class NoRunningConfigurationRecorderException(ServiceException):
    code: str = "NoRunningConfigurationRecorderException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchBucketException(ServiceException):
    code: str = "NoSuchBucketException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchConfigRuleException(ServiceException):
    code: str = "NoSuchConfigRuleException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchConfigRuleInConformancePackException(ServiceException):
    code: str = "NoSuchConfigRuleInConformancePackException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchConfigurationAggregatorException(ServiceException):
    code: str = "NoSuchConfigurationAggregatorException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchConfigurationRecorderException(ServiceException):
    code: str = "NoSuchConfigurationRecorderException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchConformancePackException(ServiceException):
    code: str = "NoSuchConformancePackException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchDeliveryChannelException(ServiceException):
    code: str = "NoSuchDeliveryChannelException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchOrganizationConfigRuleException(ServiceException):
    code: str = "NoSuchOrganizationConfigRuleException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchOrganizationConformancePackException(ServiceException):
    code: str = "NoSuchOrganizationConformancePackException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchRemediationConfigurationException(ServiceException):
    code: str = "NoSuchRemediationConfigurationException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchRemediationExceptionException(ServiceException):
    code: str = "NoSuchRemediationExceptionException"
    sender_fault: bool = False
    status_code: int = 400


class NoSuchRetentionConfigurationException(ServiceException):
    code: str = "NoSuchRetentionConfigurationException"
    sender_fault: bool = False
    status_code: int = 400


class OrganizationAccessDeniedException(ServiceException):
    code: str = "OrganizationAccessDeniedException"
    sender_fault: bool = False
    status_code: int = 400


class OrganizationAllFeaturesNotEnabledException(ServiceException):
    code: str = "OrganizationAllFeaturesNotEnabledException"
    sender_fault: bool = False
    status_code: int = 400


class OrganizationConformancePackTemplateValidationException(ServiceException):
    code: str = "OrganizationConformancePackTemplateValidationException"
    sender_fault: bool = False
    status_code: int = 400


class OversizedConfigurationItemException(ServiceException):
    code: str = "OversizedConfigurationItemException"
    sender_fault: bool = False
    status_code: int = 400


class RemediationInProgressException(ServiceException):
    code: str = "RemediationInProgressException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceConcurrentModificationException(ServiceException):
    code: str = "ResourceConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotDiscoveredException(ServiceException):
    code: str = "ResourceNotDiscoveredException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class TooManyTagsException(ServiceException):
    code: str = "TooManyTagsException"
    sender_fault: bool = False
    status_code: int = 400


class UnmodifiableEntityException(ServiceException):
    code: str = "UnmodifiableEntityException"
    sender_fault: bool = False
    status_code: int = 400


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


AggregatorRegionList = list[String]
AccountAggregationSourceAccountList = list[AccountId]


class AccountAggregationSource(TypedDict, total=False):
    AccountIds: AccountAggregationSourceAccountList
    AllAwsRegions: Boolean | None
    AwsRegions: AggregatorRegionList | None


AccountAggregationSourceList = list[AccountAggregationSource]


class ComplianceContributorCount(TypedDict, total=False):
    CappedCount: Integer | None
    CapExceeded: Boolean | None


class Compliance(TypedDict, total=False):
    ComplianceType: ComplianceType | None
    ComplianceContributorCount: ComplianceContributorCount | None


class AggregateComplianceByConfigRule(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName | None
    Compliance: Compliance | None
    AccountId: AccountId | None
    AwsRegion: AwsRegion | None


AggregateComplianceByConfigRuleList = list[AggregateComplianceByConfigRule]


class AggregateConformancePackCompliance(TypedDict, total=False):
    ComplianceType: ConformancePackComplianceType | None
    CompliantRuleCount: Integer | None
    NonCompliantRuleCount: Integer | None
    TotalRuleCount: Integer | None


class AggregateComplianceByConformancePack(TypedDict, total=False):
    ConformancePackName: ConformancePackName | None
    Compliance: AggregateConformancePackCompliance | None
    AccountId: AccountId | None
    AwsRegion: AwsRegion | None


AggregateComplianceByConformancePackList = list[AggregateComplianceByConformancePack]
Date = datetime


class ComplianceSummary(TypedDict, total=False):
    CompliantResourceCount: ComplianceContributorCount | None
    NonCompliantResourceCount: ComplianceContributorCount | None
    ComplianceSummaryTimestamp: Date | None


class AggregateComplianceCount(TypedDict, total=False):
    GroupName: StringWithCharLimit256 | None
    ComplianceSummary: ComplianceSummary | None


AggregateComplianceCountList = list[AggregateComplianceCount]


class AggregateConformancePackComplianceCount(TypedDict, total=False):
    CompliantConformancePackCount: Integer | None
    NonCompliantConformancePackCount: Integer | None


class AggregateConformancePackComplianceFilters(TypedDict, total=False):
    ConformancePackName: ConformancePackName | None
    ComplianceType: ConformancePackComplianceType | None
    AccountId: AccountId | None
    AwsRegion: AwsRegion | None


class AggregateConformancePackComplianceSummary(TypedDict, total=False):
    ComplianceSummary: AggregateConformancePackComplianceCount | None
    GroupName: StringWithCharLimit256 | None


class AggregateConformancePackComplianceSummaryFilters(TypedDict, total=False):
    AccountId: AccountId | None
    AwsRegion: AwsRegion | None


AggregateConformancePackComplianceSummaryList = list[AggregateConformancePackComplianceSummary]


class EvaluationResultQualifier(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName | None
    ResourceType: StringWithCharLimit256 | None
    ResourceId: BaseResourceId | None
    EvaluationMode: EvaluationMode | None


class EvaluationResultIdentifier(TypedDict, total=False):
    EvaluationResultQualifier: EvaluationResultQualifier | None
    OrderingTimestamp: Date | None
    ResourceEvaluationId: ResourceEvaluationId | None


class AggregateEvaluationResult(TypedDict, total=False):
    EvaluationResultIdentifier: EvaluationResultIdentifier | None
    ComplianceType: ComplianceType | None
    ResultRecordedTime: Date | None
    ConfigRuleInvokedTime: Date | None
    Annotation: StringWithCharLimit256 | None
    AccountId: AccountId | None
    AwsRegion: AwsRegion | None


AggregateEvaluationResultList = list[AggregateEvaluationResult]


class AggregateResourceIdentifier(TypedDict, total=False):
    SourceAccountId: AccountId
    SourceRegion: AwsRegion
    ResourceId: ResourceId
    ResourceType: ResourceType
    ResourceName: ResourceName | None


class AggregatedSourceStatus(TypedDict, total=False):
    SourceId: String | None
    SourceType: AggregatedSourceType | None
    AwsRegion: AwsRegion | None
    LastUpdateStatus: AggregatedSourceStatusType | None
    LastUpdateTime: Date | None
    LastErrorCode: String | None
    LastErrorMessage: String | None


AggregatedSourceStatusList = list[AggregatedSourceStatus]
AggregatedSourceStatusTypeList = list[AggregatedSourceStatusType]


class AggregationAuthorization(TypedDict, total=False):
    AggregationAuthorizationArn: String | None
    AuthorizedAccountId: AccountId | None
    AuthorizedAwsRegion: AwsRegion | None
    CreationTime: Date | None


AggregationAuthorizationList = list[AggregationAuthorization]
ResourceTypeValueList = list[ResourceTypeValue]


class AggregatorFilterResourceType(TypedDict, total=False):
    Type: AggregatorFilterType | None
    Value: ResourceTypeValueList | None


ServicePrincipalValueList = list[ServicePrincipalValue]


class AggregatorFilterServicePrincipal(TypedDict, total=False):
    Type: AggregatorFilterType | None
    Value: ServicePrincipalValueList | None


class AggregatorFilters(TypedDict, total=False):
    ResourceType: AggregatorFilterResourceType | None
    ServicePrincipal: AggregatorFilterServicePrincipal | None


ResourceTypeList = list[ResourceType]


class AssociateResourceTypesRequest(ServiceRequest):
    ConfigurationRecorderArn: AmazonResourceName
    ResourceTypes: ResourceTypeList


RecordingModeResourceTypesList = list[ResourceType]


class RecordingModeOverride(TypedDict, total=False):
    description: Description | None
    resourceTypes: RecordingModeResourceTypesList
    recordingFrequency: RecordingFrequency


RecordingModeOverrides = list[RecordingModeOverride]


class RecordingMode(TypedDict, total=False):
    recordingFrequency: RecordingFrequency
    recordingModeOverrides: RecordingModeOverrides | None


class RecordingStrategy(TypedDict, total=False):
    useOnly: RecordingStrategyType | None


class ExclusionByResourceTypes(TypedDict, total=False):
    resourceTypes: ResourceTypeList | None


class RecordingGroup(TypedDict, total=False):
    allSupported: AllSupported | None
    includeGlobalResourceTypes: IncludeGlobalResourceTypes | None
    resourceTypes: ResourceTypeList | None
    exclusionByResourceTypes: ExclusionByResourceTypes | None
    recordingStrategy: RecordingStrategy | None


class ConfigurationRecorder(TypedDict, total=False):
    arn: AmazonResourceName | None
    name: RecorderName | None
    roleARN: String | None
    recordingGroup: RecordingGroup | None
    recordingMode: RecordingMode | None
    recordingScope: RecordingScope | None
    servicePrincipal: ServicePrincipal | None


class AssociateResourceTypesResponse(TypedDict, total=False):
    ConfigurationRecorder: ConfigurationRecorder


AutoRemediationAttemptSeconds = int
ConfigurationItemDeliveryTime = datetime
SupplementaryConfiguration = dict[SupplementaryConfigurationName, SupplementaryConfigurationValue]
ResourceCreationTime = datetime
ConfigurationItemCaptureTime = datetime


class BaseConfigurationItem(TypedDict, total=False):
    version: Version | None
    accountId: AccountId | None
    configurationItemCaptureTime: ConfigurationItemCaptureTime | None
    configurationItemStatus: ConfigurationItemStatus | None
    configurationStateId: ConfigurationStateId | None
    arn: ARN | None
    resourceType: ResourceType | None
    resourceId: ResourceId | None
    resourceName: ResourceName | None
    awsRegion: AwsRegion | None
    availabilityZone: AvailabilityZone | None
    resourceCreationTime: ResourceCreationTime | None
    configuration: Configuration | None
    supplementaryConfiguration: SupplementaryConfiguration | None
    recordingFrequency: RecordingFrequency | None
    configurationItemDeliveryTime: ConfigurationItemDeliveryTime | None


BaseConfigurationItems = list[BaseConfigurationItem]
ResourceIdentifiersList = list[AggregateResourceIdentifier]


class BatchGetAggregateResourceConfigRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    ResourceIdentifiers: ResourceIdentifiersList


UnprocessedResourceIdentifierList = list[AggregateResourceIdentifier]


class BatchGetAggregateResourceConfigResponse(TypedDict, total=False):
    BaseConfigurationItems: BaseConfigurationItems | None
    UnprocessedResourceIdentifiers: UnprocessedResourceIdentifierList | None


class ResourceKey(TypedDict, total=False):
    resourceType: ResourceType
    resourceId: ResourceId


ResourceKeys = list[ResourceKey]


class BatchGetResourceConfigRequest(ServiceRequest):
    resourceKeys: ResourceKeys


class BatchGetResourceConfigResponse(TypedDict, total=False):
    baseConfigurationItems: BaseConfigurationItems | None
    unprocessedResourceKeys: ResourceKeys | None


class ComplianceByConfigRule(TypedDict, total=False):
    ConfigRuleName: StringWithCharLimit64 | None
    Compliance: Compliance | None


ComplianceByConfigRules = list[ComplianceByConfigRule]


class ComplianceByResource(TypedDict, total=False):
    ResourceType: StringWithCharLimit256 | None
    ResourceId: BaseResourceId | None
    Compliance: Compliance | None


ComplianceByResources = list[ComplianceByResource]
ComplianceResourceTypes = list[StringWithCharLimit256]


class ComplianceSummaryByResourceType(TypedDict, total=False):
    ResourceType: StringWithCharLimit256 | None
    ComplianceSummary: ComplianceSummary | None


ComplianceSummariesByResourceType = list[ComplianceSummaryByResourceType]
ComplianceTypes = list[ComplianceType]


class ConfigExportDeliveryInfo(TypedDict, total=False):
    lastStatus: DeliveryStatus | None
    lastErrorCode: String | None
    lastErrorMessage: String | None
    lastAttemptTime: Date | None
    lastSuccessfulTime: Date | None
    nextDeliveryTime: Date | None


class EvaluationModeConfiguration(TypedDict, total=False):
    Mode: EvaluationMode | None


EvaluationModes = list[EvaluationModeConfiguration]


class CustomPolicyDetails(TypedDict, total=False):
    PolicyRuntime: PolicyRuntime
    PolicyText: PolicyText
    EnableDebugLogDelivery: Boolean | None


class SourceDetail(TypedDict, total=False):
    EventSource: EventSource | None
    MessageType: MessageType | None
    MaximumExecutionFrequency: MaximumExecutionFrequency | None


SourceDetails = list[SourceDetail]


class Source(TypedDict, total=False):
    Owner: Owner
    SourceIdentifier: StringWithCharLimit256 | None
    SourceDetails: SourceDetails | None
    CustomPolicyDetails: CustomPolicyDetails | None


class Scope(TypedDict, total=False):
    ComplianceResourceTypes: ComplianceResourceTypes | None
    TagKey: StringWithCharLimit128 | None
    TagValue: StringWithCharLimit256 | None
    ComplianceResourceId: BaseResourceId | None


class ConfigRule(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName | None
    ConfigRuleArn: StringWithCharLimit256 | None
    ConfigRuleId: StringWithCharLimit64 | None
    Description: EmptiableStringWithCharLimit256 | None
    Scope: Scope | None
    Source: Source
    InputParameters: StringWithCharLimit1024 | None
    MaximumExecutionFrequency: MaximumExecutionFrequency | None
    ConfigRuleState: ConfigRuleState | None
    CreatedBy: StringWithCharLimit256 | None
    EvaluationModes: EvaluationModes | None


class ConfigRuleComplianceFilters(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName | None
    ComplianceType: ComplianceType | None
    AccountId: AccountId | None
    AwsRegion: AwsRegion | None


class ConfigRuleComplianceSummaryFilters(TypedDict, total=False):
    AccountId: AccountId | None
    AwsRegion: AwsRegion | None


class ConfigRuleEvaluationStatus(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName | None
    ConfigRuleArn: String | None
    ConfigRuleId: String | None
    LastSuccessfulInvocationTime: Date | None
    LastFailedInvocationTime: Date | None
    LastSuccessfulEvaluationTime: Date | None
    LastFailedEvaluationTime: Date | None
    FirstActivatedTime: Date | None
    LastDeactivatedTime: Date | None
    LastErrorCode: String | None
    LastErrorMessage: String | None
    FirstEvaluationStarted: Boolean | None
    LastDebugLogDeliveryStatus: String | None
    LastDebugLogDeliveryStatusReason: String | None
    LastDebugLogDeliveryTime: Date | None


ConfigRuleEvaluationStatusList = list[ConfigRuleEvaluationStatus]
ConfigRuleNames = list[ConfigRuleName]
ConfigRules = list[ConfigRule]


class ConfigSnapshotDeliveryProperties(TypedDict, total=False):
    deliveryFrequency: MaximumExecutionFrequency | None


class ConfigStreamDeliveryInfo(TypedDict, total=False):
    lastStatus: DeliveryStatus | None
    lastErrorCode: String | None
    lastErrorMessage: String | None
    lastStatusChangeTime: Date | None


class OrganizationAggregationSource(TypedDict, total=False):
    RoleArn: String
    AwsRegions: AggregatorRegionList | None
    AllAwsRegions: Boolean | None


class ConfigurationAggregator(TypedDict, total=False):
    ConfigurationAggregatorName: ConfigurationAggregatorName | None
    ConfigurationAggregatorArn: ConfigurationAggregatorArn | None
    AccountAggregationSources: AccountAggregationSourceList | None
    OrganizationAggregationSource: OrganizationAggregationSource | None
    CreationTime: Date | None
    LastUpdatedTime: Date | None
    CreatedBy: StringWithCharLimit256 | None
    AggregatorFilters: AggregatorFilters | None


ConfigurationAggregatorList = list[ConfigurationAggregator]
ConfigurationAggregatorNameList = list[ConfigurationAggregatorName]


class Relationship(TypedDict, total=False):
    resourceType: ResourceType | None
    resourceId: ResourceId | None
    resourceName: ResourceName | None
    relationshipName: RelationshipName | None


RelationshipList = list[Relationship]
RelatedEventList = list[RelatedEvent]
Tags = dict[Name, Value]


class ConfigurationItem(TypedDict, total=False):
    version: Version | None
    accountId: AccountId | None
    configurationItemCaptureTime: ConfigurationItemCaptureTime | None
    configurationItemStatus: ConfigurationItemStatus | None
    configurationStateId: ConfigurationStateId | None
    configurationItemMD5Hash: ConfigurationItemMD5Hash | None
    arn: ARN | None
    resourceType: ResourceType | None
    resourceId: ResourceId | None
    resourceName: ResourceName | None
    awsRegion: AwsRegion | None
    availabilityZone: AvailabilityZone | None
    resourceCreationTime: ResourceCreationTime | None
    tags: Tags | None
    relatedEvents: RelatedEventList | None
    relationships: RelationshipList | None
    configuration: Configuration | None
    supplementaryConfiguration: SupplementaryConfiguration | None
    recordingFrequency: RecordingFrequency | None
    configurationItemDeliveryTime: ConfigurationItemDeliveryTime | None


ConfigurationItemList = list[ConfigurationItem]
ConfigurationRecorderFilterValues = list[ConfigurationRecorderFilterValue]


class ConfigurationRecorderFilter(TypedDict, total=False):
    filterName: ConfigurationRecorderFilterName | None
    filterValue: ConfigurationRecorderFilterValues | None


ConfigurationRecorderFilterList = list[ConfigurationRecorderFilter]
ConfigurationRecorderList = list[ConfigurationRecorder]
ConfigurationRecorderNameList = list[RecorderName]


class ConfigurationRecorderStatus(TypedDict, total=False):
    arn: AmazonResourceName | None
    name: String | None
    lastStartTime: Date | None
    lastStopTime: Date | None
    recording: Boolean | None
    lastStatus: RecorderStatus | None
    lastErrorCode: String | None
    lastErrorMessage: String | None
    lastStatusChangeTime: Date | None
    servicePrincipal: ServicePrincipal | None


ConfigurationRecorderStatusList = list[ConfigurationRecorderStatus]


class ConfigurationRecorderSummary(TypedDict, total=False):
    arn: AmazonResourceName
    name: RecorderName
    servicePrincipal: ServicePrincipal | None
    recordingScope: RecordingScope


ConfigurationRecorderSummaries = list[ConfigurationRecorderSummary]
ConformancePackConfigRuleNames = list[StringWithCharLimit64]


class ConformancePackComplianceFilters(TypedDict, total=False):
    ConfigRuleNames: ConformancePackConfigRuleNames | None
    ComplianceType: ConformancePackComplianceType | None


ConformancePackComplianceResourceIds = list[StringWithCharLimit256]
LastUpdatedTime = datetime


class ConformancePackComplianceScore(TypedDict, total=False):
    Score: ComplianceScore | None
    ConformancePackName: ConformancePackName | None
    LastUpdatedTime: LastUpdatedTime | None


ConformancePackComplianceScores = list[ConformancePackComplianceScore]
ConformancePackNameFilter = list[ConformancePackName]


class ConformancePackComplianceScoresFilters(TypedDict, total=False):
    ConformancePackNames: ConformancePackNameFilter


class ConformancePackComplianceSummary(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackComplianceStatus: ConformancePackComplianceType


ConformancePackComplianceSummaryList = list[ConformancePackComplianceSummary]


class TemplateSSMDocumentDetails(TypedDict, total=False):
    DocumentName: SSMDocumentName
    DocumentVersion: SSMDocumentVersion | None


class ConformancePackInputParameter(TypedDict, total=False):
    ParameterName: ParameterName
    ParameterValue: ParameterValue


ConformancePackInputParameters = list[ConformancePackInputParameter]


class ConformancePackDetail(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackArn: ConformancePackArn
    ConformancePackId: ConformancePackId
    DeliveryS3Bucket: DeliveryS3Bucket | None
    DeliveryS3KeyPrefix: DeliveryS3KeyPrefix | None
    ConformancePackInputParameters: ConformancePackInputParameters | None
    LastUpdateRequestedTime: Date | None
    CreatedBy: StringWithCharLimit256 | None
    TemplateSSMDocumentDetails: TemplateSSMDocumentDetails | None


ConformancePackDetailList = list[ConformancePackDetail]


class ConformancePackEvaluationFilters(TypedDict, total=False):
    ConfigRuleNames: ConformancePackConfigRuleNames | None
    ComplianceType: ConformancePackComplianceType | None
    ResourceType: StringWithCharLimit256 | None
    ResourceIds: ConformancePackComplianceResourceIds | None


class ConformancePackEvaluationResult(TypedDict, total=False):
    ComplianceType: ConformancePackComplianceType
    EvaluationResultIdentifier: EvaluationResultIdentifier
    ConfigRuleInvokedTime: Date
    ResultRecordedTime: Date
    Annotation: Annotation | None


ConformancePackNamesList = list[ConformancePackName]
ConformancePackNamesToSummarizeList = list[ConformancePackName]
ControlsList = list[StringWithCharLimit128]


class ConformancePackRuleCompliance(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName | None
    ComplianceType: ConformancePackComplianceType | None
    Controls: ControlsList | None


ConformancePackRuleComplianceList = list[ConformancePackRuleCompliance]
ConformancePackRuleEvaluationResultsList = list[ConformancePackEvaluationResult]


class ConformancePackStatusDetail(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackId: ConformancePackId
    ConformancePackArn: ConformancePackArn
    ConformancePackState: ConformancePackState
    StackArn: StackArn
    ConformancePackStatusReason: ConformancePackStatusReason | None
    LastUpdateRequestedTime: Date
    LastUpdateCompletedTime: Date | None


ConformancePackStatusDetailsList = list[ConformancePackStatusDetail]
DebugLogDeliveryAccounts = list[AccountId]


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
    ResourceType: String | None


class DeleteRemediationConfigurationResponse(TypedDict, total=False):
    pass


class RemediationExceptionResourceKey(TypedDict, total=False):
    ResourceType: StringWithCharLimit256 | None
    ResourceId: StringWithCharLimit1024 | None


RemediationExceptionResourceKeys = list[RemediationExceptionResourceKey]


class DeleteRemediationExceptionsRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: RemediationExceptionResourceKeys


class FailedDeleteRemediationExceptionsBatch(TypedDict, total=False):
    FailureMessage: String | None
    FailedItems: RemediationExceptionResourceKeys | None


FailedDeleteRemediationExceptionsBatches = list[FailedDeleteRemediationExceptionsBatch]


class DeleteRemediationExceptionsResponse(TypedDict, total=False):
    FailedBatches: FailedDeleteRemediationExceptionsBatches | None


class DeleteResourceConfigRequest(ServiceRequest):
    ResourceType: ResourceTypeString
    ResourceId: ResourceId


class DeleteRetentionConfigurationRequest(ServiceRequest):
    RetentionConfigurationName: RetentionConfigurationName


class DeleteServiceLinkedConfigurationRecorderRequest(ServiceRequest):
    ServicePrincipal: ServicePrincipal


class DeleteServiceLinkedConfigurationRecorderResponse(TypedDict, total=False):
    Arn: AmazonResourceName
    Name: RecorderName


class DeleteStoredQueryRequest(ServiceRequest):
    QueryName: QueryName


class DeleteStoredQueryResponse(TypedDict, total=False):
    pass


class DeliverConfigSnapshotRequest(ServiceRequest):
    deliveryChannelName: ChannelName


class DeliverConfigSnapshotResponse(TypedDict, total=False):
    configSnapshotId: String | None


class DeliveryChannel(TypedDict, total=False):
    name: ChannelName | None
    s3BucketName: String | None
    s3KeyPrefix: String | None
    s3KmsKeyArn: String | None
    snsTopicARN: String | None
    configSnapshotDeliveryProperties: ConfigSnapshotDeliveryProperties | None


DeliveryChannelList = list[DeliveryChannel]
DeliveryChannelNameList = list[ChannelName]


class DeliveryChannelStatus(TypedDict, total=False):
    name: String | None
    configSnapshotDeliveryInfo: ConfigExportDeliveryInfo | None
    configHistoryDeliveryInfo: ConfigExportDeliveryInfo | None
    configStreamDeliveryInfo: ConfigStreamDeliveryInfo | None


DeliveryChannelStatusList = list[DeliveryChannelStatus]


class DescribeAggregateComplianceByConfigRulesRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: ConfigRuleComplianceFilters | None
    Limit: GroupByAPILimit | None
    NextToken: NextToken | None


class DescribeAggregateComplianceByConfigRulesResponse(TypedDict, total=False):
    AggregateComplianceByConfigRules: AggregateComplianceByConfigRuleList | None
    NextToken: NextToken | None


class DescribeAggregateComplianceByConformancePacksRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: AggregateConformancePackComplianceFilters | None
    Limit: Limit | None
    NextToken: NextToken | None


class DescribeAggregateComplianceByConformancePacksResponse(TypedDict, total=False):
    AggregateComplianceByConformancePacks: AggregateComplianceByConformancePackList | None
    NextToken: NextToken | None


class DescribeAggregationAuthorizationsRequest(ServiceRequest):
    Limit: Limit | None
    NextToken: String | None


class DescribeAggregationAuthorizationsResponse(TypedDict, total=False):
    AggregationAuthorizations: AggregationAuthorizationList | None
    NextToken: String | None


class DescribeComplianceByConfigRuleRequest(ServiceRequest):
    ConfigRuleNames: ConfigRuleNames | None
    ComplianceTypes: ComplianceTypes | None
    NextToken: String | None


class DescribeComplianceByConfigRuleResponse(TypedDict, total=False):
    ComplianceByConfigRules: ComplianceByConfigRules | None
    NextToken: String | None


class DescribeComplianceByResourceRequest(ServiceRequest):
    ResourceType: StringWithCharLimit256 | None
    ResourceId: BaseResourceId | None
    ComplianceTypes: ComplianceTypes | None
    Limit: Limit | None
    NextToken: NextToken | None


class DescribeComplianceByResourceResponse(TypedDict, total=False):
    ComplianceByResources: ComplianceByResources | None
    NextToken: NextToken | None


class DescribeConfigRuleEvaluationStatusRequest(ServiceRequest):
    ConfigRuleNames: ConfigRuleNames | None
    NextToken: String | None
    Limit: RuleLimit | None


class DescribeConfigRuleEvaluationStatusResponse(TypedDict, total=False):
    ConfigRulesEvaluationStatus: ConfigRuleEvaluationStatusList | None
    NextToken: String | None


class DescribeConfigRulesFilters(TypedDict, total=False):
    EvaluationMode: EvaluationMode | None


class DescribeConfigRulesRequest(ServiceRequest):
    ConfigRuleNames: ConfigRuleNames | None
    NextToken: String | None
    Filters: DescribeConfigRulesFilters | None


class DescribeConfigRulesResponse(TypedDict, total=False):
    ConfigRules: ConfigRules | None
    NextToken: String | None


class DescribeConfigurationAggregatorSourcesStatusRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    UpdateStatus: AggregatedSourceStatusTypeList | None
    NextToken: String | None
    Limit: Limit | None


class DescribeConfigurationAggregatorSourcesStatusResponse(TypedDict, total=False):
    AggregatedSourceStatusList: AggregatedSourceStatusList | None
    NextToken: String | None


class DescribeConfigurationAggregatorsRequest(ServiceRequest):
    ConfigurationAggregatorNames: ConfigurationAggregatorNameList | None
    NextToken: String | None
    Limit: Limit | None


class DescribeConfigurationAggregatorsResponse(TypedDict, total=False):
    ConfigurationAggregators: ConfigurationAggregatorList | None
    NextToken: String | None


class DescribeConfigurationRecorderStatusRequest(ServiceRequest):
    ConfigurationRecorderNames: ConfigurationRecorderNameList | None
    ServicePrincipal: ServicePrincipal | None
    Arn: AmazonResourceName | None


class DescribeConfigurationRecorderStatusResponse(TypedDict, total=False):
    ConfigurationRecordersStatus: ConfigurationRecorderStatusList | None


class DescribeConfigurationRecordersRequest(ServiceRequest):
    ConfigurationRecorderNames: ConfigurationRecorderNameList | None
    ServicePrincipal: ServicePrincipal | None
    Arn: AmazonResourceName | None


class DescribeConfigurationRecordersResponse(TypedDict, total=False):
    ConfigurationRecorders: ConfigurationRecorderList | None


class DescribeConformancePackComplianceRequest(ServiceRequest):
    ConformancePackName: ConformancePackName
    Filters: ConformancePackComplianceFilters | None
    Limit: DescribeConformancePackComplianceLimit | None
    NextToken: NextToken | None


class DescribeConformancePackComplianceResponse(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackRuleComplianceList: ConformancePackRuleComplianceList
    NextToken: NextToken | None


class DescribeConformancePackStatusRequest(ServiceRequest):
    ConformancePackNames: ConformancePackNamesList | None
    Limit: PageSizeLimit | None
    NextToken: NextToken | None


class DescribeConformancePackStatusResponse(TypedDict, total=False):
    ConformancePackStatusDetails: ConformancePackStatusDetailsList | None
    NextToken: NextToken | None


class DescribeConformancePacksRequest(ServiceRequest):
    ConformancePackNames: ConformancePackNamesList | None
    Limit: PageSizeLimit | None
    NextToken: NextToken | None


class DescribeConformancePacksResponse(TypedDict, total=False):
    ConformancePackDetails: ConformancePackDetailList | None
    NextToken: NextToken | None


class DescribeDeliveryChannelStatusRequest(ServiceRequest):
    DeliveryChannelNames: DeliveryChannelNameList | None


class DescribeDeliveryChannelStatusResponse(TypedDict, total=False):
    DeliveryChannelsStatus: DeliveryChannelStatusList | None


class DescribeDeliveryChannelsRequest(ServiceRequest):
    DeliveryChannelNames: DeliveryChannelNameList | None


class DescribeDeliveryChannelsResponse(TypedDict, total=False):
    DeliveryChannels: DeliveryChannelList | None


OrganizationConfigRuleNames = list[StringWithCharLimit64]


class DescribeOrganizationConfigRuleStatusesRequest(ServiceRequest):
    OrganizationConfigRuleNames: OrganizationConfigRuleNames | None
    Limit: CosmosPageLimit | None
    NextToken: String | None


class OrganizationConfigRuleStatus(TypedDict, total=False):
    OrganizationConfigRuleName: OrganizationConfigRuleName
    OrganizationRuleStatus: OrganizationRuleStatus
    ErrorCode: String | None
    ErrorMessage: String | None
    LastUpdateTime: Date | None


OrganizationConfigRuleStatuses = list[OrganizationConfigRuleStatus]


class DescribeOrganizationConfigRuleStatusesResponse(TypedDict, total=False):
    OrganizationConfigRuleStatuses: OrganizationConfigRuleStatuses | None
    NextToken: String | None


class DescribeOrganizationConfigRulesRequest(ServiceRequest):
    OrganizationConfigRuleNames: OrganizationConfigRuleNames | None
    Limit: CosmosPageLimit | None
    NextToken: String | None


ResourceTypesScope = list[StringWithCharLimit256]
OrganizationConfigRuleTriggerTypeNoSNs = list[OrganizationConfigRuleTriggerTypeNoSN]


class OrganizationCustomPolicyRuleMetadataNoPolicy(TypedDict, total=False):
    Description: StringWithCharLimit256Min0 | None
    OrganizationConfigRuleTriggerTypes: OrganizationConfigRuleTriggerTypeNoSNs | None
    InputParameters: StringWithCharLimit2048 | None
    MaximumExecutionFrequency: MaximumExecutionFrequency | None
    ResourceTypesScope: ResourceTypesScope | None
    ResourceIdScope: StringWithCharLimit768 | None
    TagKeyScope: StringWithCharLimit128 | None
    TagValueScope: StringWithCharLimit256 | None
    PolicyRuntime: PolicyRuntime | None
    DebugLogDeliveryAccounts: DebugLogDeliveryAccounts | None


ExcludedAccounts = list[AccountId]
OrganizationConfigRuleTriggerTypes = list[OrganizationConfigRuleTriggerType]


class OrganizationCustomRuleMetadata(TypedDict, total=False):
    Description: StringWithCharLimit256Min0 | None
    LambdaFunctionArn: StringWithCharLimit256
    OrganizationConfigRuleTriggerTypes: OrganizationConfigRuleTriggerTypes
    InputParameters: StringWithCharLimit2048 | None
    MaximumExecutionFrequency: MaximumExecutionFrequency | None
    ResourceTypesScope: ResourceTypesScope | None
    ResourceIdScope: StringWithCharLimit768 | None
    TagKeyScope: StringWithCharLimit128 | None
    TagValueScope: StringWithCharLimit256 | None


class OrganizationManagedRuleMetadata(TypedDict, total=False):
    Description: StringWithCharLimit256Min0 | None
    RuleIdentifier: StringWithCharLimit256
    InputParameters: StringWithCharLimit2048 | None
    MaximumExecutionFrequency: MaximumExecutionFrequency | None
    ResourceTypesScope: ResourceTypesScope | None
    ResourceIdScope: StringWithCharLimit768 | None
    TagKeyScope: StringWithCharLimit128 | None
    TagValueScope: StringWithCharLimit256 | None


class OrganizationConfigRule(TypedDict, total=False):
    OrganizationConfigRuleName: OrganizationConfigRuleName
    OrganizationConfigRuleArn: StringWithCharLimit256
    OrganizationManagedRuleMetadata: OrganizationManagedRuleMetadata | None
    OrganizationCustomRuleMetadata: OrganizationCustomRuleMetadata | None
    ExcludedAccounts: ExcludedAccounts | None
    LastUpdateTime: Date | None
    OrganizationCustomPolicyRuleMetadata: OrganizationCustomPolicyRuleMetadataNoPolicy | None


OrganizationConfigRules = list[OrganizationConfigRule]


class DescribeOrganizationConfigRulesResponse(TypedDict, total=False):
    OrganizationConfigRules: OrganizationConfigRules | None
    NextToken: String | None


OrganizationConformancePackNames = list[OrganizationConformancePackName]


class DescribeOrganizationConformancePackStatusesRequest(ServiceRequest):
    OrganizationConformancePackNames: OrganizationConformancePackNames | None
    Limit: CosmosPageLimit | None
    NextToken: String | None


class OrganizationConformancePackStatus(TypedDict, total=False):
    OrganizationConformancePackName: OrganizationConformancePackName
    Status: OrganizationResourceStatus
    ErrorCode: String | None
    ErrorMessage: String | None
    LastUpdateTime: Date | None


OrganizationConformancePackStatuses = list[OrganizationConformancePackStatus]


class DescribeOrganizationConformancePackStatusesResponse(TypedDict, total=False):
    OrganizationConformancePackStatuses: OrganizationConformancePackStatuses | None
    NextToken: String | None


class DescribeOrganizationConformancePacksRequest(ServiceRequest):
    OrganizationConformancePackNames: OrganizationConformancePackNames | None
    Limit: CosmosPageLimit | None
    NextToken: String | None


class OrganizationConformancePack(TypedDict, total=False):
    OrganizationConformancePackName: OrganizationConformancePackName
    OrganizationConformancePackArn: StringWithCharLimit256
    DeliveryS3Bucket: DeliveryS3Bucket | None
    DeliveryS3KeyPrefix: DeliveryS3KeyPrefix | None
    ConformancePackInputParameters: ConformancePackInputParameters | None
    ExcludedAccounts: ExcludedAccounts | None
    LastUpdateTime: Date


OrganizationConformancePacks = list[OrganizationConformancePack]


class DescribeOrganizationConformancePacksResponse(TypedDict, total=False):
    OrganizationConformancePacks: OrganizationConformancePacks | None
    NextToken: String | None


class DescribePendingAggregationRequestsRequest(ServiceRequest):
    Limit: DescribePendingAggregationRequestsLimit | None
    NextToken: String | None


class PendingAggregationRequest(TypedDict, total=False):
    RequesterAccountId: AccountId | None
    RequesterAwsRegion: AwsRegion | None


PendingAggregationRequestList = list[PendingAggregationRequest]


class DescribePendingAggregationRequestsResponse(TypedDict, total=False):
    PendingAggregationRequests: PendingAggregationRequestList | None
    NextToken: String | None


class DescribeRemediationConfigurationsRequest(ServiceRequest):
    ConfigRuleNames: ConfigRuleNames


class SsmControls(TypedDict, total=False):
    ConcurrentExecutionRatePercentage: Percentage | None
    ErrorPercentage: Percentage | None


class ExecutionControls(TypedDict, total=False):
    SsmControls: SsmControls | None


StaticParameterValues = list[StringWithCharLimit256]


class StaticValue(TypedDict, total=False):
    Values: StaticParameterValues


class ResourceValue(TypedDict, total=False):
    Value: ResourceValueType


class RemediationParameterValue(TypedDict, total=False):
    ResourceValue: ResourceValue | None
    StaticValue: StaticValue | None


RemediationParameters = dict[StringWithCharLimit256, RemediationParameterValue]


class RemediationConfiguration(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName
    TargetType: RemediationTargetType
    TargetId: StringWithCharLimit256
    TargetVersion: String | None
    Parameters: RemediationParameters | None
    ResourceType: String | None
    Automatic: Boolean | None
    ExecutionControls: ExecutionControls | None
    MaximumAutomaticAttempts: AutoRemediationAttempts | None
    RetryAttemptSeconds: AutoRemediationAttemptSeconds | None
    Arn: StringWithCharLimit1024 | None
    CreatedByService: StringWithCharLimit1024 | None


RemediationConfigurations = list[RemediationConfiguration]


class DescribeRemediationConfigurationsResponse(TypedDict, total=False):
    RemediationConfigurations: RemediationConfigurations | None


class DescribeRemediationExceptionsRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: RemediationExceptionResourceKeys | None
    Limit: Limit | None
    NextToken: String | None


class RemediationException(TypedDict, total=False):
    ConfigRuleName: ConfigRuleName
    ResourceType: StringWithCharLimit256
    ResourceId: StringWithCharLimit1024
    Message: StringWithCharLimit1024 | None
    ExpirationTime: Date | None


RemediationExceptions = list[RemediationException]


class DescribeRemediationExceptionsResponse(TypedDict, total=False):
    RemediationExceptions: RemediationExceptions | None
    NextToken: String | None


class DescribeRemediationExecutionStatusRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: ResourceKeys | None
    Limit: Limit | None
    NextToken: String | None


class RemediationExecutionStep(TypedDict, total=False):
    Name: String | None
    State: RemediationExecutionStepState | None
    ErrorMessage: String | None
    StartTime: Date | None
    StopTime: Date | None


RemediationExecutionSteps = list[RemediationExecutionStep]


class RemediationExecutionStatus(TypedDict, total=False):
    ResourceKey: ResourceKey | None
    State: RemediationExecutionState | None
    StepDetails: RemediationExecutionSteps | None
    InvocationTime: Date | None
    LastUpdatedTime: Date | None


RemediationExecutionStatuses = list[RemediationExecutionStatus]


class DescribeRemediationExecutionStatusResponse(TypedDict, total=False):
    RemediationExecutionStatuses: RemediationExecutionStatuses | None
    NextToken: String | None


RetentionConfigurationNameList = list[RetentionConfigurationName]


class DescribeRetentionConfigurationsRequest(ServiceRequest):
    RetentionConfigurationNames: RetentionConfigurationNameList | None
    NextToken: NextToken | None


class RetentionConfiguration(TypedDict, total=False):
    Name: RetentionConfigurationName
    RetentionPeriodInDays: RetentionPeriodInDays


RetentionConfigurationList = list[RetentionConfiguration]


class DescribeRetentionConfigurationsResponse(TypedDict, total=False):
    RetentionConfigurations: RetentionConfigurationList | None
    NextToken: NextToken | None


class DisassociateResourceTypesRequest(ServiceRequest):
    ConfigurationRecorderArn: AmazonResourceName
    ResourceTypes: ResourceTypeList


class DisassociateResourceTypesResponse(TypedDict, total=False):
    ConfigurationRecorder: ConfigurationRecorder


DiscoveredResourceIdentifierList = list[AggregateResourceIdentifier]
EarlierTime = datetime
OrderingTimestamp = datetime


class Evaluation(TypedDict, total=False):
    ComplianceResourceType: StringWithCharLimit256
    ComplianceResourceId: BaseResourceId
    ComplianceType: ComplianceType
    Annotation: StringWithCharLimit256 | None
    OrderingTimestamp: OrderingTimestamp


class EvaluationContext(TypedDict, total=False):
    EvaluationContextIdentifier: EvaluationContextIdentifier | None


class EvaluationResult(TypedDict, total=False):
    EvaluationResultIdentifier: EvaluationResultIdentifier | None
    ComplianceType: ComplianceType | None
    ResultRecordedTime: Date | None
    ConfigRuleInvokedTime: Date | None
    Annotation: StringWithCharLimit256 | None
    ResultToken: String | None


EvaluationResults = list[EvaluationResult]


class EvaluationStatus(TypedDict, total=False):
    Status: ResourceEvaluationStatus
    FailureReason: StringWithCharLimit1024 | None


Evaluations = list[Evaluation]


class ExternalEvaluation(TypedDict, total=False):
    ComplianceResourceType: StringWithCharLimit256
    ComplianceResourceId: BaseResourceId
    ComplianceType: ComplianceType
    Annotation: StringWithCharLimit256 | None
    OrderingTimestamp: OrderingTimestamp


class FailedRemediationBatch(TypedDict, total=False):
    FailureMessage: String | None
    FailedItems: RemediationConfigurations | None


FailedRemediationBatches = list[FailedRemediationBatch]


class FailedRemediationExceptionBatch(TypedDict, total=False):
    FailureMessage: String | None
    FailedItems: RemediationExceptions | None


FailedRemediationExceptionBatches = list[FailedRemediationExceptionBatch]


class FieldInfo(TypedDict, total=False):
    Name: FieldName | None


FieldInfoList = list[FieldInfo]


class GetAggregateComplianceDetailsByConfigRuleRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    ConfigRuleName: ConfigRuleName
    AccountId: AccountId
    AwsRegion: AwsRegion
    ComplianceType: ComplianceType | None
    Limit: Limit | None
    NextToken: NextToken | None


class GetAggregateComplianceDetailsByConfigRuleResponse(TypedDict, total=False):
    AggregateEvaluationResults: AggregateEvaluationResultList | None
    NextToken: NextToken | None


class GetAggregateConfigRuleComplianceSummaryRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: ConfigRuleComplianceSummaryFilters | None
    GroupByKey: ConfigRuleComplianceSummaryGroupKey | None
    Limit: GroupByAPILimit | None
    NextToken: NextToken | None


class GetAggregateConfigRuleComplianceSummaryResponse(TypedDict, total=False):
    GroupByKey: StringWithCharLimit256 | None
    AggregateComplianceCounts: AggregateComplianceCountList | None
    NextToken: NextToken | None


class GetAggregateConformancePackComplianceSummaryRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: AggregateConformancePackComplianceSummaryFilters | None
    GroupByKey: AggregateConformancePackComplianceSummaryGroupKey | None
    Limit: Limit | None
    NextToken: NextToken | None


class GetAggregateConformancePackComplianceSummaryResponse(TypedDict, total=False):
    AggregateConformancePackComplianceSummaries: (
        AggregateConformancePackComplianceSummaryList | None
    )
    GroupByKey: StringWithCharLimit256 | None
    NextToken: NextToken | None


class ResourceCountFilters(TypedDict, total=False):
    ResourceType: ResourceType | None
    AccountId: AccountId | None
    Region: AwsRegion | None


class GetAggregateDiscoveredResourceCountsRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Filters: ResourceCountFilters | None
    GroupByKey: ResourceCountGroupKey | None
    Limit: GroupByAPILimit | None
    NextToken: NextToken | None


Long = int


class GroupedResourceCount(TypedDict, total=False):
    GroupName: StringWithCharLimit256
    ResourceCount: Long


GroupedResourceCountList = list[GroupedResourceCount]


class GetAggregateDiscoveredResourceCountsResponse(TypedDict, total=False):
    TotalDiscoveredResources: Long
    GroupByKey: StringWithCharLimit256 | None
    GroupedResourceCounts: GroupedResourceCountList | None
    NextToken: NextToken | None


class GetAggregateResourceConfigRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    ResourceIdentifier: AggregateResourceIdentifier


class GetAggregateResourceConfigResponse(TypedDict, total=False):
    ConfigurationItem: ConfigurationItem | None


class GetComplianceDetailsByConfigRuleRequest(ServiceRequest):
    ConfigRuleName: StringWithCharLimit64
    ComplianceTypes: ComplianceTypes | None
    Limit: Limit | None
    NextToken: NextToken | None


class GetComplianceDetailsByConfigRuleResponse(TypedDict, total=False):
    EvaluationResults: EvaluationResults | None
    NextToken: NextToken | None


class GetComplianceDetailsByResourceRequest(ServiceRequest):
    ResourceType: StringWithCharLimit256 | None
    ResourceId: BaseResourceId | None
    ComplianceTypes: ComplianceTypes | None
    NextToken: String | None
    ResourceEvaluationId: ResourceEvaluationId | None


class GetComplianceDetailsByResourceResponse(TypedDict, total=False):
    EvaluationResults: EvaluationResults | None
    NextToken: String | None


class GetComplianceSummaryByConfigRuleResponse(TypedDict, total=False):
    ComplianceSummary: ComplianceSummary | None


ResourceTypes = list[StringWithCharLimit256]


class GetComplianceSummaryByResourceTypeRequest(ServiceRequest):
    ResourceTypes: ResourceTypes | None


class GetComplianceSummaryByResourceTypeResponse(TypedDict, total=False):
    ComplianceSummariesByResourceType: ComplianceSummariesByResourceType | None


class GetConformancePackComplianceDetailsRequest(ServiceRequest):
    ConformancePackName: ConformancePackName
    Filters: ConformancePackEvaluationFilters | None
    Limit: GetConformancePackComplianceDetailsLimit | None
    NextToken: NextToken | None


class GetConformancePackComplianceDetailsResponse(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackRuleEvaluationResults: ConformancePackRuleEvaluationResultsList | None
    NextToken: NextToken | None


class GetConformancePackComplianceSummaryRequest(ServiceRequest):
    ConformancePackNames: ConformancePackNamesToSummarizeList
    Limit: PageSizeLimit | None
    NextToken: NextToken | None


class GetConformancePackComplianceSummaryResponse(TypedDict, total=False):
    ConformancePackComplianceSummaryList: ConformancePackComplianceSummaryList | None
    NextToken: NextToken | None


class GetCustomRulePolicyRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName | None


class GetCustomRulePolicyResponse(TypedDict, total=False):
    PolicyText: PolicyText | None


class GetDiscoveredResourceCountsRequest(ServiceRequest):
    resourceTypes: ResourceTypes | None
    limit: Limit | None
    nextToken: NextToken | None


class ResourceCount(TypedDict, total=False):
    resourceType: ResourceType | None
    count: Long | None


ResourceCounts = list[ResourceCount]


class GetDiscoveredResourceCountsResponse(TypedDict, total=False):
    totalDiscoveredResources: Long | None
    resourceCounts: ResourceCounts | None
    nextToken: NextToken | None


class StatusDetailFilters(TypedDict, total=False):
    AccountId: AccountId | None
    MemberAccountRuleStatus: MemberAccountRuleStatus | None


class GetOrganizationConfigRuleDetailedStatusRequest(ServiceRequest):
    OrganizationConfigRuleName: OrganizationConfigRuleName
    Filters: StatusDetailFilters | None
    Limit: CosmosPageLimit | None
    NextToken: String | None


class MemberAccountStatus(TypedDict, total=False):
    AccountId: AccountId
    ConfigRuleName: StringWithCharLimit64
    MemberAccountRuleStatus: MemberAccountRuleStatus
    ErrorCode: String | None
    ErrorMessage: String | None
    LastUpdateTime: Date | None


OrganizationConfigRuleDetailedStatus = list[MemberAccountStatus]


class GetOrganizationConfigRuleDetailedStatusResponse(TypedDict, total=False):
    OrganizationConfigRuleDetailedStatus: OrganizationConfigRuleDetailedStatus | None
    NextToken: String | None


class OrganizationResourceDetailedStatusFilters(TypedDict, total=False):
    AccountId: AccountId | None
    Status: OrganizationResourceDetailedStatus | None


class GetOrganizationConformancePackDetailedStatusRequest(ServiceRequest):
    OrganizationConformancePackName: OrganizationConformancePackName
    Filters: OrganizationResourceDetailedStatusFilters | None
    Limit: CosmosPageLimit | None
    NextToken: String | None


class OrganizationConformancePackDetailedStatus(TypedDict, total=False):
    AccountId: AccountId
    ConformancePackName: StringWithCharLimit256
    Status: OrganizationResourceDetailedStatus
    ErrorCode: String | None
    ErrorMessage: String | None
    LastUpdateTime: Date | None


OrganizationConformancePackDetailedStatuses = list[OrganizationConformancePackDetailedStatus]


class GetOrganizationConformancePackDetailedStatusResponse(TypedDict, total=False):
    OrganizationConformancePackDetailedStatuses: OrganizationConformancePackDetailedStatuses | None
    NextToken: String | None


class GetOrganizationCustomRulePolicyRequest(ServiceRequest):
    OrganizationConfigRuleName: OrganizationConfigRuleName


class GetOrganizationCustomRulePolicyResponse(TypedDict, total=False):
    PolicyText: PolicyText | None


LaterTime = datetime


class GetResourceConfigHistoryRequest(ServiceRequest):
    resourceType: ResourceType
    resourceId: ResourceId
    laterTime: LaterTime | None
    earlierTime: EarlierTime | None
    chronologicalOrder: ChronologicalOrder | None
    limit: Limit | None
    nextToken: NextToken | None


class GetResourceConfigHistoryResponse(TypedDict, total=False):
    configurationItems: ConfigurationItemList | None
    nextToken: NextToken | None


class GetResourceEvaluationSummaryRequest(ServiceRequest):
    ResourceEvaluationId: ResourceEvaluationId


class ResourceDetails(TypedDict, total=False):
    ResourceId: BaseResourceId
    ResourceType: StringWithCharLimit256
    ResourceConfiguration: ResourceConfiguration
    ResourceConfigurationSchemaType: ResourceConfigurationSchemaType | None


class GetResourceEvaluationSummaryResponse(TypedDict, total=False):
    ResourceEvaluationId: ResourceEvaluationId | None
    EvaluationMode: EvaluationMode | None
    EvaluationStatus: EvaluationStatus | None
    EvaluationStartTimestamp: Date | None
    Compliance: ComplianceType | None
    EvaluationContext: EvaluationContext | None
    ResourceDetails: ResourceDetails | None


class GetStoredQueryRequest(ServiceRequest):
    QueryName: QueryName


class StoredQuery(TypedDict, total=False):
    QueryId: QueryId | None
    QueryArn: QueryArn | None
    QueryName: QueryName
    Description: QueryDescription | None
    Expression: QueryExpression | None


class GetStoredQueryResponse(TypedDict, total=False):
    StoredQuery: StoredQuery | None


class ResourceFilters(TypedDict, total=False):
    AccountId: AccountId | None
    ResourceId: ResourceId | None
    ResourceName: ResourceName | None
    Region: AwsRegion | None


class ListAggregateDiscoveredResourcesRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    ResourceType: ResourceType
    Filters: ResourceFilters | None
    Limit: Limit | None
    NextToken: NextToken | None


class ListAggregateDiscoveredResourcesResponse(TypedDict, total=False):
    ResourceIdentifiers: DiscoveredResourceIdentifierList | None
    NextToken: NextToken | None


class ListConfigurationRecordersRequest(ServiceRequest):
    Filters: ConfigurationRecorderFilterList | None
    MaxResults: MaxResults | None
    NextToken: NextToken | None


class ListConfigurationRecordersResponse(TypedDict, total=False):
    ConfigurationRecorderSummaries: ConfigurationRecorderSummaries
    NextToken: NextToken | None


class ListConformancePackComplianceScoresRequest(ServiceRequest):
    Filters: ConformancePackComplianceScoresFilters | None
    SortOrder: SortOrder | None
    SortBy: SortBy | None
    Limit: PageSizeLimit | None
    NextToken: NextToken | None


class ListConformancePackComplianceScoresResponse(TypedDict, total=False):
    NextToken: NextToken | None
    ConformancePackComplianceScores: ConformancePackComplianceScores


ResourceIdList = list[ResourceId]


class ListDiscoveredResourcesRequest(ServiceRequest):
    resourceType: ResourceType
    resourceIds: ResourceIdList | None
    resourceName: ResourceName | None
    limit: Limit | None
    includeDeletedResources: Boolean | None
    nextToken: NextToken | None


ResourceDeletionTime = datetime


class ResourceIdentifier(TypedDict, total=False):
    resourceType: ResourceType | None
    resourceId: ResourceId | None
    resourceName: ResourceName | None
    resourceDeletionTime: ResourceDeletionTime | None


ResourceIdentifierList = list[ResourceIdentifier]


class ListDiscoveredResourcesResponse(TypedDict, total=False):
    resourceIdentifiers: ResourceIdentifierList | None
    nextToken: NextToken | None


class TimeWindow(TypedDict, total=False):
    StartTime: Date | None
    EndTime: Date | None


class ResourceEvaluationFilters(TypedDict, total=False):
    EvaluationMode: EvaluationMode | None
    TimeWindow: TimeWindow | None
    EvaluationContextIdentifier: EvaluationContextIdentifier | None


class ListResourceEvaluationsRequest(ServiceRequest):
    Filters: ResourceEvaluationFilters | None
    Limit: ListResourceEvaluationsPageItemLimit | None
    NextToken: String | None


class ResourceEvaluation(TypedDict, total=False):
    ResourceEvaluationId: ResourceEvaluationId | None
    EvaluationMode: EvaluationMode | None
    EvaluationStartTimestamp: Date | None


ResourceEvaluations = list[ResourceEvaluation]


class ListResourceEvaluationsResponse(TypedDict, total=False):
    ResourceEvaluations: ResourceEvaluations | None
    NextToken: String | None


class ListStoredQueriesRequest(ServiceRequest):
    NextToken: String | None
    MaxResults: Limit | None


class StoredQueryMetadata(TypedDict, total=False):
    QueryId: QueryId
    QueryArn: QueryArn
    QueryName: QueryName
    Description: QueryDescription | None


StoredQueryMetadataList = list[StoredQueryMetadata]


class ListStoredQueriesResponse(TypedDict, total=False):
    StoredQueryMetadata: StoredQueryMetadataList | None
    NextToken: String | None


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    Limit: Limit | None
    NextToken: NextToken | None


class Tag(TypedDict, total=False):
    Key: TagKey | None
    Value: TagValue | None


TagList = list[Tag]


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: TagList | None
    NextToken: NextToken | None


class OrganizationCustomPolicyRuleMetadata(TypedDict, total=False):
    Description: StringWithCharLimit256Min0 | None
    OrganizationConfigRuleTriggerTypes: OrganizationConfigRuleTriggerTypeNoSNs | None
    InputParameters: StringWithCharLimit2048 | None
    MaximumExecutionFrequency: MaximumExecutionFrequency | None
    ResourceTypesScope: ResourceTypesScope | None
    ResourceIdScope: StringWithCharLimit768 | None
    TagKeyScope: StringWithCharLimit128 | None
    TagValueScope: StringWithCharLimit256 | None
    PolicyRuntime: PolicyRuntime
    PolicyText: PolicyText
    DebugLogDeliveryAccounts: DebugLogDeliveryAccounts | None


TagsList = list[Tag]


class PutAggregationAuthorizationRequest(ServiceRequest):
    AuthorizedAccountId: AccountId
    AuthorizedAwsRegion: AwsRegion
    Tags: TagsList | None


class PutAggregationAuthorizationResponse(TypedDict, total=False):
    AggregationAuthorization: AggregationAuthorization | None


class PutConfigRuleRequest(ServiceRequest):
    ConfigRule: ConfigRule
    Tags: TagsList | None


class PutConfigurationAggregatorRequest(ServiceRequest):
    ConfigurationAggregatorName: ConfigurationAggregatorName
    AccountAggregationSources: AccountAggregationSourceList | None
    OrganizationAggregationSource: OrganizationAggregationSource | None
    Tags: TagsList | None
    AggregatorFilters: AggregatorFilters | None


class PutConfigurationAggregatorResponse(TypedDict, total=False):
    ConfigurationAggregator: ConfigurationAggregator | None


class PutConfigurationRecorderRequest(ServiceRequest):
    ConfigurationRecorder: ConfigurationRecorder
    Tags: TagsList | None


class PutConformancePackRequest(ServiceRequest):
    ConformancePackName: ConformancePackName
    TemplateS3Uri: TemplateS3Uri | None
    TemplateBody: TemplateBody | None
    DeliveryS3Bucket: DeliveryS3Bucket | None
    DeliveryS3KeyPrefix: DeliveryS3KeyPrefix | None
    ConformancePackInputParameters: ConformancePackInputParameters | None
    TemplateSSMDocumentDetails: TemplateSSMDocumentDetails | None


class PutConformancePackResponse(TypedDict, total=False):
    ConformancePackArn: ConformancePackArn | None


class PutDeliveryChannelRequest(ServiceRequest):
    DeliveryChannel: DeliveryChannel


class PutEvaluationsRequest(ServiceRequest):
    Evaluations: Evaluations | None
    ResultToken: String
    TestMode: Boolean | None


class PutEvaluationsResponse(TypedDict, total=False):
    FailedEvaluations: Evaluations | None


class PutExternalEvaluationRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ExternalEvaluation: ExternalEvaluation


class PutExternalEvaluationResponse(TypedDict, total=False):
    pass


class PutOrganizationConfigRuleRequest(ServiceRequest):
    OrganizationConfigRuleName: OrganizationConfigRuleName
    OrganizationManagedRuleMetadata: OrganizationManagedRuleMetadata | None
    OrganizationCustomRuleMetadata: OrganizationCustomRuleMetadata | None
    ExcludedAccounts: ExcludedAccounts | None
    OrganizationCustomPolicyRuleMetadata: OrganizationCustomPolicyRuleMetadata | None


class PutOrganizationConfigRuleResponse(TypedDict, total=False):
    OrganizationConfigRuleArn: StringWithCharLimit256 | None


class PutOrganizationConformancePackRequest(ServiceRequest):
    OrganizationConformancePackName: OrganizationConformancePackName
    TemplateS3Uri: TemplateS3Uri | None
    TemplateBody: TemplateBody | None
    DeliveryS3Bucket: DeliveryS3Bucket | None
    DeliveryS3KeyPrefix: DeliveryS3KeyPrefix | None
    ConformancePackInputParameters: ConformancePackInputParameters | None
    ExcludedAccounts: ExcludedAccounts | None


class PutOrganizationConformancePackResponse(TypedDict, total=False):
    OrganizationConformancePackArn: StringWithCharLimit256 | None


class PutRemediationConfigurationsRequest(ServiceRequest):
    RemediationConfigurations: RemediationConfigurations


class PutRemediationConfigurationsResponse(TypedDict, total=False):
    FailedBatches: FailedRemediationBatches | None


class PutRemediationExceptionsRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: RemediationExceptionResourceKeys
    Message: StringWithCharLimit1024 | None
    ExpirationTime: Date | None


class PutRemediationExceptionsResponse(TypedDict, total=False):
    FailedBatches: FailedRemediationExceptionBatches | None


class PutResourceConfigRequest(ServiceRequest):
    ResourceType: ResourceTypeString
    SchemaVersionId: SchemaVersionId
    ResourceId: ResourceId
    ResourceName: ResourceName | None
    Configuration: Configuration
    Tags: Tags | None


class PutRetentionConfigurationRequest(ServiceRequest):
    RetentionPeriodInDays: RetentionPeriodInDays


class PutRetentionConfigurationResponse(TypedDict, total=False):
    RetentionConfiguration: RetentionConfiguration | None


class PutServiceLinkedConfigurationRecorderRequest(ServiceRequest):
    ServicePrincipal: ServicePrincipal
    Tags: TagsList | None


class PutServiceLinkedConfigurationRecorderResponse(TypedDict, total=False):
    Arn: AmazonResourceName | None
    Name: RecorderName | None


class PutStoredQueryRequest(ServiceRequest):
    StoredQuery: StoredQuery
    Tags: TagsList | None


class PutStoredQueryResponse(TypedDict, total=False):
    QueryArn: QueryArn | None


class QueryInfo(TypedDict, total=False):
    SelectFields: FieldInfoList | None


ReevaluateConfigRuleNames = list[ConfigRuleName]
Results = list[String]


class SelectAggregateResourceConfigRequest(ServiceRequest):
    Expression: Expression
    ConfigurationAggregatorName: ConfigurationAggregatorName
    Limit: Limit | None
    MaxResults: Limit | None
    NextToken: NextToken | None


class SelectAggregateResourceConfigResponse(TypedDict, total=False):
    Results: Results | None
    QueryInfo: QueryInfo | None
    NextToken: NextToken | None


class SelectResourceConfigRequest(ServiceRequest):
    Expression: Expression
    Limit: Limit | None
    NextToken: NextToken | None


class SelectResourceConfigResponse(TypedDict, total=False):
    Results: Results | None
    QueryInfo: QueryInfo | None
    NextToken: NextToken | None


class StartConfigRulesEvaluationRequest(ServiceRequest):
    ConfigRuleNames: ReevaluateConfigRuleNames | None


class StartConfigRulesEvaluationResponse(TypedDict, total=False):
    pass


class StartConfigurationRecorderRequest(ServiceRequest):
    ConfigurationRecorderName: RecorderName


class StartRemediationExecutionRequest(ServiceRequest):
    ConfigRuleName: ConfigRuleName
    ResourceKeys: ResourceKeys


class StartRemediationExecutionResponse(TypedDict, total=False):
    FailureMessage: String | None
    FailedItems: ResourceKeys | None


class StartResourceEvaluationRequest(ServiceRequest):
    ResourceDetails: ResourceDetails
    EvaluationContext: EvaluationContext | None
    EvaluationMode: EvaluationMode
    EvaluationTimeout: EvaluationTimeout | None
    ClientToken: ClientToken | None


class StartResourceEvaluationResponse(TypedDict, total=False):
    ResourceEvaluationId: ResourceEvaluationId | None


class StopConfigurationRecorderRequest(ServiceRequest):
    ConfigurationRecorderName: RecorderName


TagKeyList = list[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    Tags: TagList


class UntagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    TagKeys: TagKeyList


class ConfigApi:
    service: str = "config"
    version: str = "2014-11-12"

    @handler("AssociateResourceTypes")
    def associate_resource_types(
        self,
        context: RequestContext,
        configuration_recorder_arn: AmazonResourceName,
        resource_types: ResourceTypeList,
        **kwargs,
    ) -> AssociateResourceTypesResponse:
        raise NotImplementedError

    @handler("BatchGetAggregateResourceConfig")
    def batch_get_aggregate_resource_config(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        resource_identifiers: ResourceIdentifiersList,
        **kwargs,
    ) -> BatchGetAggregateResourceConfigResponse:
        raise NotImplementedError

    @handler("BatchGetResourceConfig")
    def batch_get_resource_config(
        self, context: RequestContext, resource_keys: ResourceKeys, **kwargs
    ) -> BatchGetResourceConfigResponse:
        raise NotImplementedError

    @handler("DeleteAggregationAuthorization")
    def delete_aggregation_authorization(
        self,
        context: RequestContext,
        authorized_account_id: AccountId,
        authorized_aws_region: AwsRegion,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteConfigRule")
    def delete_config_rule(
        self, context: RequestContext, config_rule_name: ConfigRuleName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteConfigurationAggregator")
    def delete_configuration_aggregator(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteConfigurationRecorder")
    def delete_configuration_recorder(
        self, context: RequestContext, configuration_recorder_name: RecorderName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteConformancePack")
    def delete_conformance_pack(
        self, context: RequestContext, conformance_pack_name: ConformancePackName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDeliveryChannel")
    def delete_delivery_channel(
        self, context: RequestContext, delivery_channel_name: ChannelName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteEvaluationResults")
    def delete_evaluation_results(
        self, context: RequestContext, config_rule_name: StringWithCharLimit64, **kwargs
    ) -> DeleteEvaluationResultsResponse:
        raise NotImplementedError

    @handler("DeleteOrganizationConfigRule")
    def delete_organization_config_rule(
        self,
        context: RequestContext,
        organization_config_rule_name: OrganizationConfigRuleName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteOrganizationConformancePack")
    def delete_organization_conformance_pack(
        self,
        context: RequestContext,
        organization_conformance_pack_name: OrganizationConformancePackName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeletePendingAggregationRequest")
    def delete_pending_aggregation_request(
        self,
        context: RequestContext,
        requester_account_id: AccountId,
        requester_aws_region: AwsRegion,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRemediationConfiguration")
    def delete_remediation_configuration(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_type: String | None = None,
        **kwargs,
    ) -> DeleteRemediationConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteRemediationExceptions")
    def delete_remediation_exceptions(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: RemediationExceptionResourceKeys,
        **kwargs,
    ) -> DeleteRemediationExceptionsResponse:
        raise NotImplementedError

    @handler("DeleteResourceConfig")
    def delete_resource_config(
        self,
        context: RequestContext,
        resource_type: ResourceTypeString,
        resource_id: ResourceId,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRetentionConfiguration")
    def delete_retention_configuration(
        self,
        context: RequestContext,
        retention_configuration_name: RetentionConfigurationName,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteServiceLinkedConfigurationRecorder")
    def delete_service_linked_configuration_recorder(
        self, context: RequestContext, service_principal: ServicePrincipal, **kwargs
    ) -> DeleteServiceLinkedConfigurationRecorderResponse:
        raise NotImplementedError

    @handler("DeleteStoredQuery")
    def delete_stored_query(
        self, context: RequestContext, query_name: QueryName, **kwargs
    ) -> DeleteStoredQueryResponse:
        raise NotImplementedError

    @handler("DeliverConfigSnapshot")
    def deliver_config_snapshot(
        self, context: RequestContext, delivery_channel_name: ChannelName, **kwargs
    ) -> DeliverConfigSnapshotResponse:
        raise NotImplementedError

    @handler("DescribeAggregateComplianceByConfigRules")
    def describe_aggregate_compliance_by_config_rules(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: ConfigRuleComplianceFilters | None = None,
        limit: GroupByAPILimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAggregateComplianceByConfigRulesResponse:
        raise NotImplementedError

    @handler("DescribeAggregateComplianceByConformancePacks")
    def describe_aggregate_compliance_by_conformance_packs(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: AggregateConformancePackComplianceFilters | None = None,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeAggregateComplianceByConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribeAggregationAuthorizations")
    def describe_aggregation_authorizations(
        self,
        context: RequestContext,
        limit: Limit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeAggregationAuthorizationsResponse:
        raise NotImplementedError

    @handler("DescribeComplianceByConfigRule")
    def describe_compliance_by_config_rule(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames | None = None,
        compliance_types: ComplianceTypes | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeComplianceByConfigRuleResponse:
        raise NotImplementedError

    @handler("DescribeComplianceByResource")
    def describe_compliance_by_resource(
        self,
        context: RequestContext,
        resource_type: StringWithCharLimit256 | None = None,
        resource_id: BaseResourceId | None = None,
        compliance_types: ComplianceTypes | None = None,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeComplianceByResourceResponse:
        raise NotImplementedError

    @handler("DescribeConfigRuleEvaluationStatus")
    def describe_config_rule_evaluation_status(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames | None = None,
        next_token: String | None = None,
        limit: RuleLimit | None = None,
        **kwargs,
    ) -> DescribeConfigRuleEvaluationStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigRules")
    def describe_config_rules(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames | None = None,
        next_token: String | None = None,
        filters: DescribeConfigRulesFilters | None = None,
        **kwargs,
    ) -> DescribeConfigRulesResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationAggregatorSourcesStatus")
    def describe_configuration_aggregator_sources_status(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        update_status: AggregatedSourceStatusTypeList | None = None,
        next_token: String | None = None,
        limit: Limit | None = None,
        **kwargs,
    ) -> DescribeConfigurationAggregatorSourcesStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationAggregators")
    def describe_configuration_aggregators(
        self,
        context: RequestContext,
        configuration_aggregator_names: ConfigurationAggregatorNameList | None = None,
        next_token: String | None = None,
        limit: Limit | None = None,
        **kwargs,
    ) -> DescribeConfigurationAggregatorsResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRecorderStatus")
    def describe_configuration_recorder_status(
        self,
        context: RequestContext,
        configuration_recorder_names: ConfigurationRecorderNameList | None = None,
        service_principal: ServicePrincipal | None = None,
        arn: AmazonResourceName | None = None,
        **kwargs,
    ) -> DescribeConfigurationRecorderStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRecorders")
    def describe_configuration_recorders(
        self,
        context: RequestContext,
        configuration_recorder_names: ConfigurationRecorderNameList | None = None,
        service_principal: ServicePrincipal | None = None,
        arn: AmazonResourceName | None = None,
        **kwargs,
    ) -> DescribeConfigurationRecordersResponse:
        raise NotImplementedError

    @handler("DescribeConformancePackCompliance")
    def describe_conformance_pack_compliance(
        self,
        context: RequestContext,
        conformance_pack_name: ConformancePackName,
        filters: ConformancePackComplianceFilters | None = None,
        limit: DescribeConformancePackComplianceLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeConformancePackComplianceResponse:
        raise NotImplementedError

    @handler("DescribeConformancePackStatus")
    def describe_conformance_pack_status(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesList | None = None,
        limit: PageSizeLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeConformancePackStatusResponse:
        raise NotImplementedError

    @handler("DescribeConformancePacks")
    def describe_conformance_packs(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesList | None = None,
        limit: PageSizeLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribeDeliveryChannelStatus")
    def describe_delivery_channel_status(
        self,
        context: RequestContext,
        delivery_channel_names: DeliveryChannelNameList | None = None,
        **kwargs,
    ) -> DescribeDeliveryChannelStatusResponse:
        raise NotImplementedError

    @handler("DescribeDeliveryChannels")
    def describe_delivery_channels(
        self,
        context: RequestContext,
        delivery_channel_names: DeliveryChannelNameList | None = None,
        **kwargs,
    ) -> DescribeDeliveryChannelsResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConfigRuleStatuses")
    def describe_organization_config_rule_statuses(
        self,
        context: RequestContext,
        organization_config_rule_names: OrganizationConfigRuleNames | None = None,
        limit: CosmosPageLimit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeOrganizationConfigRuleStatusesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConfigRules")
    def describe_organization_config_rules(
        self,
        context: RequestContext,
        organization_config_rule_names: OrganizationConfigRuleNames | None = None,
        limit: CosmosPageLimit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeOrganizationConfigRulesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConformancePackStatuses")
    def describe_organization_conformance_pack_statuses(
        self,
        context: RequestContext,
        organization_conformance_pack_names: OrganizationConformancePackNames | None = None,
        limit: CosmosPageLimit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeOrganizationConformancePackStatusesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConformancePacks")
    def describe_organization_conformance_packs(
        self,
        context: RequestContext,
        organization_conformance_pack_names: OrganizationConformancePackNames | None = None,
        limit: CosmosPageLimit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeOrganizationConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribePendingAggregationRequests")
    def describe_pending_aggregation_requests(
        self,
        context: RequestContext,
        limit: DescribePendingAggregationRequestsLimit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribePendingAggregationRequestsResponse:
        raise NotImplementedError

    @handler("DescribeRemediationConfigurations")
    def describe_remediation_configurations(
        self, context: RequestContext, config_rule_names: ConfigRuleNames, **kwargs
    ) -> DescribeRemediationConfigurationsResponse:
        raise NotImplementedError

    @handler("DescribeRemediationExceptions")
    def describe_remediation_exceptions(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: RemediationExceptionResourceKeys | None = None,
        limit: Limit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeRemediationExceptionsResponse:
        raise NotImplementedError

    @handler("DescribeRemediationExecutionStatus")
    def describe_remediation_execution_status(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: ResourceKeys | None = None,
        limit: Limit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> DescribeRemediationExecutionStatusResponse:
        raise NotImplementedError

    @handler("DescribeRetentionConfigurations")
    def describe_retention_configurations(
        self,
        context: RequestContext,
        retention_configuration_names: RetentionConfigurationNameList | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> DescribeRetentionConfigurationsResponse:
        raise NotImplementedError

    @handler("DisassociateResourceTypes")
    def disassociate_resource_types(
        self,
        context: RequestContext,
        configuration_recorder_arn: AmazonResourceName,
        resource_types: ResourceTypeList,
        **kwargs,
    ) -> DisassociateResourceTypesResponse:
        raise NotImplementedError

    @handler("GetAggregateComplianceDetailsByConfigRule")
    def get_aggregate_compliance_details_by_config_rule(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        config_rule_name: ConfigRuleName,
        account_id: AccountId,
        aws_region: AwsRegion,
        compliance_type: ComplianceType | None = None,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetAggregateComplianceDetailsByConfigRuleResponse:
        raise NotImplementedError

    @handler("GetAggregateConfigRuleComplianceSummary")
    def get_aggregate_config_rule_compliance_summary(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: ConfigRuleComplianceSummaryFilters | None = None,
        group_by_key: ConfigRuleComplianceSummaryGroupKey | None = None,
        limit: GroupByAPILimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetAggregateConfigRuleComplianceSummaryResponse:
        raise NotImplementedError

    @handler("GetAggregateConformancePackComplianceSummary")
    def get_aggregate_conformance_pack_compliance_summary(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: AggregateConformancePackComplianceSummaryFilters | None = None,
        group_by_key: AggregateConformancePackComplianceSummaryGroupKey | None = None,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetAggregateConformancePackComplianceSummaryResponse:
        raise NotImplementedError

    @handler("GetAggregateDiscoveredResourceCounts")
    def get_aggregate_discovered_resource_counts(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        filters: ResourceCountFilters | None = None,
        group_by_key: ResourceCountGroupKey | None = None,
        limit: GroupByAPILimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetAggregateDiscoveredResourceCountsResponse:
        raise NotImplementedError

    @handler("GetAggregateResourceConfig")
    def get_aggregate_resource_config(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        resource_identifier: AggregateResourceIdentifier,
        **kwargs,
    ) -> GetAggregateResourceConfigResponse:
        raise NotImplementedError

    @handler("GetComplianceDetailsByConfigRule")
    def get_compliance_details_by_config_rule(
        self,
        context: RequestContext,
        config_rule_name: StringWithCharLimit64,
        compliance_types: ComplianceTypes | None = None,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetComplianceDetailsByConfigRuleResponse:
        raise NotImplementedError

    @handler("GetComplianceDetailsByResource")
    def get_compliance_details_by_resource(
        self,
        context: RequestContext,
        resource_type: StringWithCharLimit256 | None = None,
        resource_id: BaseResourceId | None = None,
        compliance_types: ComplianceTypes | None = None,
        next_token: String | None = None,
        resource_evaluation_id: ResourceEvaluationId | None = None,
        **kwargs,
    ) -> GetComplianceDetailsByResourceResponse:
        raise NotImplementedError

    @handler("GetComplianceSummaryByConfigRule")
    def get_compliance_summary_by_config_rule(
        self, context: RequestContext, **kwargs
    ) -> GetComplianceSummaryByConfigRuleResponse:
        raise NotImplementedError

    @handler("GetComplianceSummaryByResourceType")
    def get_compliance_summary_by_resource_type(
        self, context: RequestContext, resource_types: ResourceTypes | None = None, **kwargs
    ) -> GetComplianceSummaryByResourceTypeResponse:
        raise NotImplementedError

    @handler("GetConformancePackComplianceDetails")
    def get_conformance_pack_compliance_details(
        self,
        context: RequestContext,
        conformance_pack_name: ConformancePackName,
        filters: ConformancePackEvaluationFilters | None = None,
        limit: GetConformancePackComplianceDetailsLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetConformancePackComplianceDetailsResponse:
        raise NotImplementedError

    @handler("GetConformancePackComplianceSummary")
    def get_conformance_pack_compliance_summary(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesToSummarizeList,
        limit: PageSizeLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetConformancePackComplianceSummaryResponse:
        raise NotImplementedError

    @handler("GetCustomRulePolicy")
    def get_custom_rule_policy(
        self, context: RequestContext, config_rule_name: ConfigRuleName | None = None, **kwargs
    ) -> GetCustomRulePolicyResponse:
        raise NotImplementedError

    @handler("GetDiscoveredResourceCounts")
    def get_discovered_resource_counts(
        self,
        context: RequestContext,
        resource_types: ResourceTypes | None = None,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetDiscoveredResourceCountsResponse:
        raise NotImplementedError

    @handler("GetOrganizationConfigRuleDetailedStatus")
    def get_organization_config_rule_detailed_status(
        self,
        context: RequestContext,
        organization_config_rule_name: OrganizationConfigRuleName,
        filters: StatusDetailFilters | None = None,
        limit: CosmosPageLimit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> GetOrganizationConfigRuleDetailedStatusResponse:
        raise NotImplementedError

    @handler("GetOrganizationConformancePackDetailedStatus")
    def get_organization_conformance_pack_detailed_status(
        self,
        context: RequestContext,
        organization_conformance_pack_name: OrganizationConformancePackName,
        filters: OrganizationResourceDetailedStatusFilters | None = None,
        limit: CosmosPageLimit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> GetOrganizationConformancePackDetailedStatusResponse:
        raise NotImplementedError

    @handler("GetOrganizationCustomRulePolicy")
    def get_organization_custom_rule_policy(
        self,
        context: RequestContext,
        organization_config_rule_name: OrganizationConfigRuleName,
        **kwargs,
    ) -> GetOrganizationCustomRulePolicyResponse:
        raise NotImplementedError

    @handler("GetResourceConfigHistory")
    def get_resource_config_history(
        self,
        context: RequestContext,
        resource_type: ResourceType,
        resource_id: ResourceId,
        later_time: LaterTime | None = None,
        earlier_time: EarlierTime | None = None,
        chronological_order: ChronologicalOrder | None = None,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> GetResourceConfigHistoryResponse:
        raise NotImplementedError

    @handler("GetResourceEvaluationSummary")
    def get_resource_evaluation_summary(
        self, context: RequestContext, resource_evaluation_id: ResourceEvaluationId, **kwargs
    ) -> GetResourceEvaluationSummaryResponse:
        raise NotImplementedError

    @handler("GetStoredQuery")
    def get_stored_query(
        self, context: RequestContext, query_name: QueryName, **kwargs
    ) -> GetStoredQueryResponse:
        raise NotImplementedError

    @handler("ListAggregateDiscoveredResources")
    def list_aggregate_discovered_resources(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        resource_type: ResourceType,
        filters: ResourceFilters | None = None,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListAggregateDiscoveredResourcesResponse:
        raise NotImplementedError

    @handler("ListConfigurationRecorders")
    def list_configuration_recorders(
        self,
        context: RequestContext,
        filters: ConfigurationRecorderFilterList | None = None,
        max_results: MaxResults | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListConfigurationRecordersResponse:
        raise NotImplementedError

    @handler("ListConformancePackComplianceScores")
    def list_conformance_pack_compliance_scores(
        self,
        context: RequestContext,
        filters: ConformancePackComplianceScoresFilters | None = None,
        sort_order: SortOrder | None = None,
        sort_by: SortBy | None = None,
        limit: PageSizeLimit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListConformancePackComplianceScoresResponse:
        raise NotImplementedError

    @handler("ListDiscoveredResources")
    def list_discovered_resources(
        self,
        context: RequestContext,
        resource_type: ResourceType,
        resource_ids: ResourceIdList | None = None,
        resource_name: ResourceName | None = None,
        limit: Limit | None = None,
        include_deleted_resources: Boolean | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListDiscoveredResourcesResponse:
        raise NotImplementedError

    @handler("ListResourceEvaluations")
    def list_resource_evaluations(
        self,
        context: RequestContext,
        filters: ResourceEvaluationFilters | None = None,
        limit: ListResourceEvaluationsPageItemLimit | None = None,
        next_token: String | None = None,
        **kwargs,
    ) -> ListResourceEvaluationsResponse:
        raise NotImplementedError

    @handler("ListStoredQueries")
    def list_stored_queries(
        self,
        context: RequestContext,
        next_token: String | None = None,
        max_results: Limit | None = None,
        **kwargs,
    ) -> ListStoredQueriesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutAggregationAuthorization")
    def put_aggregation_authorization(
        self,
        context: RequestContext,
        authorized_account_id: AccountId,
        authorized_aws_region: AwsRegion,
        tags: TagsList | None = None,
        **kwargs,
    ) -> PutAggregationAuthorizationResponse:
        raise NotImplementedError

    @handler("PutConfigRule")
    def put_config_rule(
        self,
        context: RequestContext,
        config_rule: ConfigRule,
        tags: TagsList | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutConfigurationAggregator")
    def put_configuration_aggregator(
        self,
        context: RequestContext,
        configuration_aggregator_name: ConfigurationAggregatorName,
        account_aggregation_sources: AccountAggregationSourceList | None = None,
        organization_aggregation_source: OrganizationAggregationSource | None = None,
        tags: TagsList | None = None,
        aggregator_filters: AggregatorFilters | None = None,
        **kwargs,
    ) -> PutConfigurationAggregatorResponse:
        raise NotImplementedError

    @handler("PutConfigurationRecorder")
    def put_configuration_recorder(
        self,
        context: RequestContext,
        configuration_recorder: ConfigurationRecorder,
        tags: TagsList | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutConformancePack")
    def put_conformance_pack(
        self,
        context: RequestContext,
        conformance_pack_name: ConformancePackName,
        template_s3_uri: TemplateS3Uri | None = None,
        template_body: TemplateBody | None = None,
        delivery_s3_bucket: DeliveryS3Bucket | None = None,
        delivery_s3_key_prefix: DeliveryS3KeyPrefix | None = None,
        conformance_pack_input_parameters: ConformancePackInputParameters | None = None,
        template_ssm_document_details: TemplateSSMDocumentDetails | None = None,
        **kwargs,
    ) -> PutConformancePackResponse:
        raise NotImplementedError

    @handler("PutDeliveryChannel")
    def put_delivery_channel(
        self, context: RequestContext, delivery_channel: DeliveryChannel, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("PutEvaluations")
    def put_evaluations(
        self,
        context: RequestContext,
        result_token: String,
        evaluations: Evaluations | None = None,
        test_mode: Boolean | None = None,
        **kwargs,
    ) -> PutEvaluationsResponse:
        raise NotImplementedError

    @handler("PutExternalEvaluation")
    def put_external_evaluation(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        external_evaluation: ExternalEvaluation,
        **kwargs,
    ) -> PutExternalEvaluationResponse:
        raise NotImplementedError

    @handler("PutOrganizationConfigRule")
    def put_organization_config_rule(
        self,
        context: RequestContext,
        organization_config_rule_name: OrganizationConfigRuleName,
        organization_managed_rule_metadata: OrganizationManagedRuleMetadata | None = None,
        organization_custom_rule_metadata: OrganizationCustomRuleMetadata | None = None,
        excluded_accounts: ExcludedAccounts | None = None,
        organization_custom_policy_rule_metadata: OrganizationCustomPolicyRuleMetadata
        | None = None,
        **kwargs,
    ) -> PutOrganizationConfigRuleResponse:
        raise NotImplementedError

    @handler("PutOrganizationConformancePack")
    def put_organization_conformance_pack(
        self,
        context: RequestContext,
        organization_conformance_pack_name: OrganizationConformancePackName,
        template_s3_uri: TemplateS3Uri | None = None,
        template_body: TemplateBody | None = None,
        delivery_s3_bucket: DeliveryS3Bucket | None = None,
        delivery_s3_key_prefix: DeliveryS3KeyPrefix | None = None,
        conformance_pack_input_parameters: ConformancePackInputParameters | None = None,
        excluded_accounts: ExcludedAccounts | None = None,
        **kwargs,
    ) -> PutOrganizationConformancePackResponse:
        raise NotImplementedError

    @handler("PutRemediationConfigurations")
    def put_remediation_configurations(
        self,
        context: RequestContext,
        remediation_configurations: RemediationConfigurations,
        **kwargs,
    ) -> PutRemediationConfigurationsResponse:
        raise NotImplementedError

    @handler("PutRemediationExceptions")
    def put_remediation_exceptions(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: RemediationExceptionResourceKeys,
        message: StringWithCharLimit1024 | None = None,
        expiration_time: Date | None = None,
        **kwargs,
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
        resource_name: ResourceName | None = None,
        tags: Tags | None = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutRetentionConfiguration")
    def put_retention_configuration(
        self, context: RequestContext, retention_period_in_days: RetentionPeriodInDays, **kwargs
    ) -> PutRetentionConfigurationResponse:
        raise NotImplementedError

    @handler("PutServiceLinkedConfigurationRecorder")
    def put_service_linked_configuration_recorder(
        self,
        context: RequestContext,
        service_principal: ServicePrincipal,
        tags: TagsList | None = None,
        **kwargs,
    ) -> PutServiceLinkedConfigurationRecorderResponse:
        raise NotImplementedError

    @handler("PutStoredQuery")
    def put_stored_query(
        self,
        context: RequestContext,
        stored_query: StoredQuery,
        tags: TagsList | None = None,
        **kwargs,
    ) -> PutStoredQueryResponse:
        raise NotImplementedError

    @handler("SelectAggregateResourceConfig")
    def select_aggregate_resource_config(
        self,
        context: RequestContext,
        expression: Expression,
        configuration_aggregator_name: ConfigurationAggregatorName,
        limit: Limit | None = None,
        max_results: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> SelectAggregateResourceConfigResponse:
        raise NotImplementedError

    @handler("SelectResourceConfig")
    def select_resource_config(
        self,
        context: RequestContext,
        expression: Expression,
        limit: Limit | None = None,
        next_token: NextToken | None = None,
        **kwargs,
    ) -> SelectResourceConfigResponse:
        raise NotImplementedError

    @handler("StartConfigRulesEvaluation")
    def start_config_rules_evaluation(
        self,
        context: RequestContext,
        config_rule_names: ReevaluateConfigRuleNames | None = None,
        **kwargs,
    ) -> StartConfigRulesEvaluationResponse:
        raise NotImplementedError

    @handler("StartConfigurationRecorder")
    def start_configuration_recorder(
        self, context: RequestContext, configuration_recorder_name: RecorderName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("StartRemediationExecution")
    def start_remediation_execution(
        self,
        context: RequestContext,
        config_rule_name: ConfigRuleName,
        resource_keys: ResourceKeys,
        **kwargs,
    ) -> StartRemediationExecutionResponse:
        raise NotImplementedError

    @handler("StartResourceEvaluation")
    def start_resource_evaluation(
        self,
        context: RequestContext,
        resource_details: ResourceDetails,
        evaluation_mode: EvaluationMode,
        evaluation_context: EvaluationContext | None = None,
        evaluation_timeout: EvaluationTimeout | None = None,
        client_token: ClientToken | None = None,
        **kwargs,
    ) -> StartResourceEvaluationResponse:
        raise NotImplementedError

    @handler("StopConfigurationRecorder")
    def stop_configuration_recorder(
        self, context: RequestContext, configuration_recorder_name: RecorderName, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> None:
        raise NotImplementedError
