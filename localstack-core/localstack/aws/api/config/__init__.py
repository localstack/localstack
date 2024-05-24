from datetime import datetime
from typing import Dict, List, Optional, TypedDict

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
RetentionConfigurationName = str
RetentionPeriodInDays = int
RuleLimit = int
SSMDocumentName = str
SSMDocumentVersion = str
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


class EvaluationMode(str):
    DETECTIVE = "DETECTIVE"
    PROACTIVE = "PROACTIVE"


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


class OrganizationConfigRuleTriggerTypeNoSN(str):
    ConfigurationItemChangeNotification = "ConfigurationItemChangeNotification"
    OversizedConfigurationItemChangeNotification = "OversizedConfigurationItemChangeNotification"


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
    CUSTOM_POLICY = "CUSTOM_POLICY"


class RecorderStatus(str):
    Pending = "Pending"
    Success = "Success"
    Failure = "Failure"


class RecordingFrequency(str):
    CONTINUOUS = "CONTINUOUS"
    DAILY = "DAILY"


class RecordingStrategyType(str):
    ALL_SUPPORTED_RESOURCE_TYPES = "ALL_SUPPORTED_RESOURCE_TYPES"
    INCLUSION_BY_RESOURCE_TYPES = "INCLUSION_BY_RESOURCE_TYPES"
    EXCLUSION_BY_RESOURCE_TYPES = "EXCLUSION_BY_RESOURCE_TYPES"


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


class ResourceConfigurationSchemaType(str):
    CFN_RESOURCE_SCHEMA = "CFN_RESOURCE_SCHEMA"


class ResourceCountGroupKey(str):
    RESOURCE_TYPE = "RESOURCE_TYPE"
    ACCOUNT_ID = "ACCOUNT_ID"
    AWS_REGION = "AWS_REGION"


class ResourceEvaluationStatus(str):
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    SUCCEEDED = "SUCCEEDED"


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


class ResourceValueType(str):
    RESOURCE_ID = "RESOURCE_ID"


class SortBy(str):
    SCORE = "SCORE"


class SortOrder(str):
    ASCENDING = "ASCENDING"
    DESCENDING = "DESCENDING"


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


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = False
    status_code: int = 400


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
    EvaluationMode: Optional[EvaluationMode]


class EvaluationResultIdentifier(TypedDict, total=False):
    EvaluationResultQualifier: Optional[EvaluationResultQualifier]
    OrderingTimestamp: Optional[Date]
    ResourceEvaluationId: Optional[ResourceEvaluationId]


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
ConfigurationItemDeliveryTime = datetime
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
    recordingFrequency: Optional[RecordingFrequency]
    configurationItemDeliveryTime: Optional[ConfigurationItemDeliveryTime]


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


class EvaluationModeConfiguration(TypedDict, total=False):
    Mode: Optional[EvaluationMode]


EvaluationModes = List[EvaluationModeConfiguration]


class CustomPolicyDetails(TypedDict, total=False):
    PolicyRuntime: PolicyRuntime
    PolicyText: PolicyText
    EnableDebugLogDelivery: Optional[Boolean]


class SourceDetail(TypedDict, total=False):
    EventSource: Optional[EventSource]
    MessageType: Optional[MessageType]
    MaximumExecutionFrequency: Optional[MaximumExecutionFrequency]


SourceDetails = List[SourceDetail]


class Source(TypedDict, total=False):
    Owner: Owner
    SourceIdentifier: Optional[StringWithCharLimit256]
    SourceDetails: Optional[SourceDetails]
    CustomPolicyDetails: Optional[CustomPolicyDetails]


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
    EvaluationModes: Optional[EvaluationModes]


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
    LastDebugLogDeliveryStatus: Optional[String]
    LastDebugLogDeliveryStatusReason: Optional[String]
    LastDebugLogDeliveryTime: Optional[Date]


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
    recordingFrequency: Optional[RecordingFrequency]
    configurationItemDeliveryTime: Optional[ConfigurationItemDeliveryTime]


ConfigurationItemList = List[ConfigurationItem]
RecordingModeResourceTypesList = List[ResourceType]


class RecordingModeOverride(TypedDict, total=False):
    description: Optional[Description]
    resourceTypes: RecordingModeResourceTypesList
    recordingFrequency: RecordingFrequency


RecordingModeOverrides = List[RecordingModeOverride]


class RecordingMode(TypedDict, total=False):
    recordingFrequency: RecordingFrequency
    recordingModeOverrides: Optional[RecordingModeOverrides]


class RecordingStrategy(TypedDict, total=False):
    useOnly: Optional[RecordingStrategyType]


ResourceTypeList = List[ResourceType]


class ExclusionByResourceTypes(TypedDict, total=False):
    resourceTypes: Optional[ResourceTypeList]


class RecordingGroup(TypedDict, total=False):
    allSupported: Optional[AllSupported]
    includeGlobalResourceTypes: Optional[IncludeGlobalResourceTypes]
    resourceTypes: Optional[ResourceTypeList]
    exclusionByResourceTypes: Optional[ExclusionByResourceTypes]
    recordingStrategy: Optional[RecordingStrategy]


class ConfigurationRecorder(TypedDict, total=False):
    name: Optional[RecorderName]
    roleARN: Optional[String]
    recordingGroup: Optional[RecordingGroup]
    recordingMode: Optional[RecordingMode]


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
LastUpdatedTime = datetime


class ConformancePackComplianceScore(TypedDict, total=False):
    Score: Optional[ComplianceScore]
    ConformancePackName: Optional[ConformancePackName]
    LastUpdatedTime: Optional[LastUpdatedTime]


ConformancePackComplianceScores = List[ConformancePackComplianceScore]
ConformancePackNameFilter = List[ConformancePackName]


class ConformancePackComplianceScoresFilters(TypedDict, total=False):
    ConformancePackNames: ConformancePackNameFilter


class ConformancePackComplianceSummary(TypedDict, total=False):
    ConformancePackName: ConformancePackName
    ConformancePackComplianceStatus: ConformancePackComplianceType


ConformancePackComplianceSummaryList = List[ConformancePackComplianceSummary]


class TemplateSSMDocumentDetails(TypedDict, total=False):
    DocumentName: SSMDocumentName
    DocumentVersion: Optional[SSMDocumentVersion]


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
    TemplateSSMDocumentDetails: Optional[TemplateSSMDocumentDetails]


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
DebugLogDeliveryAccounts = List[AccountId]


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


class DescribeConfigRulesFilters(TypedDict, total=False):
    EvaluationMode: Optional[EvaluationMode]


class DescribeConfigRulesRequest(ServiceRequest):
    ConfigRuleNames: Optional[ConfigRuleNames]
    NextToken: Optional[String]
    Filters: Optional[DescribeConfigRulesFilters]


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


ResourceTypesScope = List[StringWithCharLimit256]
OrganizationConfigRuleTriggerTypeNoSNs = List[OrganizationConfigRuleTriggerTypeNoSN]


class OrganizationCustomPolicyRuleMetadataNoPolicy(TypedDict, total=False):
    Description: Optional[StringWithCharLimit256Min0]
    OrganizationConfigRuleTriggerTypes: Optional[OrganizationConfigRuleTriggerTypeNoSNs]
    InputParameters: Optional[StringWithCharLimit2048]
    MaximumExecutionFrequency: Optional[MaximumExecutionFrequency]
    ResourceTypesScope: Optional[ResourceTypesScope]
    ResourceIdScope: Optional[StringWithCharLimit768]
    TagKeyScope: Optional[StringWithCharLimit128]
    TagValueScope: Optional[StringWithCharLimit256]
    PolicyRuntime: Optional[PolicyRuntime]
    DebugLogDeliveryAccounts: Optional[DebugLogDeliveryAccounts]


ExcludedAccounts = List[AccountId]
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
    OrganizationCustomPolicyRuleMetadata: Optional[OrganizationCustomPolicyRuleMetadataNoPolicy]


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


class EvaluationContext(TypedDict, total=False):
    EvaluationContextIdentifier: Optional[EvaluationContextIdentifier]


class EvaluationResult(TypedDict, total=False):
    EvaluationResultIdentifier: Optional[EvaluationResultIdentifier]
    ComplianceType: Optional[ComplianceType]
    ResultRecordedTime: Optional[Date]
    ConfigRuleInvokedTime: Optional[Date]
    Annotation: Optional[StringWithCharLimit256]
    ResultToken: Optional[String]


EvaluationResults = List[EvaluationResult]


class EvaluationStatus(TypedDict, total=False):
    Status: ResourceEvaluationStatus
    FailureReason: Optional[StringWithCharLimit1024]


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
    ResourceType: Optional[StringWithCharLimit256]
    ResourceId: Optional[BaseResourceId]
    ComplianceTypes: Optional[ComplianceTypes]
    NextToken: Optional[String]
    ResourceEvaluationId: Optional[ResourceEvaluationId]


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


class GetCustomRulePolicyRequest(ServiceRequest):
    ConfigRuleName: Optional[ConfigRuleName]


class GetCustomRulePolicyResponse(TypedDict, total=False):
    PolicyText: Optional[PolicyText]


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


class GetOrganizationCustomRulePolicyRequest(ServiceRequest):
    OrganizationConfigRuleName: OrganizationConfigRuleName


class GetOrganizationCustomRulePolicyResponse(TypedDict, total=False):
    PolicyText: Optional[PolicyText]


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


class GetResourceEvaluationSummaryRequest(ServiceRequest):
    ResourceEvaluationId: ResourceEvaluationId


class ResourceDetails(TypedDict, total=False):
    ResourceId: BaseResourceId
    ResourceType: StringWithCharLimit256
    ResourceConfiguration: ResourceConfiguration
    ResourceConfigurationSchemaType: Optional[ResourceConfigurationSchemaType]


class GetResourceEvaluationSummaryResponse(TypedDict, total=False):
    ResourceEvaluationId: Optional[ResourceEvaluationId]
    EvaluationMode: Optional[EvaluationMode]
    EvaluationStatus: Optional[EvaluationStatus]
    EvaluationStartTimestamp: Optional[Date]
    Compliance: Optional[ComplianceType]
    EvaluationContext: Optional[EvaluationContext]
    ResourceDetails: Optional[ResourceDetails]


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


class ListConformancePackComplianceScoresRequest(ServiceRequest):
    Filters: Optional[ConformancePackComplianceScoresFilters]
    SortOrder: Optional[SortOrder]
    SortBy: Optional[SortBy]
    Limit: Optional[PageSizeLimit]
    NextToken: Optional[NextToken]


class ListConformancePackComplianceScoresResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ConformancePackComplianceScores: ConformancePackComplianceScores


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


class TimeWindow(TypedDict, total=False):
    StartTime: Optional[Date]
    EndTime: Optional[Date]


class ResourceEvaluationFilters(TypedDict, total=False):
    EvaluationMode: Optional[EvaluationMode]
    TimeWindow: Optional[TimeWindow]
    EvaluationContextIdentifier: Optional[EvaluationContextIdentifier]


class ListResourceEvaluationsRequest(ServiceRequest):
    Filters: Optional[ResourceEvaluationFilters]
    Limit: Optional[ListResourceEvaluationsPageItemLimit]
    NextToken: Optional[String]


class ResourceEvaluation(TypedDict, total=False):
    ResourceEvaluationId: Optional[ResourceEvaluationId]
    EvaluationMode: Optional[EvaluationMode]
    EvaluationStartTimestamp: Optional[Date]


ResourceEvaluations = List[ResourceEvaluation]


class ListResourceEvaluationsResponse(TypedDict, total=False):
    ResourceEvaluations: Optional[ResourceEvaluations]
    NextToken: Optional[String]


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


class OrganizationCustomPolicyRuleMetadata(TypedDict, total=False):
    Description: Optional[StringWithCharLimit256Min0]
    OrganizationConfigRuleTriggerTypes: Optional[OrganizationConfigRuleTriggerTypeNoSNs]
    InputParameters: Optional[StringWithCharLimit2048]
    MaximumExecutionFrequency: Optional[MaximumExecutionFrequency]
    ResourceTypesScope: Optional[ResourceTypesScope]
    ResourceIdScope: Optional[StringWithCharLimit768]
    TagKeyScope: Optional[StringWithCharLimit128]
    TagValueScope: Optional[StringWithCharLimit256]
    PolicyRuntime: PolicyRuntime
    PolicyText: PolicyText
    DebugLogDeliveryAccounts: Optional[DebugLogDeliveryAccounts]


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
    TemplateSSMDocumentDetails: Optional[TemplateSSMDocumentDetails]


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
    OrganizationCustomPolicyRuleMetadata: Optional[OrganizationCustomPolicyRuleMetadata]


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


class StartResourceEvaluationRequest(ServiceRequest):
    ResourceDetails: ResourceDetails
    EvaluationContext: Optional[EvaluationContext]
    EvaluationMode: EvaluationMode
    EvaluationTimeout: Optional[EvaluationTimeout]
    ClientToken: Optional[ClientToken]


class StartResourceEvaluationResponse(TypedDict, total=False):
    ResourceEvaluationId: Optional[ResourceEvaluationId]


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
        resource_type: String = None,
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
        filters: ConfigRuleComplianceFilters = None,
        limit: GroupByAPILimit = None,
        next_token: NextToken = None,
        **kwargs,
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
        **kwargs,
    ) -> DescribeAggregateComplianceByConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribeAggregationAuthorizations")
    def describe_aggregation_authorizations(
        self, context: RequestContext, limit: Limit = None, next_token: String = None, **kwargs
    ) -> DescribeAggregationAuthorizationsResponse:
        raise NotImplementedError

    @handler("DescribeComplianceByConfigRule")
    def describe_compliance_by_config_rule(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames = None,
        compliance_types: ComplianceTypes = None,
        next_token: String = None,
        **kwargs,
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
        **kwargs,
    ) -> DescribeComplianceByResourceResponse:
        raise NotImplementedError

    @handler("DescribeConfigRuleEvaluationStatus")
    def describe_config_rule_evaluation_status(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames = None,
        next_token: String = None,
        limit: RuleLimit = None,
        **kwargs,
    ) -> DescribeConfigRuleEvaluationStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigRules")
    def describe_config_rules(
        self,
        context: RequestContext,
        config_rule_names: ConfigRuleNames = None,
        next_token: String = None,
        filters: DescribeConfigRulesFilters = None,
        **kwargs,
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
        **kwargs,
    ) -> DescribeConfigurationAggregatorSourcesStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationAggregators")
    def describe_configuration_aggregators(
        self,
        context: RequestContext,
        configuration_aggregator_names: ConfigurationAggregatorNameList = None,
        next_token: String = None,
        limit: Limit = None,
        **kwargs,
    ) -> DescribeConfigurationAggregatorsResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRecorderStatus")
    def describe_configuration_recorder_status(
        self,
        context: RequestContext,
        configuration_recorder_names: ConfigurationRecorderNameList = None,
        **kwargs,
    ) -> DescribeConfigurationRecorderStatusResponse:
        raise NotImplementedError

    @handler("DescribeConfigurationRecorders")
    def describe_configuration_recorders(
        self,
        context: RequestContext,
        configuration_recorder_names: ConfigurationRecorderNameList = None,
        **kwargs,
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
        **kwargs,
    ) -> DescribeConformancePackComplianceResponse:
        raise NotImplementedError

    @handler("DescribeConformancePackStatus")
    def describe_conformance_pack_status(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesList = None,
        limit: PageSizeLimit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeConformancePackStatusResponse:
        raise NotImplementedError

    @handler("DescribeConformancePacks")
    def describe_conformance_packs(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesList = None,
        limit: PageSizeLimit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribeDeliveryChannelStatus")
    def describe_delivery_channel_status(
        self,
        context: RequestContext,
        delivery_channel_names: DeliveryChannelNameList = None,
        **kwargs,
    ) -> DescribeDeliveryChannelStatusResponse:
        raise NotImplementedError

    @handler("DescribeDeliveryChannels")
    def describe_delivery_channels(
        self,
        context: RequestContext,
        delivery_channel_names: DeliveryChannelNameList = None,
        **kwargs,
    ) -> DescribeDeliveryChannelsResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConfigRuleStatuses")
    def describe_organization_config_rule_statuses(
        self,
        context: RequestContext,
        organization_config_rule_names: OrganizationConfigRuleNames = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeOrganizationConfigRuleStatusesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConfigRules")
    def describe_organization_config_rules(
        self,
        context: RequestContext,
        organization_config_rule_names: OrganizationConfigRuleNames = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeOrganizationConfigRulesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConformancePackStatuses")
    def describe_organization_conformance_pack_statuses(
        self,
        context: RequestContext,
        organization_conformance_pack_names: OrganizationConformancePackNames = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeOrganizationConformancePackStatusesResponse:
        raise NotImplementedError

    @handler("DescribeOrganizationConformancePacks")
    def describe_organization_conformance_packs(
        self,
        context: RequestContext,
        organization_conformance_pack_names: OrganizationConformancePackNames = None,
        limit: CosmosPageLimit = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeOrganizationConformancePacksResponse:
        raise NotImplementedError

    @handler("DescribePendingAggregationRequests")
    def describe_pending_aggregation_requests(
        self,
        context: RequestContext,
        limit: DescribePendingAggregationRequestsLimit = None,
        next_token: String = None,
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
        resource_keys: RemediationExceptionResourceKeys = None,
        limit: Limit = None,
        next_token: String = None,
        **kwargs,
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
        **kwargs,
    ) -> DescribeRemediationExecutionStatusResponse:
        raise NotImplementedError

    @handler("DescribeRetentionConfigurations")
    def describe_retention_configurations(
        self,
        context: RequestContext,
        retention_configuration_names: RetentionConfigurationNameList = None,
        next_token: NextToken = None,
        **kwargs,
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
        **kwargs,
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
        **kwargs,
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
        **kwargs,
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
        compliance_types: ComplianceTypes = None,
        limit: Limit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> GetComplianceDetailsByConfigRuleResponse:
        raise NotImplementedError

    @handler("GetComplianceDetailsByResource")
    def get_compliance_details_by_resource(
        self,
        context: RequestContext,
        resource_type: StringWithCharLimit256 = None,
        resource_id: BaseResourceId = None,
        compliance_types: ComplianceTypes = None,
        next_token: String = None,
        resource_evaluation_id: ResourceEvaluationId = None,
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
        self, context: RequestContext, resource_types: ResourceTypes = None, **kwargs
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
        **kwargs,
    ) -> GetConformancePackComplianceDetailsResponse:
        raise NotImplementedError

    @handler("GetConformancePackComplianceSummary")
    def get_conformance_pack_compliance_summary(
        self,
        context: RequestContext,
        conformance_pack_names: ConformancePackNamesToSummarizeList,
        limit: PageSizeLimit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> GetConformancePackComplianceSummaryResponse:
        raise NotImplementedError

    @handler("GetCustomRulePolicy")
    def get_custom_rule_policy(
        self, context: RequestContext, config_rule_name: ConfigRuleName = None, **kwargs
    ) -> GetCustomRulePolicyResponse:
        raise NotImplementedError

    @handler("GetDiscoveredResourceCounts")
    def get_discovered_resource_counts(
        self,
        context: RequestContext,
        resource_types: ResourceTypes = None,
        limit: Limit = None,
        next_token: NextToken = None,
        **kwargs,
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
        **kwargs,
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
        later_time: LaterTime = None,
        earlier_time: EarlierTime = None,
        chronological_order: ChronologicalOrder = None,
        limit: Limit = None,
        next_token: NextToken = None,
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
        filters: ResourceFilters = None,
        limit: Limit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListAggregateDiscoveredResourcesResponse:
        raise NotImplementedError

    @handler("ListConformancePackComplianceScores")
    def list_conformance_pack_compliance_scores(
        self,
        context: RequestContext,
        filters: ConformancePackComplianceScoresFilters = None,
        sort_order: SortOrder = None,
        sort_by: SortBy = None,
        limit: PageSizeLimit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListConformancePackComplianceScoresResponse:
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
        **kwargs,
    ) -> ListDiscoveredResourcesResponse:
        raise NotImplementedError

    @handler("ListResourceEvaluations")
    def list_resource_evaluations(
        self,
        context: RequestContext,
        filters: ResourceEvaluationFilters = None,
        limit: ListResourceEvaluationsPageItemLimit = None,
        next_token: String = None,
        **kwargs,
    ) -> ListResourceEvaluationsResponse:
        raise NotImplementedError

    @handler("ListStoredQueries")
    def list_stored_queries(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: Limit = None,
        **kwargs,
    ) -> ListStoredQueriesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        limit: Limit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("PutAggregationAuthorization")
    def put_aggregation_authorization(
        self,
        context: RequestContext,
        authorized_account_id: AccountId,
        authorized_aws_region: AwsRegion,
        tags: TagsList = None,
        **kwargs,
    ) -> PutAggregationAuthorizationResponse:
        raise NotImplementedError

    @handler("PutConfigRule")
    def put_config_rule(
        self, context: RequestContext, config_rule: ConfigRule, tags: TagsList = None, **kwargs
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
        **kwargs,
    ) -> PutConfigurationAggregatorResponse:
        raise NotImplementedError

    @handler("PutConfigurationRecorder")
    def put_configuration_recorder(
        self, context: RequestContext, configuration_recorder: ConfigurationRecorder, **kwargs
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
        template_ssm_document_details: TemplateSSMDocumentDetails = None,
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
        evaluations: Evaluations = None,
        test_mode: Boolean = None,
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
        organization_managed_rule_metadata: OrganizationManagedRuleMetadata = None,
        organization_custom_rule_metadata: OrganizationCustomRuleMetadata = None,
        excluded_accounts: ExcludedAccounts = None,
        organization_custom_policy_rule_metadata: OrganizationCustomPolicyRuleMetadata = None,
        **kwargs,
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
        message: StringWithCharLimit1024 = None,
        expiration_time: Date = None,
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
        resource_name: ResourceName = None,
        tags: Tags = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("PutRetentionConfiguration")
    def put_retention_configuration(
        self, context: RequestContext, retention_period_in_days: RetentionPeriodInDays, **kwargs
    ) -> PutRetentionConfigurationResponse:
        raise NotImplementedError

    @handler("PutStoredQuery")
    def put_stored_query(
        self, context: RequestContext, stored_query: StoredQuery, tags: TagsList = None, **kwargs
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
        **kwargs,
    ) -> SelectAggregateResourceConfigResponse:
        raise NotImplementedError

    @handler("SelectResourceConfig")
    def select_resource_config(
        self,
        context: RequestContext,
        expression: Expression,
        limit: Limit = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> SelectResourceConfigResponse:
        raise NotImplementedError

    @handler("StartConfigRulesEvaluation")
    def start_config_rules_evaluation(
        self, context: RequestContext, config_rule_names: ReevaluateConfigRuleNames = None, **kwargs
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
        evaluation_context: EvaluationContext = None,
        evaluation_timeout: EvaluationTimeout = None,
        client_token: ClientToken = None,
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
