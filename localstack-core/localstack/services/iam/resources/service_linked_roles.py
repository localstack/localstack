SERVICE_LINKED_ROLES = {
    "accountdiscovery.ssm.amazonaws.com": {
        "service": "accountdiscovery.ssm.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonSSM_AccountDiscovery",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSSystemsManagerAccountDiscoveryServicePolicy"
        ],
        "suffix_allowed": False,
    },
    "acm.amazonaws.com": {
        "service": "acm.amazonaws.com",
        "role_name": "AWSServiceRoleForCertificateManager",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/CertificateManagerServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "appmesh.amazonaws.com": {
        "service": "appmesh.amazonaws.com",
        "role_name": "AWSServiceRoleForAppMesh",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSAppMeshServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "autoscaling-plans.amazonaws.com": {
        "service": "autoscaling-plans.amazonaws.com",
        "role_name": "AWSServiceRoleForAutoScalingPlans_EC2AutoScaling",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSAutoScalingPlansEC2AutoScalingPolicy"
        ],
        "suffix_allowed": False,
    },
    "autoscaling.amazonaws.com": {
        "service": "autoscaling.amazonaws.com",
        "role_name": "AWSServiceRoleForAutoScaling",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AutoScalingServiceRolePolicy"
        ],
        "suffix_allowed": True,
    },
    "backup.amazonaws.com": {
        "service": "backup.amazonaws.com",
        "role_name": "AWSServiceRoleForBackup",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSBackupServiceLinkedRolePolicyForBackup"
        ],
        "suffix_allowed": False,
    },
    "batch.amazonaws.com": {
        "service": "batch.amazonaws.com",
        "role_name": "AWSServiceRoleForBatch",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/BatchServiceRolePolicy"],
        "suffix_allowed": False,
    },
    "cassandra.application-autoscaling.amazonaws.com": {
        "service": "cassandra.application-autoscaling.amazonaws.com",
        "role_name": "AWSServiceRoleForApplicationAutoScaling_CassandraTable",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSApplicationAutoscalingCassandraTablePolicy"
        ],
        "suffix_allowed": False,
    },
    "cks.kms.amazonaws.com": {
        "service": "cks.kms.amazonaws.com",
        "role_name": "AWSServiceRoleForKeyManagementServiceCustomKeyStores",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSKeyManagementServiceCustomKeyStoresServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "cloudtrail.amazonaws.com": {
        "service": "cloudtrail.amazonaws.com",
        "role_name": "AWSServiceRoleForCloudTrail",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/CloudTrailServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "codestar-notifications.amazonaws.com": {
        "service": "codestar-notifications.amazonaws.com",
        "role_name": "AWSServiceRoleForCodeStarNotifications",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSCodeStarNotificationsServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "config.amazonaws.com": {
        "service": "config.amazonaws.com",
        "role_name": "AWSServiceRoleForConfig",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSConfigServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "connect.amazonaws.com": {
        "service": "connect.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonConnect",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonConnectServiceLinkedRolePolicy"
        ],
        "suffix_allowed": True,
    },
    "dms-fleet-advisor.amazonaws.com": {
        "service": "dms-fleet-advisor.amazonaws.com",
        "role_name": "AWSServiceRoleForDMSFleetAdvisor",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSDMSFleetAdvisorServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "dms.amazonaws.com": {
        "service": "dms.amazonaws.com",
        "role_name": "AWSServiceRoleForDMSServerless",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSDMSServerlessServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "docdb-elastic.amazonaws.com": {
        "service": "docdb-elastic.amazonaws.com",
        "role_name": "AWSServiceRoleForDocDB-Elastic",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonDocDB-ElasticServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "ec2-instance-connect.amazonaws.com": {
        "service": "ec2-instance-connect.amazonaws.com",
        "role_name": "AWSServiceRoleForEc2InstanceConnect",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/Ec2InstanceConnectEndpoint"
        ],
        "suffix_allowed": False,
    },
    "ec2.application-autoscaling.amazonaws.com": {
        "service": "ec2.application-autoscaling.amazonaws.com",
        "role_name": "AWSServiceRoleForApplicationAutoScaling_EC2SpotFleetRequest",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSApplicationAutoscalingEC2SpotFleetRequestPolicy"
        ],
        "suffix_allowed": False,
    },
    "ecr.amazonaws.com": {
        "service": "ecr.amazonaws.com",
        "role_name": "AWSServiceRoleForECRTemplate",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/ECRTemplateServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "ecs.amazonaws.com": {
        "service": "ecs.amazonaws.com",
        "role_name": "AWSServiceRoleForECS",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonECSServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "eks-connector.amazonaws.com": {
        "service": "eks-connector.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonEKSConnector",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonEKSConnectorServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "eks-fargate.amazonaws.com": {
        "service": "eks-fargate.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonEKSForFargate",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonEKSForFargateServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "eks-nodegroup.amazonaws.com": {
        "service": "eks-nodegroup.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonEKSNodegroup",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSServiceRoleForAmazonEKSNodegroup"
        ],
        "suffix_allowed": False,
    },
    "eks.amazonaws.com": {
        "service": "eks.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonEKS",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonEKSServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "elasticache.amazonaws.com": {
        "service": "elasticache.amazonaws.com",
        "role_name": "AWSServiceRoleForElastiCache",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/ElastiCacheServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "elasticbeanstalk.amazonaws.com": {
        "service": "elasticbeanstalk.amazonaws.com",
        "role_name": "AWSServiceRoleForElasticBeanstalk",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSElasticBeanstalkServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "elasticfilesystem.amazonaws.com": {
        "service": "elasticfilesystem.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonElasticFileSystem",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonElasticFileSystemServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "elasticloadbalancing.amazonaws.com": {
        "service": "elasticloadbalancing.amazonaws.com",
        "role_name": "AWSServiceRoleForElasticLoadBalancing",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSElasticLoadBalancingServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "email.cognito-idp.amazonaws.com": {
        "service": "email.cognito-idp.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonCognitoIdpEmailService",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonCognitoIdpEmailServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "emr-containers.amazonaws.com": {
        "service": "emr-containers.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonEMRContainers",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonEMRContainersServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "emrwal.amazonaws.com": {
        "service": "emrwal.amazonaws.com",
        "role_name": "AWSServiceRoleForEMRWAL",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/EMRDescribeClusterPolicyForEMRWAL"
        ],
        "suffix_allowed": False,
    },
    "fis.amazonaws.com": {
        "service": "fis.amazonaws.com",
        "role_name": "AWSServiceRoleForFIS",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonFISServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "grafana.amazonaws.com": {
        "service": "grafana.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonGrafana",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonGrafanaServiceLinkedRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "imagebuilder.amazonaws.com": {
        "service": "imagebuilder.amazonaws.com",
        "role_name": "AWSServiceRoleForImageBuilder",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSServiceRoleForImageBuilder"
        ],
        "suffix_allowed": False,
    },
    "iotmanagedintegrations.amazonaws.com": {
        "service": "iotmanagedintegrations.amazonaws.com",
        "role_name": "AWSServiceRoleForIoTManagedIntegrations",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSIoTManagedIntegrationsRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "kafka.amazonaws.com": {
        "service": "kafka.amazonaws.com",
        "role_name": "AWSServiceRoleForKafka",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/KafkaServiceRolePolicy"],
        "suffix_allowed": False,
    },
    "kafkaconnect.amazonaws.com": {
        "service": "kafkaconnect.amazonaws.com",
        "role_name": "AWSServiceRoleForKafkaConnect",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/KafkaConnectServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "lakeformation.amazonaws.com": {
        "service": "lakeformation.amazonaws.com",
        "role_name": "AWSServiceRoleForLakeFormationDataAccess",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/LakeFormationDataAccessServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "lex.amazonaws.com": {
        "service": "lex.amazonaws.com",
        "role_name": "AWSServiceRoleForLexBots",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/AmazonLexBotPolicy"],
        "suffix_allowed": False,
    },
    "lexv2.amazonaws.com": {
        "service": "lexv2.amazonaws.com",
        "role_name": "AWSServiceRoleForLexV2Bots",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/AmazonLexV2BotPolicy"],
        "suffix_allowed": True,
    },
    "lightsail.amazonaws.com": {
        "service": "lightsail.amazonaws.com",
        "role_name": "AWSServiceRoleForLightsail",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/LightsailExportAccess"],
        "suffix_allowed": False,
    },
    "m2.amazonaws.com": {
        "service": "m2.amazonaws.com",
        "role_name": "AWSServiceRoleForAWSM2",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/AWSM2ServicePolicy"],
        "suffix_allowed": False,
    },
    "memorydb.amazonaws.com": {
        "service": "memorydb.amazonaws.com",
        "role_name": "AWSServiceRoleForMemoryDB",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/MemoryDBServiceRolePolicy"],
        "suffix_allowed": False,
    },
    "mq.amazonaws.com": {
        "service": "mq.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonMQ",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/AmazonMQServiceRolePolicy"],
        "suffix_allowed": False,
    },
    "mrk.kms.amazonaws.com": {
        "service": "mrk.kms.amazonaws.com",
        "role_name": "AWSServiceRoleForKeyManagementServiceMultiRegionKeys",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSKeyManagementServiceMultiRegionKeysServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "notifications.amazonaws.com": {
        "service": "notifications.amazonaws.com",
        "role_name": "AWSServiceRoleForAwsUserNotifications",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSUserNotificationsServiceLinkedRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "observability.aoss.amazonaws.com": {
        "service": "observability.aoss.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonOpenSearchServerless",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonOpenSearchServerlessServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "opensearchservice.amazonaws.com": {
        "service": "opensearchservice.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonOpenSearchService",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonOpenSearchServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "ops.apigateway.amazonaws.com": {
        "service": "ops.apigateway.amazonaws.com",
        "role_name": "AWSServiceRoleForAPIGateway",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/APIGatewayServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "ops.emr-serverless.amazonaws.com": {
        "service": "ops.emr-serverless.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonEMRServerless",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonEMRServerlessServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "opsdatasync.ssm.amazonaws.com": {
        "service": "opsdatasync.ssm.amazonaws.com",
        "role_name": "AWSServiceRoleForSystemsManagerOpsDataSync",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSSystemsManagerOpsDataSyncServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "opsinsights.ssm.amazonaws.com": {
        "service": "opsinsights.ssm.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonSSM_OpsInsights",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSSSMOpsInsightsServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "pullthroughcache.ecr.amazonaws.com": {
        "service": "pullthroughcache.ecr.amazonaws.com",
        "role_name": "AWSServiceRoleForECRPullThroughCache",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSECRPullThroughCache_ServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "ram.amazonaws.com": {
        "service": "ram.amazonaws.com",
        "role_name": "AWSServiceRoleForResourceAccessManager",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSResourceAccessManagerServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "rds.amazonaws.com": {
        "service": "rds.amazonaws.com",
        "role_name": "AWSServiceRoleForRDS",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonRDSServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "redshift.amazonaws.com": {
        "service": "redshift.amazonaws.com",
        "role_name": "AWSServiceRoleForRedshift",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonRedshiftServiceLinkedRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "replication.cassandra.amazonaws.com": {
        "service": "replication.cassandra.amazonaws.com",
        "role_name": "AWSServiceRoleForKeyspacesReplication",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/KeyspacesReplicationServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "replication.ecr.amazonaws.com": {
        "service": "replication.ecr.amazonaws.com",
        "role_name": "AWSServiceRoleForECRReplication",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/ECRReplicationServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "repository.sync.codeconnections.amazonaws.com": {
        "service": "repository.sync.codeconnections.amazonaws.com",
        "role_name": "AWSServiceRoleForGitSync",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSGitSyncServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "resource-explorer-2.amazonaws.com": {
        "service": "resource-explorer-2.amazonaws.com",
        "role_name": "AWSServiceRoleForResourceExplorer",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSResourceExplorerServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "rolesanywhere.amazonaws.com": {
        "service": "rolesanywhere.amazonaws.com",
        "role_name": "AWSServiceRoleForRolesAnywhere",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSRolesAnywhereServicePolicy"
        ],
        "suffix_allowed": False,
    },
    "s3-outposts.amazonaws.com": {
        "service": "s3-outposts.amazonaws.com",
        "role_name": "AWSServiceRoleForS3OnOutposts",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSS3OnOutpostsServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "ses.amazonaws.com": {
        "service": "ses.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonSES",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonSESServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "shield.amazonaws.com": {
        "service": "shield.amazonaws.com",
        "role_name": "AWSServiceRoleForAWSShield",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSShieldServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "ssm-incidents.amazonaws.com": {
        "service": "ssm-incidents.amazonaws.com",
        "role_name": "AWSServiceRoleForIncidentManager",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSIncidentManagerServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "ssm-quicksetup.amazonaws.com": {
        "service": "ssm-quicksetup.amazonaws.com",
        "role_name": "AWSServiceRoleForSSMQuickSetup",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/SSMQuickSetupRolePolicy"],
        "suffix_allowed": False,
    },
    "ssm.amazonaws.com": {
        "service": "ssm.amazonaws.com",
        "role_name": "AWSServiceRoleForAmazonSSM",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AmazonSSMServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "sso.amazonaws.com": {
        "service": "sso.amazonaws.com",
        "role_name": "AWSServiceRoleForSSO",
        "attached_policies": ["arn:aws:iam::aws:policy/aws-service-role/AWSSSOServiceRolePolicy"],
        "suffix_allowed": False,
    },
    "vpcorigin.cloudfront.amazonaws.com": {
        "service": "vpcorigin.cloudfront.amazonaws.com",
        "role_name": "AWSServiceRoleForCloudFrontVPCOrigin",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/AWSCloudFrontVPCOriginServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "waf.amazonaws.com": {
        "service": "waf.amazonaws.com",
        "role_name": "AWSServiceRoleForWAFLogging",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/WAFLoggingServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
    "wafv2.amazonaws.com": {
        "service": "wafv2.amazonaws.com",
        "role_name": "AWSServiceRoleForWAFV2Logging",
        "attached_policies": [
            "arn:aws:iam::aws:policy/aws-service-role/WAFV2LoggingServiceRolePolicy"
        ],
        "suffix_allowed": False,
    },
}
