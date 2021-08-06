# LocalStack Feature Coverage

This page summarizes the implemented APIs and features provided by LocalStack, as well as their level of parity with the real cloud (e.g., AWS) or managed service provider.

## Support Tiers

LocalStack provides a variety of different features and cloud APIs (e.g., AWS), but the level of support and parity with the real system differs for the different services:

* **Tier 1 (⭐⭐⭐⭐)**: Feature fully supported by LocalStack maintainers; feature is guaranteed to pass all or the majority of tests
* **Tier 2 (⭐⭐⭐)**: Feature supports the majority of use cases (e.g., CRUD operations), but some advanced usages may not be fully supported
* **Tier 3 (⭐⭐)**: Feature may be lightly tested (or not), and so it should be considered unstable
* **Tier 4 (⭐)**: Feature is experimental, only partially supported or implemented
* **Tier 5 (-)**: Feature is not currently implemented, but on our roadmap

In the coverage tables below, the features are marked with their respective availability across different LocalStack versions:

* Community version (default, if not marked)
* Pro version (marked with "Pro")
* Enterprise version (marked with "Enterprise")

## AWS Feature Coverage

<table>
  <tr><th>Service / Feature</th><th>Coverage Level</th><th>Terraform Tests</th><th>Notes</th></tr>
  <tr><td colspan=4><b>ACM</b></td></tr>
  <tr><td>Certificates</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  <tr><td>Account Configuration</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Amplify</b> (Pro)</td></tr>
  <tr><td>Apps</td><td>...</td><td></td><td></td></tr>
  <tr><td>Backend Environments</td><td>...</td><td></td><td></td></tr>
  <tr><td>Branches</td><td>...</td><td></td><td></td></tr>
  <tr><td>Deployments</td><td>...</td><td></td><td></td></tr>
  <tr><td>Domain Associations</td><td>...</td><td></td><td></td></tr>
  <tr><td>Jobs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  <tr><td>Webhooks</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>API Gateway</b></td></tr>
  <tr><td>API Keys</td><td>...</td><td></td><td></td></tr>
  <tr><td>Authorizer</td><td>...</td><td></td><td></td></tr>
  <tr><td>Base Path Mappings</td><td>...</td><td></td><td></td></tr>
  <tr><td>Deployments</td><td>...</td><td></td><td></td></tr>
  <tr><td>Documentation Parts</td><td>...</td><td></td><td></td></tr>
  <tr><td>Documentation Versions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Domain Names</td><td>...</td><td></td><td></td></tr>
  <tr><td>Gateway / Integration / Method Responses</td><td>...</td><td></td><td></td></tr>
  <tr><td>Integrations</td><td>...</td><td></td><td></td></tr>
  <tr><td>Methods</td><td>...</td><td></td><td></td></tr>
  <tr><td>Models</td><td>...</td><td></td><td></td></tr>
  <tr><td>Request Validators</td><td>...</td><td></td><td></td></tr>
  <tr><td>Request Validators</td><td>...</td><td></td><td></td></tr>
  <tr><td>Resources</td><td>...</td><td></td><td></td></tr>
  <tr><td>REST APIs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stages</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  <tr><td>Usage Plans</td><td>...</td><td></td><td></td></tr>
  <tr><td>Usage Plan Keys</td><td>...</td><td></td><td></td></tr>
  <tr><td>VPC Links</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>API Gateway v2</b> (Pro)</td></tr>
  <tr><td>APIs</td><td>...</td><td></td><td></td></tr>
  <tr><td>API Mappings</td><td>...</td><td></td><td></td></tr>
  <tr><td>Authorizers</td><td>...</td><td></td><td></td></tr>
  <tr><td>Deployments</td><td>...</td><td></td><td></td></tr>
  <tr><td>Domain Names</td><td>...</td><td></td><td></td></tr>
  <tr><td>Import APIs from OpenAPI specs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Integrations</td><td>...</td><td></td><td></td></tr>
  <tr><td>Integration Responses</td><td>...</td><td></td><td></td></tr>
  <tr><td>Models</td><td>...</td><td></td><td></td></tr>
  <tr><td>Routes</td><td>...</td><td></td><td></td></tr>
  <tr><td>Route Responses</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stages</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  <tr><td>VPC Links</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>AppSync</b> (Pro)</td></tr>
  <tr><td>API Caches</td><td>...</td><td></td><td></td></tr>
  <tr><td>API Keys</td><td>...</td><td></td><td></td></tr>
  <tr><td>Data Sources</td><td>...</td><td></td><td></td></tr>
  <tr><td>Functions</td><td>...</td><td></td><td></td></tr>
  <tr><td>GraphQL APIs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Resolvers</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  <tr><td>Types</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Athena</b> (Pro)</td></tr>
  <tr><td>Data Catalogs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Databases</td><td>...</td><td></td><td></td></tr>
  <tr><td>Named Queries</td><td>...</td><td></td><td></td></tr>
  <tr><td>Prepared Statements</td><td>...</td><td></td><td></td></tr>
  <tr><td>Query Executions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Table Metadata</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  <tr><td>Work Groups</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Backup</b> (Pro)</td></tr>
  <tr><td>Backup Jobs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Backup Plans</td><td>...</td><td></td><td></td></tr>
  <tr><td>Backup Selections</td><td>...</td><td></td><td></td></tr>
  <tr><td>Backup Vaults</td><td>...</td><td></td><td></td></tr>
  <tr><td>Backup Vault Access Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Backup Vault Notifications</td><td>...</td><td></td><td></td></tr>
  <tr><td>Global Settings</td><td>...</td><td></td><td></td></tr>
  <tr><td>Protected Resources</td><td>...</td><td></td><td></td></tr>
  <tr><td>Recovery Points</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Batch</b> (Pro)</td></tr>
  <tr><td>Compute Environments</td><td>...</td><td></td><td></td></tr>
  <tr><td>Job Queues</td><td>...</td><td></td><td></td></tr>
  <tr><td>Job Definitions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Jobs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>CloudFormation</b></td></tr>
  <tr><td>Change Sets</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stacks</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stack Drifts</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stack Events</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stack Instances</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stack Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stack Resources</td><td>...</td><td></td><td></td></tr>
  <tr><td>Stack Sets</td><td>...</td><td></td><td></td></tr>
  <tr><td>Publishers</td><td>...</td><td></td><td></td></tr>
  <tr><td>Templates</td><td>...</td><td></td><td></td></tr>
  <tr><td>Type Activations</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>CloudFront</b> (Pro)</td></tr>
  <tr><td>Cache Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Distributions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Field Level Encryption</td><td>...</td><td></td><td></td></tr>
  <tr><td>Functions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Invalidations</td><td>...</td><td></td><td></td></tr>
  <tr><td>Key Groups</td><td>...</td><td></td><td></td></tr>
  <tr><td>Monitoring Subscriptions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Origin Access Identities</td><td>...</td><td></td><td></td></tr>
  <tr><td>Origin Request Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Public Keys</td><td>...</td><td></td><td></td></tr>
  <tr><td>Realtime Log Configs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Streaming Distributions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>CloudTrail</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>CloudWatch</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>CloudWatch Logs</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>CodeCommit</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Cognito Identity</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Cognito Identity Provider (IdP)</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>DynamoDB</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>DynamoDB Streams</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>EC2</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>ECR</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>ECS</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>EKS</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>ElastiCache</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Elasticsearch Service</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>EMR</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>EventBridge (CloudWatch Events)</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>Firehose</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>Glue</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>IAM</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>IoT (IoT Analytics, IoT Data)</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Kinesis</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>KMS</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>Lambda</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>Managed Streaming for Kafka (MSK)</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>MediaStore</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Neptune DB</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>QLDB</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>RDS / Aurora Serverless</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Redshift</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
      
  <tr><td colspan=4><b>Route53</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>S3</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>SageMaker</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>SecretsManager</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>SES</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>SNS</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>SQS</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>SSM</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>StepFunctions</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>STS</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
     
  <tr><td colspan=4><b>Timestream</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Transfer</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>XRay</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
</table>

## API Persistence Coverage

Details following soon.
