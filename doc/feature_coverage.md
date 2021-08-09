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
  <tr><td>Event Selectors</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Insight Selectors</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Trails</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Start/Stop Logging</td><td>⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>CloudWatch</b></td></tr>
  <tr><td>Alarms</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>Alarm Histories</td><td>-</td><td></td><td></td></tr>
  <tr><td>Anomaly Detectors</td><td>-</td><td></td><td></td></tr>
  <tr><td>Dashboards</td><td>-</td><td></td><td></td></tr>
  <tr><td>Insight Rules</td><td>-</td><td></td><td></td></tr>
  <tr><td>Metric Data</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Metric Statistics</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Metric Streams</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>CloudWatch Logs</b></td></tr>
  <tr><td>Destinations</td><td>...</td><td></td><td></td></tr>
  <tr><td>Export Tasks</td><td>...</td><td></td><td></td></tr>
  <tr><td>Log Events</td><td>...</td><td></td><td></td></tr>
  <tr><td>Log Groups</td><td>...</td><td></td><td></td></tr>
  <tr><td>Log Streams</td><td>...</td><td></td><td></td></tr>
  <tr><td>Metric Filters</td><td>...</td><td></td><td></td></tr>
  <tr><td>Queries</td><td>...</td><td></td><td></td></tr>
  <tr><td>Query Definitions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Resource Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Retention Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Subscription Filters</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>CodeCommit</b> (Pro)</td></tr>
  <tr><td>Approval Rules</td><td>...</td><td></td><td></td></tr>
  <tr><td>Blobs / Files / Folders</td><td>...</td><td></td><td></td></tr>
  <tr><td>Branches</td><td>...</td><td></td><td></td></tr>
  <tr><td>Comments</td><td>...</td><td></td><td></td></tr>
  <tr><td>Commits</td><td>...</td><td></td><td></td></tr>
  <tr><td>Merge Commits / Conflicts</td><td>...</td><td></td><td></td></tr>
  <tr><td>Pull Requests</td><td>...</td><td></td><td></td></tr>
  <tr><td>Repositories</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Cognito Identity</b> (Pro)</td></tr>
  <tr><td>Developer Identities</td><td>-</td><td></td><td></td></tr>
  <tr><td>Identities</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Identity Pool Roles</td><td>-</td><td></td><td></td></tr>
  <tr><td>Identity Pools</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>OpenID Tokens</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>-</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Cognito Identity Provider (IdP)</b> (Pro)</td></tr>
  <tr><td>Admin APIs</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Devices</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>Auth Flows</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Groups</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Lambda Triggers</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>MFA Configs</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Resource Servers</td><td>-</td><td></td><td></td></tr>
  <tr><td>Risk Configurations</td><td>-</td><td></td><td></td></tr>
  <tr><td>Identity Providers</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>User Import Jobs</td><td>-</td><td></td><td></td></tr>
  <tr><td>User Pool Clients</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>User Pool Domains</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>User Pools</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Users</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>DynamoDB</b></td></tr>
  <tr><td>Backups (Pro)</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Batch Operations</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Global Tables</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Items</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Kinesis Streaming Destinations</td><td>-</td><td></td><td></td></tr>
  <tr><td>PartiQL Queries</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Query / Scan Operations</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tables</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Table Replica Autoscaling</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>DynamoDB Streams</b></td></tr>
  <tr><td>Records</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Shard Iterators</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Streams</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>EC2</b></td></tr>
  <tr><td>Classic Links</td><td>...</td><td></td><td></td></tr>
  <tr><td>Customer Gateways</td><td>...</td><td></td><td></td></tr>
  <tr><td>DHCP Options</td><td>...</td><td></td><td></td></tr>
  <tr><td>Allocate/Deallocate Elastic IPs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Fleets</td><td>-</td><td></td><td></td></tr>
  <tr><td>Flow Logs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Images</td><td>...</td><td></td><td></td></tr>
  <tr><td>Internet Gateways</td><td>...</td><td></td><td></td></tr>
  <tr><td>Local Gateway Routes</td><td>...</td><td></td><td></td></tr>
  <tr><td>Key Pairs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Launch Templates</td><td>...</td><td></td><td></td></tr>
  <tr><td>NAT Gateways</td><td>...</td><td></td><td></td></tr>
  <tr><td>Network ACLs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Network Interfaces</td><td>...</td><td></td><td></td></tr>
  <tr><td>Reserved Instances</td><td>...</td><td></td><td></td></tr>
  <tr><td>Route Tables / Routes</td><td>...</td><td></td><td></td></tr>
  <tr><td>Scheduled Instances</td><td>...</td><td></td><td></td></tr>
  <tr><td>Security Groups / Egress / Ingress</td><td>...</td><td></td><td></td></tr>
  <tr><td>Snapshots</td><td>...</td><td></td><td></td></tr>
  <tr><td>Spot Instances</td><td>...</td><td></td><td></td></tr>
  <tr><td>Start Instances as VMs (Pro)</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>Subnets</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Traffic Mirrors</td><td>...</td><td></td><td></td></tr>
  <tr><td>Transit Gateways</td><td>...</td><td></td><td></td></tr>
  <tr><td>Volumes</td><td>...</td><td></td><td></td></tr>
  <tr><td>VPC Endpoint Connections</td><td>...</td><td></td><td></td></tr>
  <tr><td>VPC Peering Connections</td><td>...</td><td></td><td></td></tr>
  <tr><td>VPCs</td><td>...</td><td></td><td></td></tr>
  <tr><td>VPN Gateways / Connections</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>ECR</b> (Pro)</td></tr>
  <tr><td>Images</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Image Scans</td><td>-</td><td></td><td></td></tr>
  <tr><td>Lifecycle Policies</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Registries</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Registry Policies</td><td>-</td><td></td><td></td></tr>
  <tr><td>Replication Configurations</td><td>-</td><td></td><td></td></tr>
  <tr><td>Repositories</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Repository Policies</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>ECS</b> (Pro)</td></tr>
  <tr><td>Account Settings</td><td>-</td><td></td><td></td></tr>
  <tr><td>Attributes</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Capacity Providers</td><td>-</td><td></td><td></td></tr>
  <tr><td>Clusters</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Container Instances</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Services</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Task Definitions</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Task Sets</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tasks</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>EKS</b> (Pro)</td></tr>
  <tr><td>AddOns</td><td>-</td><td></td><td></td></tr>
  <tr><td>Clusters</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Fargate Profiles</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>Identity Provider Configs</td><td>-</td><td></td><td></td></tr>
  <tr><td>Node Groups</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Updates</td><td>-</td><td></td><td></td></tr>

  <tr><td colspan=4><b>ElastiCache</b> (Pro)</td></tr>
  <tr><td>Cache Clusters (Redis)</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Cache Clusters (Memcached)</td><td>-</td><td></td><td></td></tr>
  <tr><td>Cache Parameter Groups</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Cache Security Groups</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Cache Subnet Groups</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Global Replication Groups</td><td>-</td><td></td><td></td></tr>
  <tr><td>Replication Groups</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Snapshots</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Users / User Groups</td><td>-</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Elasticsearch Service</b></td></tr>
  <tr><td>Cross-Cluster Search Connections</td><td>-</td><td></td><td></td></tr>
  <tr><td>Elasticsearch Domains</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Packages</td><td>-</td><td></td><td></td></tr>
  <tr><td>Reserved Instances</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>EMR</b> (Pro)</td></tr>
  <tr><td>Clusters</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Instance Fleets</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Job Flow Steps</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Managed Scaling Policies</td><td>-</td><td></td><td></td></tr>
  <tr><td>Notebook Executions</td><td>-</td><td></td><td></td></tr>
  <tr><td>Run Job Flows (Queries)</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Security Configurations</td><td>-</td><td></td><td></td></tr>
  <tr><td>Studios</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>EventBridge (CloudWatch Events)</b></td></tr>
  <tr><td>API Destinations</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Archives</td><td>-</td><td></td><td></td></tr>
  <tr><td>Connections</td><td>-</td><td></td><td></td></tr>
  <tr><td>Event Buses</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Event Sources</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Partner Event Sources</td><td>-</td><td></td><td></td></tr>
  <tr><td>Replays</td><td>-</td><td></td><td></td></tr>
  <tr><td>Rules</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Firehose</b></td></tr>
  <tr><td>Delivery Streams</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Destinations</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Records</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Glue</b> (Pro)</td></tr>
  <tr><td>Classifiers</td><td>...</td><td></td><td></td></tr>
  <tr><td>Connections</td><td>...</td><td></td><td></td></tr>
  <tr><td>Crawlers</td><td>...</td><td></td><td></td></tr>
  <tr><td>Databases</td><td>...</td><td></td><td></td></tr>
  <tr><td>Dev Endpoints</td><td>...</td><td></td><td></td></tr>
  <tr><td>Jobs</td><td>...</td><td></td><td></td></tr>
  <tr><td>ML Transforms</td><td>...</td><td></td><td></td></tr>
  <tr><td>Partitions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Registries</td><td>...</td><td></td><td></td></tr>
  <tr><td>Schemas</td><td>...</td><td></td><td></td></tr>
  <tr><td>Scripts</td><td>...</td><td></td><td></td></tr>
  <tr><td>Security Configurations</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tables</td><td>...</td><td></td><td></td></tr>
  <tr><td>Triggers</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  <tr><td>User Defined Functions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Workflows</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>IAM</b></td></tr>
  <tr><td>Access Keys</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Account Aliases</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Credential Reports</td><td>-</td><td></td><td></td></tr>
  <tr><td>Groups</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Instance Profiles</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Login Profiles</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>OIDC Providers</td><td>-</td><td></td><td></td></tr>
  <tr><td>Policies</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Roles</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>SAML Providers</td><td>-</td><td></td><td></td></tr>
  <tr><td>Server Certificates</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Service Linked Roles</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Users</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Virtual MFA Devices</td><td>⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>IoT (IoT Analytics, IoT Data)</b> (Pro)</td></tr>
  <tr><td>Authorizers</td><td>...</td><td></td><td></td></tr>
  <tr><td>Billing Groups</td><td>...</td><td></td><td></td></tr>
  <tr><td>Certificates</td><td>...</td><td></td><td></td></tr>
  <tr><td>Custom Metrics</td><td>...</td><td></td><td></td></tr>
  <tr><td>Dimensions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Domain Configurations</td><td>...</td><td></td><td></td></tr>
  <tr><td>Jobs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Jobs Executions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Jobs Templates</td><td>...</td><td></td><td></td></tr>
  <tr><td>Mitigation Actions</td><td>...</td><td></td><td></td></tr>
  <tr><td>Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Provisioning Claims / Templates</td><td>...</td><td></td><td></td></tr>
  <tr><td>Role Aliases</td><td>...</td><td></td><td></td></tr>
  <tr><td>Security Profiles</td><td>...</td><td></td><td></td></tr>
  <tr><td>Streams</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>
  <tr><td>Thing Groups</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Thing Types</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Things</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Topic Rules</td><td>⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Kinesis</b></td></tr>
  <tr><td>Records</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Split / Merge Shards</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Stream Consumers</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Stream Encryption</td><td>-</td><td></td><td></td></tr>
  <tr><td>Streams</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Subscribe to Shard</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>KMS</b></td></tr>
  <tr><td>Aliases</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Custom Key Stores</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Encrypt / Decrypt / Sign Data</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Grants</td><td>...</td><td></td><td></td></tr>
  <tr><td>Key Policies</td><td>-</td><td></td><td></td></tr>
  <tr><td>Keys</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Lambda</b></td></tr>
  <tr><td>Aliases</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Code Signing Configs</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>Event Invoke Configs</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Event Source Mappings</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Function Concurrencies</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Functions</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Invoke Functions</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Layers (Pro)</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Permissions</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Managed Streaming for Kafka (MSK)</b> (Pro)</td></tr>
  <tr><td>Brokers</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>Cluster Operations</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>Clusters</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Configurations</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

  <tr><td colspan=4><b>MediaStore</b> (Pro)</td></tr>
  <tr><td>Access Logging</td><td>...</td><td></td><td></td></tr>
  <tr><td>Container Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Containers</td><td>...</td><td></td><td></td></tr>
  <tr><td>CORS Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Lifecycle Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Metric Policies</td><td>...</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>...</td><td></td><td></td></tr>

  <tr><td colspan=4><b>Neptune DB</b> (Pro)</td></tr>
  <tr><td>DB Clusters</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>DB Cluster Endpoints</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>DB Cluster Parameter Groups</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>DB Cluster Snapshots</td><td>-</td><td></td><td></td></tr>
  <tr><td>Engine Default Parameters</td><td>⭐⭐</td><td></td><td></td></tr>
  <tr><td>Event Subscriptions</td><td>-</td><td></td><td></td></tr>
  <tr><td>Events</td><td>-</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>-</td><td></td><td></td></tr>

  <tr><td colspan=4><b>QLDB</b> (Pro)</td></tr>
  <tr><td>Blocks</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Digests</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Journal Kinesis Streams</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Journal S3 Exports</td><td>⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Ledgers</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Send Commands / Run Queries</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>
  <tr><td>Tags</td><td>⭐⭐⭐⭐</td><td></td><td></td></tr>

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
