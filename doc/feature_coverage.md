# LocalStack Feature Coverage

This page summarizes the implemented APIs and features provided by LocalStack, as well as their level of parity with the real cloud (e.g., AWS).

## AWS Feature Coverage

<table>
  <tr><th>Service / Feature</th><th>Coverage Level</th><th>Terraform Tests</th><th>Notes</th></tr>
  <tr><td colspan=4><b>ACM</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Amplify</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>API Gateway</b></td></tr>
  <tr><td>REST APIs</td><td>...</td><td></td><td></td></tr>
  <tr><td>Resources</td><td>...</td><td></td><td></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>API Gateway v2</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>AppSync</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Athena</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Backup</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>Batch</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>CloudFormation</b></td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
  <tr><td colspan=4><b>CloudFront</b> (Pro)</td></tr>
  <tr><td>...</td><td>...</td><td></td><td></td></tr>
  
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
