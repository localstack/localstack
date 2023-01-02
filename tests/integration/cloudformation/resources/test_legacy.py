import json
import os
import time

import pytest
import yaml
from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserError

from localstack.aws.accounts import get_aws_account_id
from localstack.services.cloudformation.engine import template_preparer
from localstack.testing.aws.lambda_utils import is_new_provider
from localstack.utils.aws import arns
from localstack.utils.common import load_file, short_uid
from localstack.utils.testutil import create_zip_file, list_all_resources

TEST_TEMPLATE_3 = (
    """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  S3Setup:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-%s
"""
    % short_uid()
)

TEST_TEMPLATE_8 = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Template for AWS::AWS::Function.",
    "Resources": {
        "S3Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": ""}},
        "S3BucketPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": {"Ref": "S3Bucket"},
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:PutObject"],
                            "Resource": ["*"],
                        }
                    ]
                },
            },
        },
    },
}

TEST_TEMPLATE_9 = (
    """
Parameters:
  gitBranch:
    Type: String
    Default: dev

Mappings:
  AccountInfo:
    "%s":
      ID: 10000000
      ENV: dev

Conditions:
  FeatureBranch:
    Fn::Equals:
      - Ref: gitBranch
      - 'dev'

Resources:
  HeartbeatHandlerLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      RetentionInDays: 1
      LogGroupName:
        Fn::Join:
          - '_'
          - - '/aws/lambda/AWS_DUB_LAM'
            - !FindInMap [ AccountInfo, !Ref "AWS::AccountId", ID ]
            - !If [ FeatureBranch, !Ref "gitBranch", !Ref "AWS::NoValue" ]
            - 'MessageFooHandler'
            - !FindInMap [ AccountInfo, !Ref "AWS::AccountId", ENV ]
"""
    % get_aws_account_id()
)

TEST_TEMPLATE_13 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  IamRoleLambdaExecution:
    Type: 'AWS::IAM::Role'
    Properties:
      RoleName: %s
      Path: %s
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
            Resource:
              - !Sub >-
                arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/aws-dev-log:*
  ManagedRolePolicy:
    Type: 'AWS::IAM::ManagedPolicy'
    Properties:
      ManagedPolicyName: %s
      Roles: [!GetAtt IamRoleLambdaExecution.RoleName]
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'
"""

TEST_TEMPLATE_14 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  IamRoleLambdaExecution:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument: {}
      Path: %s
"""

TEST_TEMPLATE_17 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  TestQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: %s
      ReceiveMessageWaitTimeSeconds: 0
      VisibilityTimeout: 30
      MessageRetentionPeriod: 1209600

  TestBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: %s
      NotificationConfiguration:
        QueueConfigurations:
          - Event: s3:ObjectCreated:*
            Queue: %s
"""


TEST_CHANGE_SET_BODY = """
Parameters:
  EnvironmentType:
    Type: String
    Default: local
    AllowedValues:
      - prod
      - stage
      - dev
      - local

Conditions:
  IsProd:
    !Equals [ !Ref EnvironmentType, prod ]

Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: {'Fn::If': [IsProd, '_invalid_', '%s']}
"""

TEST_TEMPLATE_19 = (
    """
Conditions:
  IsPRD:
    Fn::Equals:
    - !Ref AWS::AccountId
    - xxxxxxxxxxxxxx
  IsDEV:
    Fn::Equals:
    - !Ref AWS::AccountId
    - "%s"

Resources:
  TestBucketDev:
    Type: AWS::S3::Bucket
    Condition: IsDEV
    Properties:
      BucketName: cf-dev-{id}
  TestBucketProd:
    Type: AWS::S3::Bucket
    Condition: IsPRD
    Properties:
      BucketName: cf-prd-{id}
"""
    % get_aws_account_id()
)

TEST_TEMPLATE_20 = """
AWSTemplateFormatVersion: 2010-09-09
Description: Test template
Resources:
  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs10.x
      Handler: index.handler
      Role: %s
      Code:
        ZipFile: 'file.zip'
"""

TEST_TEMPLATE_22 = """
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  Api:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
  Lambda:
    Type: AWS::Serverless::Function
    Properties:
      Events:
        ApiEvent:
          Type: Api
          Properties:
            Path: /
            Method: get
            RestApiId:
              Ref: Api
      Runtime: python3.7
      Handler: index.handler
      InlineCode: |
        def handler(event, context):
            return {'body': 'Hello World!', 'statusCode': 200}
"""


TEST_TEMPLATE_29 = """
Parameters:
  Qualifier:
    Type: String
    Default: q123
Resources:
  TestQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: %s
      Tags:
        - Key: test
          Value: !Sub "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter${CdkBootstrapVersion}"
  CdkBootstrapVersion:
    Type: "AWS::SSM::Parameter"
    Properties:
      Type: String
      Name: !Sub "/cdk-bootstrap/${Qualifier}/version"
      Value: "..."
"""


# Note: Do not add new tests here !
class TestCloudFormation:
    def test_validate_template(self, cfn_client):
        template = template_preparer.template_to_json(
            load_file(
                os.path.join(os.path.dirname(__file__), "../../templates/valid_template.json")
            )
        )
        resp = cfn_client.validate_template(TemplateBody=template)

        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(resp["Parameters"]) == 1
        assert resp["Parameters"][0]["ParameterKey"] == "KeyExample"
        assert (
            resp["Parameters"][0]["Description"]
            == "The EC2 Key Pair to allow SSH access to the instance"
        )

    def test_validate_invalid_json_template_should_fail(self, cfn_client):
        invalid_json = '{"this is invalid JSON"="bobbins"}'

        with pytest.raises((ClientError, ResponseParserError)) as ctx:
            cfn_client.validate_template(TemplateBody=invalid_json)
        if isinstance(ctx.value, ClientError):
            assert ctx.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
            assert ctx.value.response["Error"]["Message"] == "Template Validation Error"

    def test_cfn_handle_log_group_resource(self, deploy_cfn_template, logs_client):
        log_group_prefix = "/aws/lambda/AWS_DUB_LAM_10000000"

        stack = deploy_cfn_template(template=TEST_TEMPLATE_9)

        rs = logs_client.describe_log_groups(logGroupNamePrefix=log_group_prefix)
        assert len(rs["logGroups"]) == 1
        assert (
            rs["logGroups"][0]["logGroupName"]
            == "/aws/lambda/AWS_DUB_LAM_10000000_dev_MessageFooHandler_dev"
        )

        # clean up and assert deletion
        stack.destroy()
        rs = logs_client.describe_log_groups(logGroupNamePrefix=log_group_prefix)
        assert len(rs["logGroups"]) == 0

    def test_cfn_handle_iam_role_resource(self, deploy_cfn_template, iam_client):
        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        role_path_prefix = f"/role-prefix-{short_uid()}/"

        template_body = TEST_TEMPLATE_13 % (role_name, role_path_prefix, policy_name)
        stack = deploy_cfn_template(template=template_body)

        rs = iam_client.list_roles(PathPrefix=role_path_prefix)

        assert len(rs["Roles"]) == 1
        role = rs["Roles"][0]
        assert role["RoleName"] == role_name

        result = iam_client.get_policy(PolicyArn=arns.policy_arn(policy_name))
        assert result["Policy"]["PolicyName"] == policy_name

        # clean up
        stack.destroy()

        rs = iam_client.list_roles(PathPrefix=role_path_prefix)
        assert not rs["Roles"]

    def test_cfn_handle_iam_role_resource_no_role_name(self, iam_client, deploy_cfn_template):
        role_path_prefix = f"/role-prefix-{short_uid()}/"
        stack = deploy_cfn_template(template=TEST_TEMPLATE_14 % role_path_prefix)

        rs = iam_client.list_roles(PathPrefix=role_path_prefix)
        assert len(rs["Roles"]) == 1

        stack.destroy()

        rs = iam_client.list_roles(PathPrefix=role_path_prefix)
        assert not rs["Roles"]

    def test_cfn_conditional_deployment(self, s3_client, deploy_cfn_template):
        bucket_id = short_uid()
        deploy_cfn_template(template=TEST_TEMPLATE_19.format(id=bucket_id))

        buckets = s3_client.list_buckets()["Buckets"]
        dev_bucket = f"cf-dev-{bucket_id}"
        prd_bucket = f"cf-prd-{bucket_id}"
        dev_bucket = [b for b in buckets if b["Name"] == dev_bucket]
        prd_bucket = [b for b in buckets if b["Name"] == prd_bucket]

        assert not prd_bucket
        assert dev_bucket

    @pytest.mark.parametrize(
        "create_bucket_first, region", [(True, "eu-west-1"), (False, "us-east-1")]
    )
    def test_cfn_handle_s3_notification_configuration(
        self,
        region,
        create_boto_client,
        deploy_cfn_template,
        create_bucket_first,
    ):
        s3_client = create_boto_client("s3", region_name=region)
        bucket_name = f"target-{short_uid()}"
        queue_name = f"queue-{short_uid()}"
        # the queue is always created in us-east-1
        queue_arn = arns.sqs_queue_arn(queue_name)
        if create_bucket_first:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": s3_client.meta.region_name},
            )
        stack = deploy_cfn_template(
            template=TEST_TEMPLATE_17 % (queue_name, bucket_name, queue_arn),
        )
        rs = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        assert "QueueConfigurations" in rs
        assert len(rs["QueueConfigurations"]) == 1
        assert rs["QueueConfigurations"][0]["QueueArn"] == queue_arn

        stack.destroy()

        # exception below tested against AWS
        with pytest.raises(Exception) as exc:
            s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        exc.match("NoSuchBucket")

    def test_cfn_handle_serverless_api_resource(
        self, deploy_cfn_template, cfn_client, apigateway_client
    ):
        stack = deploy_cfn_template(template=TEST_TEMPLATE_22)

        res = cfn_client.list_stack_resources(StackName=stack.stack_name)["StackResourceSummaries"]
        rest_api_ids = [
            r["PhysicalResourceId"] for r in res if r["ResourceType"] == "AWS::ApiGateway::RestApi"
        ]
        lambda_func_names = [
            r["PhysicalResourceId"] for r in res if r["ResourceType"] == "AWS::Lambda::Function"
        ]

        assert len(rest_api_ids) == 1
        assert len(lambda_func_names) == 1

        rs = apigateway_client.get_resources(restApiId=rest_api_ids[0])
        assert len(rs["items"]) == 1
        resource = rs["items"][0]

        uri = resource["resourceMethods"]["GET"]["methodIntegration"]["uri"]
        lambda_arn = arns.lambda_function_arn(lambda_func_names[0])  # TODO
        assert lambda_arn in uri

    # TODO: refactor
    @pytest.mark.xfail(condition=is_new_provider(), reason="fails/times out")
    def test_update_lambda_function(
        self, lambda_client, cfn_client, s3_client, s3_create_bucket, deploy_cfn_template
    ):
        bucket_name = f"bucket-{short_uid()}"
        key_name = "lambda-package"
        role_name = f"role-{short_uid()}"
        function_name = f"func-{short_uid()}"
        package_path = os.path.join(
            os.path.dirname(__file__), "../../awslambda/functions/lambda_echo.js"
        )
        template = json.loads(
            load_file(
                os.path.join(
                    os.path.dirname(__file__), "../../templates/update_lambda_template.json"
                )
            )
        )
        template["Resources"]["PullMarketsRole"]["Properties"]["RoleName"] = role_name

        props = template["Resources"]["SomeNameFunction"]["Properties"]
        props["Code"]["S3Bucket"] = bucket_name
        props["Code"]["S3Key"] = key_name
        props["FunctionName"] = function_name

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_object(
            Bucket=bucket_name,
            Key=key_name,
            Body=create_zip_file(package_path, get_content=True),
        )

        stack = deploy_cfn_template(template=json.dumps(template))

        props.update({"Environment": {"Variables": {"AWS_NODEJS_CONNECTION_REUSE_ENABLED": 1}}})
        deploy_cfn_template(
            stack_name=stack.stack_name, template=json.dumps(template), is_update=True
        )

        rs = lambda_client.get_function(FunctionName=function_name)
        assert rs["Configuration"]["FunctionName"] == function_name
        assert (
            "AWS_NODEJS_CONNECTION_REUSE_ENABLED" in rs["Configuration"]["Environment"]["Variables"]
        )

    # TODO: evaluate
    def test_update_conditions(self, s3_client, cfn_client, deploy_cfn_template):
        stack = deploy_cfn_template(template=TEST_TEMPLATE_3)
        template = yaml.load(TEST_TEMPLATE_3)

        # TODO: avoid changing template here
        # update stack with additional resources and conditions
        bucket1 = f"b-{short_uid()}"
        bucket2 = f"b-{short_uid()}"
        template["Resources"].update(
            {
                "ToBeCreated": {
                    "Type": "AWS::S3::Bucket",
                    "Condition": "TrueCondition",
                    "Properties": {"BucketName": bucket1},
                },
                "NotToBeCreated": {
                    "Type": "AWS::S3::Bucket",
                    "Condition": "FalseCondition",
                    "Properties": {"BucketName": bucket2},
                },
            }
        )
        template["Conditions"] = {
            "TrueCondition": {"Fn::Equals": ["same", "same"]},
            "FalseCondition": {"Fn::Equals": ["this", "other"]},
        }
        cfn_client.update_stack(StackName=stack.stack_name, TemplateBody=json.dumps(template))
        cfn_client.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)

        # bucket1 should have been created, bucket2 not
        s3_client.head_bucket(Bucket=bucket1)
        with pytest.raises(Exception):
            s3_client.head_bucket(Bucket=bucket2)

    def test_cfn_template_with_short_form_fn_sub(
        self, iam_client, deploy_cfn_template, stepfunctions_client
    ):
        environment = f"env-{short_uid()}"

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/template23.yaml"
            ),
            parameters={"Environment": environment, "ApiKey": "12345"},
        )

        # 2 roles created successfully
        rs = iam_client.list_roles()
        roles = [role for role in rs["Roles"] if stack.stack_name in role["RoleName"]]
        assert len(roles) == 2

        state_machines_after = stepfunctions_client.list_state_machines()["stateMachines"]
        state_machines = [
            sm for sm in state_machines_after if f"{stack.stack_name}-StateMachine-" in sm["name"]
        ]
        assert len(state_machines) == 1

        rs = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machines[0]["stateMachineArn"]
        )
        definition = json.loads(rs["definition"].replace("\n", ""))
        payload = definition["States"]["time-series-update"]["Parameters"]["Payload"]
        assert payload == {"key": "12345"}

    def test_sub_in_lambda_function_name(
        self, s3_client, lambda_client, rg_client, deploy_cfn_template, s3_create_bucket
    ):
        environment = f"env-{short_uid()}"
        bucket = f"bucket-{short_uid()}"
        key = f"key-{short_uid()}"

        package_path = os.path.join(
            os.path.dirname(__file__), "../../awslambda/functions/lambda_echo.js"
        )

        s3_create_bucket(Bucket=bucket, ACL="public-read")
        s3_client.put_object(
            Bucket=bucket, Key=key, Body=create_zip_file(package_path, get_content=True)
        )
        time.sleep(1)  # TODO: ? what is this waiting for

        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/template24.yaml")
        ) % (
            bucket,
            key,
            bucket,
            key,
        )
        deploy_cfn_template(template=template, parameters={"Environment": environment})

        functions = lambda_client.list_functions()["Functions"]
        # assert Lambda functions created with expected name and ARN
        func_prefix = f"test-{environment}-connectionHandler"
        functions = [func for func in functions if func["FunctionName"].startswith(func_prefix)]
        assert len(functions) == 2
        func1 = [f for f in functions if f["FunctionName"].endswith("connectionHandler1")][0]
        func2 = [f for f in functions if f["FunctionName"].endswith("connectionHandler2")][0]
        assert func1["FunctionArn"].endswith(func1["FunctionName"])
        assert func2["FunctionArn"].endswith(func2["FunctionName"])

        # assert buckets which reference Lambda names have been created
        buckets = s3_client.list_buckets()["Buckets"]
        buckets = [b for b in buckets if b["Name"].startswith(func_prefix.lower())]
        # assert buckets are created correctly
        assert len(functions) == 2
        tags1 = s3_client.get_bucket_tagging(Bucket=buckets[0]["Name"])
        tags2 = s3_client.get_bucket_tagging(Bucket=buckets[1]["Name"])
        # assert correct tags - they reference the function names and should equal the bucket names (lower case)
        assert buckets[0]["Name"] == tags1["TagSet"][0]["Value"].lower()
        assert buckets[1]["Name"] == tags2["TagSet"][0]["Value"].lower()

        # assert additional resources are present
        rg_name = "cf-rg-6427"
        groups = rg_client.list_groups().get("Groups", [])
        assert [g for g in groups if g["Name"] == rg_name]

    def test_functions_in_output_export_name(self, cfn_client, sns_client, deploy_cfn_template):
        environment = f"env-{short_uid()}"

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/template26.yaml"
            ),
            parameters={"Environment": environment},
        )

        resp = cfn_client.describe_stacks(StackName=stack.stack_name)
        stack_outputs = [s["Outputs"] for s in resp["Stacks"] if s["StackName"] == stack.stack_name]
        assert len(stack_outputs) == 1

        outputs = {
            o["OutputKey"]: {"value": o["OutputValue"], "export": o["ExportName"]}
            for o in stack_outputs[0]
        }

        assert "VpcId" in outputs
        assert outputs["VpcId"].get("export") == f"{environment}-vpc-id"

        topic_arn = arns.sns_topic_arn(f"{environment}-slack-sns-topic")  # TODO(!)
        assert "TopicArn" in outputs
        assert outputs["TopicArn"].get("export") == topic_arn

        # clean up
        stack.destroy()

        topic_arns = [t["TopicArn"] for t in sns_client.list_topics()["Topics"]]
        assert topic_arn not in topic_arns

    # TODO: refactor
    @pytest.mark.xfail(reason="fails due to / depending on other tests")
    def test_deploy_stack_with_sub_select_and_sub_getaz(
        self,
        cfn_client,
        sns_client,
        cloudwatch_client,
        ec2_client,
        iam_client,
        deploy_cfn_template,
        cleanups,
    ):
        key_name = f"key-pair-foo123-{short_uid()}"
        key_pair = ec2_client.create_key_pair(KeyName=key_name)
        cleanups.append(
            lambda: ec2_client.delete_key_pair(
                KeyName=key_pair["KeyName"], KeyPairId=key_pair["KeyPairId"]
            )
        )

        # list resources before stack deployment
        metric_alarms = cloudwatch_client.describe_alarms().get("MetricAlarms", [])
        composite_alarms = cloudwatch_client.describe_alarms().get("CompositeAlarms", [])

        # deploy stack
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/template28.yaml"
            ),
            parameters={"Ec2KeyPairName": key_name},
        )
        exports = cfn_client.list_exports()["Exports"]

        subnets = [export for export in exports if export["Name"] == "public-sn-a"]
        instances = [export for export in exports if export["Name"] == "RegmonEc2InstanceId"]

        assert len(subnets) == 1
        assert len(instances) == 1

        subnet_id = subnets[0]["Value"]
        instance_id = instances[0]["Value"]

        resp = ec2_client.describe_subnets(SubnetIds=[subnet_id])
        assert len(resp["Subnets"]) == 1

        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        assert len(resp["Reservations"][0]["Instances"]) == 1

        # assert creation of further resources
        resp = sns_client.list_topics()
        topic_arns = [tp["TopicArn"] for tp in resp["Topics"]]
        assert arns.sns_topic_arn("companyname-slack-topic") in topic_arns  # TODO: manual ARN
        # TODO: fix assertions, to make tests parallelizable!
        metric_alarms_after = cloudwatch_client.describe_alarms().get("MetricAlarms", [])
        composite_alarms_after = cloudwatch_client.describe_alarms().get("CompositeAlarms", [])
        assert len(metric_alarms_after) == len(metric_alarms) + 1
        assert len(composite_alarms_after) == len(composite_alarms) + 1

        profiles = iam_client.list_instance_profiles().get("InstanceProfiles", [])
        assert len(profiles) > 0
        profile = profiles[0]
        assert len(profile["Roles"]) > 0

    # TODO: refactor
    @pytest.mark.skip(reason="update doesn't change value for instancetype")
    def test_cfn_update_ec2_instance_type(self, cfn_client, ec2_client, deploy_cfn_template):
        if cfn_client.meta.region_name not in [
            "ap-northeast-1",
            "eu-central-1",
            "eu-south-1",
            "eu-west-1",
            "eu-west-2",
            "us-east-1",
        ]:
            pytest.skip()
        ec2_client.create_key_pair(KeyName="testkey")  # TODO: cleanup

        stack = deploy_cfn_template(
            template_path=os.path.join(os.path.dirname(__file__), "templates/template30.yaml"),
            parameters={"KeyName": "testkey"},
        )

        def get_instance_id():
            resources = cfn_client.list_stack_resources(StackName=stack.stack_name)[
                "StackResourceSummaries"
            ]
            instances = [res for res in resources if res["ResourceType"] == "AWS::EC2::Instance"]
            assert len(instances) == 1
            return instances[0]["PhysicalResourceId"]

        instance_id = get_instance_id()
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        assert len(resp["Reservations"][0]["Instances"]) == 1
        assert resp["Reservations"][0]["Instances"][0]["InstanceType"] == "t2.nano"

        deploy_cfn_template(
            stack_name=stack.stack_name,
            template_path=os.path.join(os.path.dirname(__file__), "templates/template30.yaml"),
            parameters={"InstanceType": "t2.medium"},
        )

        instance_id = get_instance_id()  # get ID of updated instance (may have changed!)
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = resp["Reservations"]
        assert len(reservations) == 1
        assert reservations[0]["Instances"][0]["InstanceType"] == "t2.medium"

    def test_cfn_with_exports(self, cfn_client, deploy_cfn_template):
        # fetch initial list of exports
        exports_before = cfn_client.list_exports()["Exports"]

        stack = deploy_cfn_template(
            template_path=os.path.join(os.path.dirname(__file__), "../../templates/template32.yaml")
        )
        stack_name = stack.stack_name

        exports = cfn_client.list_exports()["Exports"]
        # TODO: fix assertion, to make tests parallelizable!
        assert len(exports) == len(exports_before) + 6
        export_names = [e["Name"] for e in exports]
        assert f"{stack_name}-FullAccessCentralControlPolicy" in export_names
        assert f"{stack_name}-ReadAccessCentralControlPolicy" in export_names
        assert f"{stack_name}-cc-groups-stream" in export_names
        assert f"{stack_name}-cc-scenes-stream" in export_names
        assert f"{stack_name}-cc-customscenes-stream" in export_names
        assert f"{stack_name}-cc-schedules-stream" in export_names

    # TODO: refactor
    def test_cfn_with_route_table(self, ec2_client, deploy_cfn_template, cfn_client):
        resp = ec2_client.describe_vpcs()
        # TODO: fix assertion, to make tests parallelizable!
        vpcs_before = [vpc["VpcId"] for vpc in resp["Vpcs"]]

        stack = deploy_cfn_template(
            template_path=os.path.join(os.path.dirname(__file__), "../../templates/template33.yaml")
        )
        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"] if vpc["VpcId"] not in vpcs_before]
        assert len(vpcs) == 1

        resp = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]]}])
        # Each VPC always have 1 default RouteTable
        assert len(resp["RouteTables"]) == 2

        # The 2nd RouteTable was created by cfn template
        route_table_id = resp["RouteTables"][1]["RouteTableId"]
        routes = resp["RouteTables"][1]["Routes"]

        # Each RouteTable has 1 default route
        assert len(routes) == 2

        assert routes[0]["DestinationCidrBlock"] == "100.0.0.0/20"

        # The 2nd Route was created by cfn template
        assert routes[1]["DestinationCidrBlock"] == "0.0.0.0/0"

        exports = cfn_client.list_exports()["Exports"]
        export_values = {ex["Name"]: ex["Value"] for ex in exports}
        assert "publicRoute-identify" in export_values
        assert export_values["publicRoute-identify"] == f"{route_table_id}~0.0.0.0/0"

        stack.destroy()

        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"] if vpc["VpcId"] not in vpcs_before]
        assert not vpcs

    # TODO: evaluate (can we drop this?)
    def test_updating_stack_with_iam_role(self, deploy_cfn_template, iam_client, lambda_client):

        # Initialization
        lambda_role_name = f"lambda-role-{short_uid()}"
        lambda_function_name = f"lambda-function-{short_uid()}"

        template = json.loads(
            load_file(os.path.join(os.path.dirname(__file__), "../../templates/template7.json"))
        )

        template["Resources"]["LambdaExecutionRole"]["Properties"]["RoleName"] = lambda_role_name
        template["Resources"]["LambdaFunction1"]["Properties"][
            "FunctionName"
        ] = lambda_function_name

        # Create stack and wait for 'CREATE_COMPLETE' status of the stack
        stack = deploy_cfn_template(template=json.dumps(template))

        # Checking required values for Lambda function and IAM Role
        list_functions = list_all_resources(
            lambda kwargs: lambda_client.list_functions(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Functions",
        )
        list_roles = list_all_resources(
            lambda kwargs: iam_client.list_roles(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Roles",
        )

        new_function = [
            function
            for function in list_functions
            if function.get("FunctionName") == lambda_function_name
        ]
        new_role = [role for role in list_roles if role.get("RoleName") == lambda_role_name]

        assert len(new_function) == 1
        assert lambda_role_name in new_function[0].get("Role")

        assert len(new_role) == 1

        # Generate new names for lambda and IAM Role
        lambda_role_name_new = f"lambda-role-new-{short_uid()}"
        lambda_function_name_new = f"lambda-function-new-{short_uid()}"

        template["Resources"]["LambdaExecutionRole"]["Properties"][
            "RoleName"
        ] = lambda_role_name_new
        template["Resources"]["LambdaFunction1"]["Properties"][
            "FunctionName"
        ] = lambda_function_name_new

        # Update stack and wait for 'UPDATE_COMPLETE' status of the stack
        deploy_cfn_template(
            is_update=True, template=json.dumps(template), stack_name=stack.stack_name
        )

        # Checking new required values for Lambda function and IAM Role

        list_functions = list_all_resources(
            lambda kwargs: lambda_client.list_functions(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Functions",
        )

        list_roles = list_all_resources(
            lambda kwargs: iam_client.list_roles(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Roles",
        )

        new_function = [
            function
            for function in list_functions
            if function.get("FunctionName") == lambda_function_name_new
        ]
        assert len(new_function) == 1
        assert lambda_role_name_new in new_function[0].get("Role")
        new_role = [role for role in list_roles if role.get("RoleName") == lambda_role_name_new]
        assert len(new_role) == 1

    def test_resolve_transitive_placeholders_in_strings(self, sqs_client, deploy_cfn_template):
        queue_name = f"q-{short_uid()}"
        stack_name = f"stack-{short_uid()}"
        deploy_cfn_template(stack_name=stack_name, template=TEST_TEMPLATE_29 % queue_name)

        tags = sqs_client.list_queue_tags(QueueUrl=arns.get_sqs_queue_url(queue_name))
        test_tag = tags["Tags"]["test"]
        assert test_tag == arns.ssm_parameter_arn("cdk-bootstrap/q123/version")


# Note: DO NOT ADD TEST CASES HERE
#       Add new tests in a corresponding file in the tests/integration/cloudformation directory
