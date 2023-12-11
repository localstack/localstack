import json
import logging
import os

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until

LOG = logging.getLogger(__name__)


@markers.aws.validated
def test_eventbus_policies(deploy_cfn_template, aws_client):
    event_bus_name = f"event-bus-{short_uid()}"

    stack_response = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/eventbridge_policy.yaml"
        ),
        parameters={"EventBusName": event_bus_name},
    )

    describe_response = aws_client.events.describe_event_bus(Name=event_bus_name)
    policy = json.loads(describe_response["Policy"])
    assert len(policy["Statement"]) == 2

    # verify physical resource ID creation
    pol1_description = aws_client.cloudformation.describe_stack_resource(
        StackName=stack_response.stack_name, LogicalResourceId="eventPolicy"
    )
    pol2_description = aws_client.cloudformation.describe_stack_resource(
        StackName=stack_response.stack_name, LogicalResourceId="eventPolicy2"
    )
    assert (
        pol1_description["StackResourceDetail"]["PhysicalResourceId"]
        != pol2_description["StackResourceDetail"]["PhysicalResourceId"]
    )

    deploy_cfn_template(
        is_update=True,
        stack_name=stack_response.stack_name,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/eventbridge_policy_singlepolicy.yaml"
        ),
        parameters={"EventBusName": event_bus_name},
    )

    describe_response = aws_client.events.describe_event_bus(Name=event_bus_name)
    policy = json.loads(describe_response["Policy"])
    assert len(policy["Statement"]) == 1


@markers.aws.validated
def test_eventbus_policy_statement(deploy_cfn_template, aws_client):
    event_bus_name = f"event-bus-{short_uid()}"
    statement_id = f"statement-{short_uid()}"

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/eventbridge_policy_statement.yaml"
        ),
        parameters={"EventBusName": event_bus_name, "StatementId": statement_id},
    )

    describe_response = aws_client.events.describe_event_bus(Name=event_bus_name)
    policy = json.loads(describe_response["Policy"])
    assert policy["Version"] == "2012-10-17"
    assert len(policy["Statement"]) == 1
    statement = policy["Statement"][0]
    assert statement["Sid"] == statement_id
    assert statement["Action"] == "events:PutEvents"
    assert statement["Principal"] == "*"
    assert statement["Effect"] == "Allow"
    assert event_bus_name in statement["Resource"]


@markers.aws.validated
def test_event_rule_to_logs(deploy_cfn_template, aws_client):
    event_rule_name = f"event-rule-{short_uid()}"
    log_group_name = f"log-group-{short_uid()}"
    event_bus_name = f"bus-{short_uid()}"
    resource_policy_name = f"policy-{short_uid()}"

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/events_loggroup.yaml"
        ),
        parameters={
            "EventRuleName": event_rule_name,
            "LogGroupName": log_group_name,
            "EventBusName": event_bus_name,
            "PolicyName": resource_policy_name,
        },
    )

    log_groups = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    log_group_names = [lg["logGroupName"] for lg in log_groups]
    assert log_group_name in log_group_names

    message_token = f"test-message-{short_uid()}"
    resp = aws_client.events.put_events(
        Entries=[
            {
                "Source": "unittest",
                "Resources": [],
                "DetailType": "ls-detail-type",
                "Detail": json.dumps({"messagetoken": message_token}),
                "EventBusName": event_bus_name,
            }
        ]
    )
    assert len(resp["Entries"]) == 1

    wait_until(
        lambda: len(aws_client.logs.describe_log_streams(logGroupName=log_group_name)["logStreams"])
        > 0,
        1.0,
        5,
        "linear",
    )
    log_streams = aws_client.logs.describe_log_streams(logGroupName=log_group_name)["logStreams"]
    log_events = aws_client.logs.get_log_events(
        logGroupName=log_group_name, logStreamName=log_streams[0]["logStreamName"]
    )
    assert message_token in log_events["events"][0]["message"]


# {"LogicalResourceId": "TestRule99A50909", "ResourceType": "AWS::Events::Rule", "ResourceStatus": "CREATE_FAILED", "ResourceStatusReason": "Parameter ScheduleExpression is not valid."}
@markers.aws.needs_fixing
def test_event_rule_creation_without_target(deploy_cfn_template, aws_client):
    event_rule_name = f"event-rule-{short_uid()}"
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/events_rule_without_targets.yaml"
        ),
        parameters={"EventRuleName": event_rule_name},
    )

    response = aws_client.events.describe_rule(
        Name=event_rule_name,
    )
    assert response


@markers.aws.validated
def test_cfn_event_bus_resource(deploy_cfn_template, aws_client):
    def _assert(expected_len):
        rs = aws_client.events.list_event_buses()
        event_buses = [eb for eb in rs["EventBuses"] if eb["Name"] == "my-test-bus"]
        assert len(event_buses) == expected_len
        rs = aws_client.events.list_connections()
        connections = [con for con in rs["Connections"] if con["Name"] == "my-test-conn"]
        assert len(connections) == expected_len

    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/template31.yaml")
    )
    _assert(1)

    stack.destroy()
    _assert(0)


TEST_TEMPLATE_16 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyBucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: %s
  ScheduledRule:
    Type: 'AWS::Events::Rule'
    Properties:
      Name: %s
      ScheduleExpression: rate(10 minutes)
      State: ENABLED
      Targets:
        - Id: TargetBucketV1
          Arn: !GetAtt "MyBucket.Arn"
"""

TEST_TEMPLATE_18 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  TestStateMachine:
    Type: "AWS::StepFunctions::StateMachine"
    Properties:
      RoleArn: %s
      DefinitionString:
        !Sub
        - |-
          {
            "StartAt": "state1",
            "States": {
              "state1": {
                "Type": "Pass",
                "Result": "Hello World",
                "End": true
              }
            }
          }
        - {}
  ScheduledRule:
    Type: AWS::Events::Rule
    Properties:
      ScheduleExpression: "cron(0/1 * * * ? *)"
      State: ENABLED
      Targets:
        - Id: TestStateMachine
          Arn: !Ref TestStateMachine
"""


@markers.aws.validated
def test_rule_properties(deploy_cfn_template, aws_client, snapshot):
    event_bus_name = f"events-{short_uid()}"
    rule_name = f"rule-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(event_bus_name, "<event-bus-name>"))
    snapshot.add_transformer(snapshot.transform.regex(rule_name, "<custom-rule-name>"))

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/events_rule_properties.yaml"
        ),
        parameters={"EventBusName": event_bus_name, "RuleName": rule_name},
    )

    rule_id = stack.outputs["RuleWithoutNameArn"].rsplit("/")[-1]
    snapshot.add_transformer(snapshot.transform.regex(rule_id, "<rule-id>"))

    without_bus_id = stack.outputs["RuleWithoutBusArn"].rsplit("/")[-1]
    snapshot.add_transformer(snapshot.transform.regex(without_bus_id, "<without-bus-id>"))

    snapshot.match("outputs", stack.outputs)


# {"LogicalResourceId": "ScheduledRule", "ResourceType": "AWS::Events::Rule", "ResourceStatus": "CREATE_FAILED", "ResourceStatusReason": "s3 is not a supported service for a target."}
@markers.aws.needs_fixing
def test_cfn_handle_events_rule(deploy_cfn_template, aws_client):
    bucket_name = f"target-{short_uid()}"
    rule_prefix = f"s3-rule-{short_uid()}"
    rule_name = f"{rule_prefix}-{short_uid()}"

    stack = deploy_cfn_template(
        template=TEST_TEMPLATE_16 % (bucket_name, rule_name),
    )

    rs = aws_client.events.list_rules(NamePrefix=rule_prefix)
    assert rule_name in [rule["Name"] for rule in rs["Rules"]]

    target_arn = arns.s3_bucket_arn(bucket_name)  # TODO: !
    rs = aws_client.events.list_targets_by_rule(Rule=rule_name)
    assert target_arn in [target["Arn"] for target in rs["Targets"]]

    # clean up
    stack.destroy()
    rs = aws_client.events.list_rules(NamePrefix=rule_prefix)
    assert rule_name not in [rule["Name"] for rule in rs["Rules"]]


# {"LogicalResourceId": "TestStateMachine", "ResourceType": "AWS::StepFunctions::StateMachine", "ResourceStatus": "CREATE_FAILED", "ResourceStatusReason": "Resource handler returned message: \"Cross-account pass role is not allowed."}
@markers.aws.needs_fixing
def test_cfn_handle_events_rule_without_name(deploy_cfn_template, aws_client):
    rs = aws_client.events.list_rules()
    rule_names = [rule["Name"] for rule in rs["Rules"]]

    stack = deploy_cfn_template(
        template=TEST_TEMPLATE_18 % arns.iam_role_arn("sfn_role", account_id=TEST_AWS_ACCOUNT_ID),
    )

    rs = aws_client.events.list_rules()
    new_rules = [rule for rule in rs["Rules"] if rule["Name"] not in rule_names]
    assert len(new_rules) == 1
    rule = new_rules[0]

    assert rule["ScheduleExpression"] == "cron(0/1 * * * ? *)"

    stack.destroy()

    rs = aws_client.events.list_rules()
    assert rule["Name"] not in [r["Name"] for r in rs["Rules"]]
