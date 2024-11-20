import json
import logging
import os

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until

LOG = logging.getLogger(__name__)


@markers.aws.validated
def test_cfn_event_api_destination_resource(deploy_cfn_template, region_name, aws_client):
    def _assert(expected_len):
        rs = aws_client.events.list_event_buses()
        event_buses = [eb for eb in rs["EventBuses"] if eb["Name"] == "my-test-bus"]
        assert len(event_buses) == expected_len
        rs = aws_client.events.list_connections()
        connections = [con for con in rs["Connections"] if con["Name"] == "my-test-conn"]
        assert len(connections) == expected_len
        rs = aws_client.events.list_api_destinations()
        api_destinations = [
            ad for ad in rs["ApiDestinations"] if ad["Name"] == "my-test-destination"
        ]
        assert len(api_destinations) == expected_len

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/events_apidestination.yml"
        ),
        parameters={
            "Region": region_name,
        },
    )
    _assert(1)

    stack.destroy()
    _assert(0)


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
