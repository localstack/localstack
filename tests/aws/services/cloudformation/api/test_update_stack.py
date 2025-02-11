import json
import os
import textwrap
from collections import defaultdict
from typing import Callable

import botocore.errorfactory
import botocore.exceptions
import pytest

from localstack.aws.api.cloudformation import StackEvent
from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.testutil import upload_file_to_bucket

PerResourceStackEvents = dict[str, list[StackEvent]]


@pytest.fixture
def capture_per_resource_events(
    aws_client: ServiceLevelClientFactory,
) -> Callable[[str], PerResourceStackEvents]:
    def capture(stack_name: str) -> PerResourceStackEvents:
        events = aws_client.cloudformation.describe_stack_events(StackName=stack_name)[
            "StackEvents"
        ]
        per_resource_events = defaultdict(list)
        for event in events:
            if logical_resource_id := event.get("LogicalResourceId"):
                per_resource_events[logical_resource_id].append(event)
        return per_resource_events

    return capture


@markers.aws.validated
def test_basic_update(deploy_cfn_template, snapshot, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    response = aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        TemplateBody=load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
        ),
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    snapshot.add_transformer(snapshot.transform.key_value("StackId", "stack-id"))
    snapshot.match("update_response", response)

    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)


@markers.aws.validated
def test_update_using_template_url(deploy_cfn_template, s3_create_bucket, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    file_url = upload_file_to_bucket(
        aws_client.s3,
        s3_create_bucket(),
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml"),
    )["Url"]

    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        TemplateURL=file_url,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)


@markers.aws.validated
@pytest.mark.skip(reason="Not supported")
def test_update_with_previous_template(deploy_cfn_template, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)


@markers.aws.needs_fixing
@pytest.mark.skip(reason="templates are not partially not valid => re-evaluate")
@pytest.mark.parametrize(
    "capability",
    [
        {"value": "CAPABILITY_IAM", "template": "iam_policy.yml"},
        {"value": "CAPABILITY_NAMED_IAM", "template": "iam_role_policy.yaml"},
    ],
)
# The AUTO_EXPAND option is used for macros
def test_update_with_capabilities(capability, deploy_cfn_template, snapshot, aws_client):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/", capability["template"])
    )

    parameter_key = "RoleName" if capability["value"] == "CAPABILITY_NAMED_IAM" else "Name"

    with pytest.raises(botocore.errorfactory.ClientError) as ex:
        aws_client.cloudformation.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": parameter_key, "ParameterValue": f"{short_uid()}"}],
        )

    snapshot.match("error", ex.value.response)

    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        Capabilities=[capability["value"]],
        Parameters=[{"ParameterKey": parameter_key, "ParameterValue": f"{short_uid()}"}],
    )

    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)


@markers.aws.validated
@pytest.mark.skip(reason="Not raising the correct error")
def test_update_with_resource_types(deploy_cfn_template, snapshot, aws_client):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    # Test with invalid type
    with pytest.raises(botocore.exceptions.ClientError) as ex:
        aws_client.cloudformation.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            ResourceTypes=["AWS::EC2:*"],
            Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
        )

    snapshot.match("invalid_type_error", ex.value.response)

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        aws_client.cloudformation.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            ResourceTypes=["AWS::EC2::*"],
            Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
        )

    snapshot.match("resource_not_allowed", ex.value.response)

    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        ResourceTypes=["AWS::SNS::Topic"],
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)


@markers.aws.validated
@pytest.mark.skip(reason="Update value not being applied")
def test_set_notification_arn_with_update(deploy_cfn_template, sns_create_topic, aws_client):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    topic_arn = sns_create_topic()["TopicArn"]

    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        NotificationARNs=[topic_arn],
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    description = aws_client.cloudformation.describe_stacks(StackName=stack.stack_name)["Stacks"][0]
    assert topic_arn in description["NotificationARNs"]


@markers.aws.validated
@pytest.mark.skip(reason="Update value not being applied")
def test_update_tags(deploy_cfn_template, aws_client):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    key = f"key-{short_uid()}"
    value = f"value-{short_uid()}"

    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        Tags=[{"Key": key, "Value": value}],
        TemplateBody=template,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    tags = aws_client.cloudformation.describe_stacks(StackName=stack.stack_name)["Stacks"][0][
        "Tags"
    ]
    assert tags[0]["Key"] == key
    assert tags[0]["Value"] == value


@markers.aws.validated
@pytest.mark.skip(reason="The correct error is not being raised")
def test_no_template_error(deploy_cfn_template, snapshot, aws_client):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        aws_client.cloudformation.update_stack(StackName=stack.stack_name)

    snapshot.match("error", ex.value.response)


@markers.aws.validated
def test_no_parameters_update(deploy_cfn_template, aws_client):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    aws_client.cloudformation.update_stack(StackName=stack.stack_name, TemplateBody=template)

    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)


@markers.aws.validated
def test_update_with_previous_parameter_value(deploy_cfn_template, snapshot, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        TemplateBody=load_file(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/sns_topic_parameter.update.yml"
            )
        ),
        Parameters=[{"ParameterKey": "TopicName", "UsePreviousValue": True}],
    )

    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)


@markers.aws.validated
@pytest.mark.skip(reason="The correct error is not being raised")
def test_update_with_role_without_permissions(
    deploy_cfn_template, snapshot, create_role, aws_client
):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    account_arn = aws_client.sts.get_caller_identity()["Arn"]
    assume_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": account_arn},
                "Effect": "Deny",
            }
        ],
    }

    role_arn = create_role(AssumeRolePolicyDocument=json.dumps(assume_policy_doc))["Role"]["Arn"]

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        aws_client.cloudformation.update_stack(
            StackName=stack.stack_name,
            UsePreviousTemplate=True,
            Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
            RoleARN=role_arn,
        )

    snapshot.match("error", ex.value.response)


@markers.aws.validated
@pytest.mark.skip(reason="The correct error is not being raised")
def test_update_with_invalid_rollback_configuration_errors(
    deploy_cfn_template, snapshot, aws_client
):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    # Test invalid alarm type
    with pytest.raises(botocore.exceptions.ClientError) as ex:
        aws_client.cloudformation.update_stack(
            StackName=stack.stack_name,
            UsePreviousTemplate=True,
            Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
            RollbackConfiguration={"RollbackTriggers": [{"Arn": short_uid(), "Type": "Another"}]},
        )
    snapshot.match("type_error", ex.value.response)

    # Test invalid alarm arn
    with pytest.raises(botocore.exceptions.ClientError) as ex:
        aws_client.cloudformation.update_stack(
            StackName=stack.stack_name,
            UsePreviousTemplate=True,
            Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
            RollbackConfiguration={
                "RollbackTriggers": [
                    {
                        "Arn": "arn:aws:cloudwatch:us-east-1:123456789012:example-name",
                        "Type": "AWS::CloudWatch::Alarm",
                    }
                ]
            },
        )

    snapshot.match("arn_error", ex.value.response)


@markers.aws.validated
@pytest.mark.skip(reason="The update value is not being applied")
def test_update_with_rollback_configuration(deploy_cfn_template, aws_client):
    aws_client.cloudwatch.put_metric_alarm(
        AlarmName="HighResourceUsage",
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName="CPUUsage",
        Namespace="CustomNamespace",
        Period=60,
        Statistic="Average",
        Threshold=70,
        TreatMissingData="notBreaching",
    )

    alarms = aws_client.cloudwatch.describe_alarms(AlarmNames=["HighResourceUsage"])
    alarm_arn = alarms["MetricAlarms"][0]["AlarmArn"]

    rollback_configuration = {
        "RollbackTriggers": [
            {"Arn": alarm_arn, "Type": "AWS::CloudWatch::Alarm"},
        ],
        "MonitoringTimeInMinutes": 123,
    }

    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": "TopicName", "UsePreviousValue": True}],
        RollbackConfiguration=rollback_configuration,
    )

    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)

    config = aws_client.cloudformation.describe_stacks(StackName=stack.stack_name)["Stacks"][0][
        "RollbackConfiguration"
    ]
    assert config == rollback_configuration

    # cleanup
    aws_client.cloudwatch.delete_alarms(AlarmNames=["HighResourceUsage"])


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(["$..Stacks..ChangeSetId"])
def test_diff_after_update(deploy_cfn_template, aws_client, snapshot):
    template_1 = textwrap.dedent("""
    Resources:
        SimpleParam:
            Type: AWS::SSM::Parameter
            Properties:
                Value: before-stack-update
                Type: String
    """)
    template_2 = textwrap.dedent("""
    Resources:
        SimpleParam1:
            Type: AWS::SSM::Parameter
            Properties:
                Value: after-stack-update
                Type: String
    """)

    stack = deploy_cfn_template(
        template=template_1,
    )

    aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack.stack_name)
    aws_client.cloudformation.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template_2,
    )
    aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)
    get_template_response = aws_client.cloudformation.get_template(StackName=stack.stack_name)
    snapshot.match("get-template-response", get_template_response)

    with pytest.raises(botocore.exceptions.ClientError) as exc_info:
        aws_client.cloudformation.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template_2,
        )
    snapshot.match("update-error", exc_info.value.response)

    describe_stack_response = aws_client.cloudformation.describe_stacks(StackName=stack.stack_name)
    assert describe_stack_response["Stacks"][0]["StackStatus"] == "UPDATE_COMPLETE"


@pytest.fixture
def capture_update_process(aws_client, snapshot, cleanups, capture_per_resource_events):
    def try_do(f, *args, **kwargs):
        try:
            f(*args, **kwargs)
        except Exception as e:
            print(f"Error executing function: {e}")

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"cs-{short_uid()}"

    def inner(t1: dict | str, t2: dict | str):
        if isinstance(t1, dict):
            t1 = json.dumps(t1)
        elif isinstance(t1, str):
            with open(t1) as infile:
                t1 = infile.read()
        if isinstance(t2, dict):
            t2 = json.dumps(t2)
        elif isinstance(t2, str):
            with open(t2) as infile:
                t2 = infile.read()

        # deploy original stack
        change_set_details = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=t1,
            ChangeSetType="CREATE",
        )
        snapshot.match("create-change-set-1", change_set_details)
        stack_id = change_set_details["StackId"]
        change_set_id = change_set_details["Id"]
        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=change_set_id
        )
        cleanups.append(
            lambda: try_do(aws_client.cloudformation.delete_change_set, ChangeSetName=change_set_id)
        )

        describe_change_set_with_prop_values = aws_client.cloudformation.describe_change_set(
            ChangeSetName=change_set_id, IncludePropertyValues=True
        )
        snapshot.match("describe-change-set-1-prop-values", describe_change_set_with_prop_values)
        describe_change_set_without_prop_values = aws_client.cloudformation.describe_change_set(
            ChangeSetName=change_set_id, IncludePropertyValues=False
        )
        snapshot.match("describe-change-set-1", describe_change_set_without_prop_values)

        execute_results = aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        snapshot.match("execute-change-set-1", execute_results)
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_id)

        # ensure stack deletion
        cleanups.append(lambda: try_do(aws_client.cloudformation.delete_stack(StackName=stack_id)))

        describe = aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0]
        snapshot.match("post-create-1-describe", describe)

        # update stack
        change_set_details = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=t2,
            ChangeSetType="UPDATE",
        )
        snapshot.match("create-change-set-2", change_set_details)
        stack_id = change_set_details["StackId"]
        change_set_id = change_set_details["Id"]
        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=change_set_id
        )

        describe_change_set_with_prop_values = aws_client.cloudformation.describe_change_set(
            ChangeSetName=change_set_id, IncludePropertyValues=True
        )
        snapshot.match("describe-change-set-2-prop-values", describe_change_set_with_prop_values)
        describe_change_set_without_prop_values = aws_client.cloudformation.describe_change_set(
            ChangeSetName=change_set_id, IncludePropertyValues=False
        )
        snapshot.match("describe-change-set-2", describe_change_set_without_prop_values)

        execute_results = aws_client.cloudformation.execute_change_set(ChangeSetName=change_set_id)
        snapshot.match("execute-change-set-2", execute_results)
        aws_client.cloudformation.get_waiter("stack_update_complete").wait(StackName=stack_id)

        describe = aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0]
        snapshot.match("post-create-2-describe", describe)

        events = capture_per_resource_events(stack_name)
        snapshot.match("per-resource-events", events)

        # delete stack
        aws_client.cloudformation.delete_stack(StackName=stack_id)
        aws_client.cloudformation.get_waiter("stack_delete_complete").wait(StackName=stack_id)
        describe = aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0]
        snapshot.match("delete-describe", describe)

    yield inner


@markers.aws.validated
@pytest.mark.wip
def test_direct_update(
    capture_update_process,
):
    name1 = f"topic-1-{short_uid()}"
    name2 = f"topic-2-{short_uid()}"
    t1 = {
        "Resources": {
            "Foo": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": name1,
                },
            },
        },
    }
    t2 = {
        "Resources": {
            "Foo": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": name2,
                },
            },
        },
    }

    capture_update_process(t1, t2)


@markers.aws.validated
@pytest.mark.wip
def test_dynamic_update(
    capture_update_process,
):
    name1 = f"topic-1-{short_uid()}"
    name2 = f"topic-2-{short_uid()}"
    t1 = {
        "Resources": {
            "Foo": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": name1,
                },
            },
            "Parameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Type": "String",
                    "Value": {
                        "Fn::GetAtt": ["Foo", "TopicName"],
                    },
                },
            },
        },
    }
    t2 = {
        "Resources": {
            "Foo": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": name2,
                },
            },
            "Parameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Type": "String",
                    "Value": {
                        "Fn::GetAtt": ["Foo", "TopicName"],
                    },
                },
            },
        },
    }

    capture_update_process(t1, t2)
