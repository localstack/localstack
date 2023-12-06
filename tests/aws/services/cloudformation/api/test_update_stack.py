import json
import os

import botocore.errorfactory
import botocore.exceptions
import pytest

from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.testutil import upload_file_to_bucket


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
