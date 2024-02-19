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


class TestUpdateDetection:
    # TODO
    # def test_update_in_place_with_parameterchanges(deploy_cfn_template, aws_client, cleanups):
    # def test_update_with_replacement_with_parameterchanges(deploy_cfn_template, aws_client, cleanups):

    # TODO
    # def test_update_in_place_with_parameterchanges(deploy_cfn_template, aws_client, cleanups):
    # def test_update_with_replacement_with_parameterchanges(deploy_cfn_template, aws_client, cleanups):

    @markers.snapshot.skip_snapshot_verify(
        paths=["$..StackResourceDetail.DriftInformation", "$..StackResourceDetail.Metadata"]
    )
    @markers.aws.unknown
    def test_update_in_place(self, deploy_cfn_template, aws_client, cleanups, snapshot):
        """Update on a single resource which should keep the same physical resource ID and call the update handler"""
        random_scope = short_uid()
        ssm_param_name = f"/test/updates/{random_scope}/param"
        ssm_param_value_1 = "val1"
        ssm_param_value_2 = "val2"

        logical_resource_id = "TestSsmParam"
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.regex(random_scope, "<random-scope>"))

        # 1. create
        template_content = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/update-ssm-parameter.yaml")
        )
        stack_name = f"slsstack-{short_uid()}"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        stack = aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template_content.replace("<param-name>", ssm_param_name).replace(
                "<param-value>", ssm_param_value_1
            ),
        )
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(
            StackName=stack["StackId"]
        )

        stack_resource_preupdate = aws_client.cloudformation.describe_stack_resource(
            StackName=stack_name, LogicalResourceId=logical_resource_id
        )
        snapshot.match("stack_resource_preupdate", stack_resource_preupdate)

        get_param_1 = aws_client.ssm.get_parameter(Name=ssm_param_name)
        snapshot.match("get_param_1", get_param_1)

        # 2. update
        template_content = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/update-ssm-parameter.yaml")
        )
        stack = aws_client.cloudformation.update_stack(
            StackName=stack_name,
            TemplateBody=template_content.replace("<param-name>", ssm_param_name).replace(
                "<param-value>", ssm_param_value_2
            ),
        )
        aws_client.cloudformation.get_waiter("stack_update_complete").wait(
            StackName=stack["StackId"]
        )

        stack_resource_postupdate = aws_client.cloudformation.describe_stack_resource(
            StackName=stack_name, LogicalResourceId=logical_resource_id
        )
        snapshot.match("stack_resource_postupdate", stack_resource_postupdate)

        get_param_2 = aws_client.ssm.get_parameter(Name=ssm_param_name)
        snapshot.match("get_param_2", get_param_2)

        # in-place update expected
        assert get_param_1["Parameter"]["Value"] != get_param_2["Parameter"]["Value"]

    @markers.aws.unknown
    def test_update_with_replacement(self, deploy_cfn_template, aws_client, cleanups, snapshot):
        """
        Update on a single resource which modifies a createOnly property and should thus lead to replacement (delete + create)

        Note that we're not using parameters here, since this is handlded as a separate issue in LS
        """
        random_scope = short_uid()
        ssm_param_name_1 = f"/test/updates/{random_scope}/param1"
        ssm_param_name_2 = f"/test/updates/{random_scope}/param2"

        logical_resource_id = "TestSsmParam"
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.regex(random_scope, "<random-scope>"))

        # 1. create
        template_content = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/update-ssm-parameter.yaml")
        )
        stack_name = f"slsstack-{short_uid()}"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        stack = aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template_content.replace("<param-name>", ssm_param_name_1).replace(
                "<param-value>", "myvalue"
            ),
        )
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(
            StackName=stack["StackId"]
        )

        stack_resource_preupdate = aws_client.cloudformation.describe_stack_resource(
            StackName=stack_name, LogicalResourceId=logical_resource_id
        )
        snapshot.match("stack_resource_preupdate", stack_resource_preupdate)

        get_param_1 = aws_client.ssm.get_parameter(Name=ssm_param_name_1)
        snapshot.match("get_param_1", get_param_1)

        # 2. update
        template_content = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/update-ssm-parameter.yaml")
        )
        stack = aws_client.cloudformation.update_stack(
            StackName=stack_name,
            TemplateBody=template_content.replace("<param-name>", ssm_param_name_2).replace(
                "<param-value>", "myvalue"
            ),
        )
        aws_client.cloudformation.get_waiter("stack_update_complete").wait(
            StackName=stack["StackId"]
        )

        stack_resource_postupdate = aws_client.cloudformation.describe_stack_resource(
            StackName=stack_name, LogicalResourceId=logical_resource_id
        )
        snapshot.match("stack_resource_postupdate", stack_resource_postupdate)

        with pytest.raises(aws_client.ssm.exceptions.ParameterNotFound) as e:
            aws_client.ssm.get_parameter(Name=ssm_param_name_1)  # fails
        snapshot.match("get_param_1_postupdate_exception", e.value.response)
        get_param_2 = aws_client.ssm.get_parameter(Name=ssm_param_name_2)
        snapshot.match("get_param_2", get_param_2)

        stack_events = aws_client.cloudformation.describe_stack_events(StackName=stack["StackId"])
        print("done")

    @markers.aws.unknown
    def test_update_with_replacement_cs(self, deploy_cfn_template, aws_client, cleanups):
        """
        Update on a single resource which modifies a createOnly property and should thus lead to replacement (delete + create)

        Note that we're not using parameters here, since this is handlded as a separate issue in LS
        """
        random_scope = short_uid()
        ssm_param_name_1 = f"/test/updates/{random_scope}/param1"
        ssm_param_name_2 = f"/test/updates/{random_scope}/param2"

        logical_resource_id = "TestSsmParam"

        # 1. create
        template_content = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/update-ssm-parameter.yaml")
        )
        stack_name = f"slsstack-{short_uid()}"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        stack = aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template_content.replace("<param-name>", ssm_param_name_1).replace(
                "<param-value>", "myvalue"
            ),
        )
        aws_client.cloudformation.get_waiter("stack_create_complete").wait(
            StackName=stack["StackId"]
        )

        stack_resource_preupdate = aws_client.cloudformation.describe_stack_resource(
            StackName=stack_name, LogicalResourceId=logical_resource_id
        )
        get_param_1 = aws_client.ssm.get_parameter(Name=ssm_param_name_1)

        # 2. update
        template_content = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/update-ssm-parameter.yaml")
        )
        cs = aws_client.cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName="MyUpdate",
            TemplateBody=template_content.replace("<param-name>", ssm_param_name_2).replace(
                "<param-value>", "myvalue"
            ),
        )
        aws_client.cloudformation.get_waiter("change_set_create_complete").wait(
            ChangeSetName=cs["Id"]
        )

        describe_cs = aws_client.cloudformation.describe_change_set(ChangeSetName=cs["Id"])
        print("ok")

        a = {
            "Action": "Modify",
            "LogicalResourceId": "TestSsmParam",
            "PhysicalResourceId": "/test/updates/e3f16698/param1",
            "ResourceType": "AWS::SSM::Parameter",
            "Replacement": "True",
            "Scope": ["Properties"],
            "Details": [
                {
                    "Target": {
                        "Attribute": "Properties",
                        "Name": "Name",
                        "RequiresRecreation": "Always",
                    },
                    "Evaluation": "Static",
                    "ChangeSource": "DirectModification",
                }
            ],
        }


# gathering cases / questions

# * does only the change of an export/import value cause a stack update? i.e. all parametrs and template are the same but updatestack leads to an update?
# transitivity: test if transitive resources are also automatically updated and how this is represented via the API
# transitivity: test how Ref vs. GetAtt might differ
