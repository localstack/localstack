import os

import botocore.errorfactory
import botocore.exceptions
import pytest

from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@pytest.mark.aws_validated
def test_basic_update(cfn_client, deploy_cfn_template, snapshot, is_stack_updated):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    response = cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
        ),
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    snapshot.add_transformer(snapshot.transform.key_value("StackId", "stack-id"))
    snapshot.match("update_response", response)

    def verify_stack():
        assert is_stack_updated(stack.stack_name)

    retry(verify_stack, retries=5, sleep_before=2, sleep=1)


@pytest.mark.aws_validated
def test_update_using_template_url(cfn_client, deploy_cfn_template, upload_file, is_stack_updated):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    file_url = upload_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )["Url"]

    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateURL=file_url,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    def verify_stack():
        assert is_stack_updated(stack.stack_name)

    retry(verify_stack, retries=5, sleep_before=2, sleep=1)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not supported")
def test_update_with_previous_template(cfn_client, deploy_cfn_template, is_stack_updated):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    cfn_client.update_stack(
        StackName=stack.stack_name,
        UsePreviousTemplate=True,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    def verify_stack():
        assert is_stack_updated(stack.stack_name)

    retry(verify_stack, retries=5, sleep_before=2, sleep=1)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not raising the correct error")
@pytest.mark.parametrize(
    "capability",
    [
        {"value": "CAPABILITY_IAM", "template": "iam_policy.yml"},
        {"value": "CAPABILITY_NAMED_IAM", "template": "iam_role_policy.yaml"},
    ],
)
# The AUTO_EXPAND option is used for macros
def test_update_with_capabilities(
    capability, deploy_cfn_template, cfn_client, snapshot, is_stack_updated
):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/", capability["template"])
    )

    parameter_key = "RoleName" if capability["value"] == "CAPABILITY_NAMED_IAM" else "Name"

    with pytest.raises(botocore.errorfactory.ClientError) as ex:
        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": parameter_key, "ParameterValue": f"{short_uid()}"}],
        )

    snapshot.match("error", ex.value.response)

    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        Capabilities=[capability["value"]],
        Parameters=[{"ParameterKey": parameter_key, "ParameterValue": f"{short_uid()}"}],
    )

    def verify_stack():
        assert is_stack_updated(stack.stack_name)

    retry(verify_stack, retries=10, sleep_before=4, sleep=1)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not raising the correct error")
def test_update_with_resource_types(deploy_cfn_template, cfn_client, is_stack_updated, snapshot):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    # Test with invalid type
    with pytest.raises(botocore.exceptions.ClientError) as ex:
        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            ResourceTypes=["AWS::EC2:*"],
            Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
        )

    snapshot.match("invalid_type_error", ex.value.response)

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            ResourceTypes=["AWS::EC2::*"],
            Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
        )

    snapshot.match("resource_not_allowed", ex.value.response)

    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        ResourceTypes=["AWS::SNS::Topic"],
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    def verify_stack():
        assert is_stack_updated(stack.stack_name)

    retry(verify_stack, retries=5, sleep_before=2, sleep=1)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Update value not being applied")
def test_set_notification_arn_with_update(deploy_cfn_template, cfn_client, sns_create_topic):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    topic_arn = sns_create_topic()["TopicArn"]

    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        NotificationARNs=[topic_arn],
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    description = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0]
    assert topic_arn in description["NotificationARNs"]


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Update value not being applied")
def test_update_tags(deploy_cfn_template, cfn_client):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    key = f"key-{short_uid()}"
    value = f"value-{short_uid()}"

    cfn_client.update_stack(
        StackName=stack.stack_name,
        Tags=[{"Key": key, "Value": value}],
        TemplateBody=template,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

    tags = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0]["Tags"]
    assert tags[0]["Key"] == key
    assert tags[0]["Value"] == value


@pytest.mark.aws_validated
@pytest.mark.skip(reason="The correct error is not being raised")
def test_no_template_error(deploy_cfn_template, cfn_client, snapshot):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        cfn_client.update_stack(StackName=stack.stack_name)

    snapshot.match("error", ex.value.response)


@pytest.mark.aws_validated
def test_no_parameters_update(deploy_cfn_template, cfn_client, is_stack_updated):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )

    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    cfn_client.update_stack(StackName=stack.stack_name, TemplateBody=template)

    def verify_stack():
        assert is_stack_updated(stack.stack_name)

    retry(verify_stack, retries=5, sleep_before=2, sleep=1)


# TODO implement next test
# def update with previous parameter value
# def test_update_with_role_without_permissions(deploy_cfn_template, cfn_client)
# def test_update_with_rollback_configurateion
