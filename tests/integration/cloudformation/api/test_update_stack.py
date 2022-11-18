import os

import botocore.errorfactory
import pytest

from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@pytest.mark.aws_validated
def test_basic_update(cfn_client, deploy_cfn_template, is_stack_updated):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )

    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
        ),
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )

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
