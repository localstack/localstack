import os

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


def test_use_previous_template_parameters(cfn_client, deploy_cfn_template, snapshot):
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}"},
    )


# def test_use_stack_policy_during_update

# def test_capabilities
