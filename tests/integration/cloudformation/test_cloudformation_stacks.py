import jinja2

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_create_stack_with_ssm_parameters(
    cfn_client, ssm_client, sns_client, cleanup_stacks, is_stack_created
):
    stack_name = f"stack-{short_uid()}"
    parameter_name = f"ls-param-{short_uid()}"
    parameter_value = f"ls-param-value-{short_uid()}"
    parameter_logical_id = "parameter123"
    ssm_client.put_parameter(Name=parameter_name, Value=parameter_value, Type="String")
    template = load_template_raw("dynamicparameter_ssm_string.yaml")
    template_rendered = jinja2.Template(template).render(parameter_name=parameter_name)
    response = cfn_client.create_stack(
        StackName=stack_name,
        TemplateBody=template_rendered,
    )
    stack_id = response["StackId"]
    assert stack_id

    try:
        wait_until(is_stack_created(stack_id))

        created_stack = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
        assert created_stack is not None
        assert created_stack["Parameters"][0]["ParameterKey"] == parameter_logical_id
        assert created_stack["Parameters"][0]["ParameterValue"] == parameter_name
        assert created_stack["Parameters"][0]["ResolvedValue"] == parameter_value

        topics = sns_client.list_topics()
        topic_arns = [t["TopicArn"] for t in topics["Topics"]]
        assert any([parameter_value in t for t in topic_arns])
    finally:
        cleanup_stacks([stack_id])
        # TODO: cleanup parameter


# TODO: more tests
