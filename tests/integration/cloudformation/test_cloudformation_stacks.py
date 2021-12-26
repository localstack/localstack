import jinja2
import yaml

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
        assert any(parameter_value in t for t in topic_arns)
    finally:
        cleanup_stacks([stack_id])
        # TODO: cleanup parameter


def test_list_stack_resources_for_removed_resource(
    cfn_client, is_stack_created, is_change_set_finished
):
    event_bus_name = f"bus-{short_uid()}"
    template = jinja2.Template(load_template_raw("eventbridge_policy.yaml")).render(
        event_bus_name=event_bus_name
    )

    stack_name = f"stack-{short_uid()}"

    response = cfn_client.create_stack(StackName=stack_name, TemplateBody=template)
    stack_id = response["StackId"]
    assert stack_id
    wait_until(is_stack_created(stack_id))

    # get list of stack resources
    resources = cfn_client.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    resources_before = len(resources)
    assert resources_before == 3
    statuses = set([res["ResourceStatus"] for res in resources])
    assert statuses == {"CREATE_COMPLETE", "UPDATE_COMPLETE"}

    # remove one resource from the template, then update stack (via change set)
    template_dict = yaml.load(template)
    template_dict["Resources"].pop("eventPolicy2")
    template2 = yaml.dump(template_dict)

    response = cfn_client.create_change_set(
        StackName=stack_name, ChangeSetName="cs1", TemplateBody=template2
    )
    change_set_id = response["Id"]
    cfn_client.execute_change_set(ChangeSetName=change_set_id)
    wait_until(is_change_set_finished(change_set_id))

    # get list of stack resources, again - make sure that deleted resource is not contained in result
    resources = cfn_client.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert len(resources) == resources_before - 1
    statuses = set([res["ResourceStatus"] for res in resources])
    assert statuses == {"CREATE_COMPLETE", "UPDATE_COMPLETE"}


# TODO: more tests
