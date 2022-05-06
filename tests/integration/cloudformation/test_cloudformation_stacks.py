import jinja2
import pytest
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


@pytest.mark.xfail(reason="outputs don't behave well in combination with conditions")
@pytest.mark.aws_validated
def test_parameter_usepreviousvalue_behavior(cfn_client, cleanups):
    stack_name = f"stack-{short_uid()}"
    cleanups.append(lambda _: cfn_client.delete_stack(StackName=stack_name))

    # 1. create with overridden default value. Due to the condition this should neither create the optional topic, nor the corresponding output
    create_response = cfn_client.create_stack(
        StackName=stack_name,
        TemplateBody=load_template_raw("cfn_reuse_param.yaml"),
        Parameters=[{"ParameterKey": "DeployParam", "ParameterValue": "no"}],
    )
    stack_id = create_response["StackId"]

    def wait_stack_done():
        return cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] in [
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
        ]

    assert wait_until(wait_stack_done)
    stack_describe_response = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 1

    # 2. update using UsePreviousValue. DeployParam should still be "no", still overriding the default and the only change should be the changed tag on the required topic
    cfn_client.update_stack(
        StackName=stack_name,
        TemplateBody=load_template_raw("cfn_reuse_param.yaml"),
        Parameters=[
            {"ParameterKey": "CustomTag", "ParameterValue": "trigger-change"},
            {"ParameterKey": "DeployParam", "UsePreviousValue": True},
        ],
    )
    assert wait_until(wait_stack_done)
    stack_describe_response = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 1

    # 3. update with setting the deployparam to "yes" not. The condition will evaluate to true and thus create the topic + output
    # note: for an even trickier challenge for the cloudformation engine, remove the second parameter key. Behavior should stay the same.
    cfn_client.update_stack(
        StackName=stack_name,
        TemplateBody=load_template_raw("cfn_reuse_param.yaml"),
        Parameters=[
            {"ParameterKey": "CustomTag", "ParameterValue": "trigger-change-2"},
            {"ParameterKey": "DeployParam", "ParameterValue": "yes"},
        ],
    )
    assert wait_until(wait_stack_done)
    stack_describe_response = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 2
