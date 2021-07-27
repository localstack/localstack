import os

import jinja2
import pytest
from botocore.exceptions import ClientError

from localstack.utils.common import load_file, short_uid
from localstack.utils.generic.wait_utils import wait_until

# TODO: refactor fixtures to automatically cleanup resources
# TODO: use factory fixtures for common resources


def load_template(tmpl_path: str) -> str:
    template = load_file(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "templates", tmpl_path)
    )
    return template
    # return template_to_json(template)


def test_create_change_set_without_parameters(cfn_client, sns_client):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template("sns_topic_simple.yaml"),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    def is_change_set_created_and_available():
        check_set = cfn_client.describe_change_set(ChangeSetName=change_set_id)
        return (
            check_set.get("Status") == "CREATE_COMPLETE"
            and check_set.get("ExecutionStatus") == "AVAILABLE"
        )

    try:
        # make sure the change set wasn't executed (which would create a topic)
        list_topics_response = sns_client.list_topics()
        assert len(list_topics_response["Topics"]) == 0

        # stack is initially in REVIEW_IN_PROGRESS state. only after executing the change_set will it change its status
        stack_response = cfn_client.describe_stacks(StackName=stack_id)
        assert stack_response["Stacks"][0]["StackStatus"] == "REVIEW_IN_PROGRESS"

        # Change set can now either be already created/available or it is pending/unavailable
        wait_until(is_change_set_created_and_available, 2, 10, strategy="exponential")
        describe_response = cfn_client.describe_change_set(ChangeSetName=change_set_id)

        assert describe_response["ChangeSetName"] == change_set_name
        assert describe_response["ChangeSetId"] == change_set_id
        assert describe_response["StackId"] == stack_id
        assert describe_response["StackName"] == stack_name
        assert describe_response["ExecutionStatus"] == "AVAILABLE"
        assert describe_response["Status"] == "CREATE_COMPLETE"
        changes = describe_response["Changes"]
        assert len(changes) == 1
        assert changes[0]["Type"] == "Resource"
        assert changes[0]["ResourceChange"]["Action"] == "Add"
        assert changes[0]["ResourceChange"]["ResourceType"] == "AWS::SNS::Topic"
        assert changes[0]["ResourceChange"]["LogicalResourceId"] == "topic123"
    finally:
        wait_until(is_change_set_created_and_available, 2, 10, strategy="exponential")
        cfn_client.delete_change_set(ChangeSetName=change_set_name, StackName=stack_name)
        cfn_client.delete_stack(StackName=stack_id)


def is_aws_cloud() -> bool:
    return os.environ.get("TEST_TARGET", "") == "AWS_CLOUD"


# TODO: implement
@pytest.mark.xfail(condition=not is_aws_cloud(), reason="Not properly implemented")
def test_create_change_set_update_without_parameters(cfn_client, sns_client):
    """after creating a stack via a CREATE change set we send an UPDATE change set changing the SNS topic name"""
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    change_set_name2 = f"change-set-{short_uid()}"

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template("sns_topic_simple.yaml"),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    def is_change_set_created_and_available(id: str):
        def _inner():
            check_set = cfn_client.describe_change_set(ChangeSetName=id)
            return (
                check_set.get("Status") == "CREATE_COMPLETE"
                and check_set.get("ExecutionStatus") == "AVAILABLE"
            )

        return _inner

    def wait_for_finished(id: str):
        def _wait_for_finished():
            check_set = cfn_client.describe_change_set(ChangeSetName=id)
            return check_set["ExecutionStatus"] == "EXECUTE_COMPLETE"

        return _wait_for_finished

    try:
        # Change set can now either be already created/available or it is pending/unavailable
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(wait_for_finished(change_set_id), 2, 10, strategy="exponential", _max_wait=300)
        template = load_template("sns_topic_simple.yaml")

        update_response = cfn_client.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name2,
            TemplateBody=template.replace("sns-topic-simple", "sns-topic-simple-2"),
            ChangeSetType="UPDATE",
        )
        wait_until(is_change_set_created_and_available(update_response["Id"]))
        describe_response = cfn_client.describe_change_set(ChangeSetName=update_response["Id"])
        changes = describe_response["Changes"]
        assert len(changes) == 1
        assert changes[0]["Type"] == "Resource"
        change = changes[0]["ResourceChange"]
        assert change["Action"] == "Modify"
        assert change["ResourceType"] == "AWS::SNS::Topic"
        assert change["LogicalResourceId"] == "topic123"
        assert "sns-topic-simple" in change["PhysicalResourceId"]
        assert change["Replacement"] == "True"
        assert "Properties" in change["Scope"]
        assert len(change["Details"]) == 1
        assert change["Details"][0]["Target"]["Name"] == "TopicName"
        assert change["Details"][0]["Target"]["RequiresRecreation"] == "Always"
    finally:
        cfn_client.delete_change_set(ChangeSetName=change_set_name, StackName=stack_name)
        cfn_client.delete_change_set(ChangeSetName=change_set_name2, StackName=stack_name)
        cfn_client.delete_stack(StackName=stack_id)


@pytest.mark.skip(reason="TODO")
def test_create_change_set_with_template_url(cfn_client):
    pass


@pytest.mark.xfail(reason="change set type not implemented")
def test_create_change_set_create_existing(cfn_client):
    """tries to create an already existing stack"""

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template("sns_topic_simple.yaml"),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    cfn_client.execute_change_set(ChangeSetName=change_set_id)

    def wait_for_finished():
        check_set = cfn_client.describe_change_set(ChangeSetName=change_set_id)
        return check_set["ExecutionStatus"] == "EXECUTE_COMPLETE"

    wait_until(wait_for_finished)

    with pytest.raises(Exception) as ex:
        change_set_name2 = f"change-set-{short_uid()}"
        response = cfn_client.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name2,
            TemplateBody=load_template("sns_topic_simple.yaml"),
            ChangeSetType="CREATE",
        )
    assert ex is not None


def test_create_change_set_update_nonexisting(cfn_client):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    with pytest.raises(Exception) as ex:
        response = cfn_client.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_template("sns_topic_simple.yaml"),
            ChangeSetType="UPDATE",
        )
        change_set_id = response["Id"]
        stack_id = response["StackId"]
        assert change_set_id
        assert stack_id
    err = ex.value.response["Error"]
    assert err["Code"] == "ValidationError"
    assert "does not exist" in err["Message"]


@pytest.mark.skip(reason="TODO")
def test_create_change_set_import(cfn_client):
    """test importing existing resources into a stack via the change set"""
    pass  # TODO


def test_create_change_set_invalid_params(cfn_client):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    with pytest.raises(ClientError) as ex:
        cfn_client.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_template("sns_topic_simple.yaml"),
            ChangeSetType="INVALID",
        )
    err = ex.value.response["Error"]
    assert err["Code"] == "ValidationError"


def test_create_change_set_missing_stackname(cfn_client):
    """in this case boto doesn't even let us send the request"""
    change_set_name = f"change-set-{short_uid()}"
    with pytest.raises(Exception):
        cfn_client.create_change_set(
            StackName="",
            ChangeSetName=change_set_name,
            TemplateBody=load_template("sns_topic_simple.yaml"),
            ChangeSetType="CREATE",
        )


@pytest.mark.xfail(
    reason="ssm parameter resolution not implemented",
    condition=(os.environ.get("TEST_TARGET") != "AWS_CLOUD"),
)
def test_create_change_set_with_ssm_parameter(cfn_client, sns_client, ssm_client):
    """References a simple stack parameter"""

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    parameter_name = f"ls-param-{short_uid()}"
    parameter_value = f"ls-param-value-{short_uid()}"
    sns_topic_logical_id = "topic123"
    parameter_logical_id = "parameter123"

    ssm_client.put_parameter(Name=parameter_name, Value=parameter_value, Type="String")
    template = load_template("dynamicparameter_ssm_string.yaml")
    template_rendered = jinja2.Template(template).render(parameter_name=parameter_name)
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    def is_change_set_created_and_available():
        check_set = cfn_client.describe_change_set(ChangeSetName=change_set_id)
        return (
            check_set.get("Status") == "CREATE_COMPLETE"
            and check_set.get("ExecutionStatus") == "AVAILABLE"
        )

    try:
        # make sure the change set wasn't executed (which would create a new topic)
        list_topics_response = sns_client.list_topics()
        matching_topics = [
            t for t in list_topics_response["Topics"] if parameter_value in t["TopicArn"]
        ]
        assert matching_topics == []

        # stack is initially in REVIEW_IN_PROGRESS state. only after executing the change_set will it change its status
        stack_response = cfn_client.describe_stacks(StackName=stack_id)
        assert stack_response["Stacks"][0]["StackStatus"] == "REVIEW_IN_PROGRESS"

        # Change set can now either be already created/available or it is pending/unavailable
        wait_until(is_change_set_created_and_available, 2, 10, strategy="exponential")
        describe_response = cfn_client.describe_change_set(ChangeSetName=change_set_id)

        assert describe_response["ChangeSetName"] == change_set_name
        assert describe_response["ChangeSetId"] == change_set_id
        assert describe_response["StackId"] == stack_id
        assert describe_response["StackName"] == stack_name
        assert describe_response["ExecutionStatus"] == "AVAILABLE"
        assert describe_response["Status"] == "CREATE_COMPLETE"
        changes = describe_response["Changes"]
        assert len(changes) == 1
        assert changes[0]["Type"] == "Resource"
        assert changes[0]["ResourceChange"]["Action"] == "Add"
        assert changes[0]["ResourceChange"]["ResourceType"] == "AWS::SNS::Topic"
        assert changes[0]["ResourceChange"]["LogicalResourceId"] == sns_topic_logical_id

        parameters = describe_response["Parameters"]
        assert len(parameters) == 1
        assert parameters[0]["ParameterKey"] == parameter_logical_id
        assert parameters[0]["ParameterValue"] == parameter_name
        assert parameters[0]["ResolvedValue"] == parameter_value  # the important part

    finally:  # TODO: make part of fixture
        wait_until(is_change_set_created_and_available, 2, 10, strategy="exponential")
        cfn_client.delete_change_set(ChangeSetName=change_set_name, StackName=stack_name)
        cfn_client.delete_stack(StackName=stack_id)
        ssm_client.delete_parameter(Name=parameter_name)


def test_describe_change_set_nonexisting(cfn_client):
    with pytest.raises(Exception) as ex:
        cfn_client.describe_change_set(ChangeSetName="DoesNotExist")

    assert ex.value.response["Error"]["Code"] == "ResourceNotFoundException"


def test_execute_change_set(cfn_client, sns_client):
    """check if executing a change set succeeds in creating/modifying the resources in changed"""

    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template("sns_topic_simple.yaml"),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    cfn_client.execute_change_set(ChangeSetName=change_set_id)

    def wait_for_finished():
        check_set = cfn_client.describe_change_set(ChangeSetName=change_set_id)
        return check_set["ExecutionStatus"] == "EXECUTE_COMPLETE"

    wait_until(wait_for_finished)
    # check if stack resource was created
    topics = sns_client.list_topics()
    topic_arns = [t for t in map(lambda x: x["TopicArn"], topics["Topics"])]
    assert any([("sns-topic-simple" in t) for t in topic_arns])
    # TODO: cleanup creates resources


def test_delete_change_set_nonexisting(cfn_client):
    with pytest.raises(Exception) as ex:
        cfn_client.delete_change_set(ChangeSetName="DoesNotExist")

    assert ex.value.response["Error"]["Code"] == "ResourceNotFoundException"
