import os

from localstack.utils.cloudformation.template_preparer import template_to_json
from localstack.utils.common import load_file, short_uid


def load_template(tmpl_path: str) -> str:
    template = load_file(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "templates", tmpl_path)
    )
    return template_to_json(template)


def test_create_change_set_without_parameters(cfn_client):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template("sns_topic_simple.yaml"),
        ChangeSetType="CREATE",
    )
    try:
        change_set_id = response["Id"]
        stack_id = response["StackId"]
        assert change_set_id
        assert stack_id

        stack_response = cfn_client.describe_stacks(StackName=stack_id)
        assert stack_response["Stacks"][0]["StackStatus"] == "REVIEW_IN_PROGRESS"

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
        cfn_client.delete_change_set(ChangeSetName=change_set_name)
