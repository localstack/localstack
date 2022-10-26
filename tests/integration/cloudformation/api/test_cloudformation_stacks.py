import json
import os

import pytest
import yaml

from localstack.testing.aws.cloudformation_utils import load_template_file
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid


@pytest.mark.aws_validated
def test_stack_time_attributes(cfn_client, is_stack_updated, deploy_cfn_template):
    api_name = f"test_{short_uid()}"
    template_path = os.path.join(os.path.dirname(__file__), "../../templates/simple_api.yaml")

    deployed = deploy_cfn_template(
        template_path=template_path,
        parameters={"ApiName": api_name},
    )
    stack_name = deployed.stack_name
    assert "CreationTime" in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]

    api_name = f"test_{short_uid()}"
    deploy_cfn_template(
        is_update=True,
        stack_name=deployed.stack_name,
        template_path=template_path,
        parameters={"ApiName": api_name},
    )

    assert "LastUpdatedTime" in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
    cfn_client.delete_stack(
        StackName=stack_name,
    )
    assert "DeletionTime" in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]


@pytest.mark.aws_validated
def test_stack_description_special_chars(cfn_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    template = """
AWSTemplateFormatVersion: "2010-09-09"
Description: 'test <env>.test.net'
Resources:
  TestResource:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: "100.30.20.0/20"
    """

    deployed = deploy_cfn_template(template=template)
    response = cfn_client.describe_stacks(StackName=deployed.stack_id)["Stacks"][0]
    snapshot.match("describe_stack", response)


@pytest.mark.aws_validated
@pytest.mark.parametrize("fileformat", ["yaml", "json"])
def test_get_template(cfn_client, deploy_cfn_template, snapshot, fileformat):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), f"../../templates/sns_topic_template.{fileformat}"
        )
    )
    topic_name = stack.outputs["TopicName"]
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"), priority=-1)

    describe_stacks = cfn_client.describe_stacks(StackName=stack.stack_id)
    snapshot.match("describe_stacks", describe_stacks)

    template_original = cfn_client.get_template(StackName=stack.stack_id, TemplateStage="Original")
    snapshot.match("template_original", template_original)

    template_processed = cfn_client.get_template(
        StackName=stack.stack_id, TemplateStage="Processed"
    )
    snapshot.match("template_processed", template_processed)


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(
    paths=["$..ParameterValue", "$..PhysicalResourceId", "$..Capabilities"]
)
def test_stack_update_resources(
    cfn_client,
    deploy_cfn_template,
    is_change_set_finished,
    is_change_set_created_and_available,
    snapshot,
):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("PhysicalResourceId"))

    api_name = f"test_{short_uid()}"
    template_path = os.path.join(os.path.dirname(__file__), "../../templates/simple_api.yaml")

    # create stack
    deployed = deploy_cfn_template(template_path=template_path, parameters={"ApiName": api_name})
    stack_name = deployed.stack_name
    stack_id = deployed.stack_id

    # assert snapshot of created stack
    snapshot.match("stack_created", cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0])

    # update stack, with one additional resource
    api_name = f"test_{short_uid()}"
    template_body = yaml.safe_load(load_template_file(template_path))
    template_body["Resources"]["Bucket"] = {"Type": "AWS::S3::Bucket"}
    deploy_cfn_template(
        is_update=True,
        stack_name=deployed.stack_name,
        template=json.dumps(template_body),
        parameters={"ApiName": api_name},
    )

    # assert snapshot of updated stack
    snapshot.match("stack_updated", cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0])

    # describe stack resources
    resources = cfn_client.describe_stack_resources(StackName=stack_name)
    snapshot.match("stack_resources", resources)


def test_list_stack_resources_for_removed_resource(cfn_client, deploy_cfn_template):
    template_path = os.path.join(
        os.path.dirname(__file__), "../../templates/eventbridge_policy.yaml"
    )
    event_bus_name = f"bus-{short_uid()}"
    stack = deploy_cfn_template(
        template_path=template_path,
        parameters={"EventBusName": event_bus_name},
    )

    resources = cfn_client.list_stack_resources(StackName=stack.stack_name)[
        "StackResourceSummaries"
    ]
    resources_before = len(resources)
    assert resources_before == 3
    statuses = set([res["ResourceStatus"] for res in resources])
    assert statuses == {"CREATE_COMPLETE"}

    # remove one resource from the template, then update stack (via change set)
    template_dict = yaml.safe_load(open(template_path))
    template_dict["Resources"].pop("eventPolicy2")
    template2 = yaml.dump(template_dict)

    deploy_cfn_template(
        stack_name=stack.stack_name,
        is_update=True,
        template=template2,
        parameters={"EventBusName": event_bus_name},
    )

    # get list of stack resources, again - make sure that deleted resource is not contained in result
    resources = cfn_client.list_stack_resources(StackName=stack.stack_name)[
        "StackResourceSummaries"
    ]
    assert len(resources) == resources_before - 1
    statuses = set([res["ResourceStatus"] for res in resources])
    assert statuses == {"UPDATE_COMPLETE"}


def test_update_stack_with_same_template(cfn_client, deploy_cfn_template):
    template = load_file(os.path.join(os.path.dirname(__file__), "../../templates/fifo_queue.json"))
    stack = deploy_cfn_template(template=template)

    with pytest.raises(Exception) as ctx:  # TODO: capture proper exception
        cfn_client.update_stack(StackName=stack.stack_name, TemplateBody=template)
        cfn_client.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)

    error_message = str(ctx.value)
    assert "UpdateStack" in error_message
    assert "No updates are to be performed." in error_message


@pytest.mark.skip_snapshot_verify(paths=["$..StackEvents"])
def test_list_events_after_deployment(cfn_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(SortingTransformer("StackEvents", lambda x: x["Timestamp"]))
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
        )
    )
    response = cfn_client.describe_stack_events(StackName=stack.stack_name)
    snapshot.match("events", response)
