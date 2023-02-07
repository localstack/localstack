import json
import os

import botocore.exceptions
import pytest
import yaml

from localstack.services.cloudformation.engine.yaml_parser import parse_yaml
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry, wait_until


class TestStacksApi:
    @pytest.mark.aws_validated
    def test_stack_lifecycle(self, cfn_client, is_stack_updated, deploy_cfn_template, snapshot):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.key_value("ParameterValue", "parameter-value"))
        api_name = f"test_{short_uid()}"
        template_path = os.path.join(os.path.dirname(__file__), "../../templates/simple_api.yaml")

        deployed = deploy_cfn_template(
            template_path=template_path,
            parameters={"ApiName": api_name},
        )
        stack_name = deployed.stack_name
        creation_description = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
        snapshot.match("creation", creation_description)

        api_name = f"test_{short_uid()}"
        deploy_cfn_template(
            is_update=True,
            stack_name=deployed.stack_name,
            template_path=template_path,
            parameters={"ApiName": api_name},
        )
        update_description = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
        snapshot.match("update", update_description)

        cfn_client.delete_stack(
            StackName=stack_name,
        )
        deletion_description = (
            "DeletionTime" in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
        )
        snapshot.match("deletion", deletion_description)

    @pytest.mark.aws_validated
    def test_stack_description_special_chars(self, cfn_client, deploy_cfn_template, snapshot):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())

        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "test <env>.test.net",
            "Resources": {
                "TestResource": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": "100.30.20.0/20"},
                }
            },
        }
        deployed = deploy_cfn_template(template=json.dumps(template))
        response = cfn_client.describe_stacks(StackName=deployed.stack_id)["Stacks"][0]
        snapshot.match("describe_stack", response)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize("fileformat", ["yaml", "json"])
    def test_get_template(self, cfn_client, deploy_cfn_template, snapshot, fileformat):
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

        template_original = cfn_client.get_template(
            StackName=stack.stack_id, TemplateStage="Original"
        )
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
        self,
        cfn_client,
        deploy_cfn_template,
        is_change_set_finished,
        is_change_set_created_and_available,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.key_value("PhysicalResourceId"))

        api_name = f"test_{short_uid()}"

        # create stack
        deployed = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/simple_api.yaml"
            ),
            parameters={"ApiName": api_name},
        )
        stack_name = deployed.stack_name
        stack_id = deployed.stack_id

        # assert snapshot of created stack
        snapshot.match("stack_created", cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0])

        # update stack, with one additional resource
        api_name = f"test_{short_uid()}"
        deploy_cfn_template(
            is_update=True,
            stack_name=deployed.stack_name,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/simple_api.update.yaml"
            ),
            parameters={"ApiName": api_name},
        )

        # assert snapshot of updated stack
        snapshot.match("stack_updated", cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0])

        # describe stack resources
        resources = cfn_client.describe_stack_resources(StackName=stack_name)
        snapshot.match("stack_resources", resources)

    def test_list_stack_resources_for_removed_resource(self, cfn_client, deploy_cfn_template):
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
        template_dict = parse_yaml(load_file(template_path))
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

    def test_update_stack_with_same_template(self, cfn_client, deploy_cfn_template):
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/fifo_queue.json")
        )
        stack = deploy_cfn_template(template=template)

        with pytest.raises(Exception) as ctx:  # TODO: capture proper exception
            cfn_client.update_stack(StackName=stack.stack_name, TemplateBody=template)
            cfn_client.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)

        error_message = str(ctx.value)
        assert "UpdateStack" in error_message
        assert "No updates are to be performed." in error_message

    @pytest.mark.skip_snapshot_verify(paths=["$..StackEvents"])
    def test_list_events_after_deployment(self, cfn_client, deploy_cfn_template, snapshot):
        snapshot.add_transformer(SortingTransformer("StackEvents", lambda x: x["Timestamp"]))
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
            )
        )
        response = cfn_client.describe_stack_events(StackName=stack.stack_name)
        snapshot.match("events", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="disable rollback not supported")
    @pytest.mark.parametrize("rollback_disabled, length_expected", [(False, 0), (True, 1)])
    def test_failure_options_for_stack_creation(
        self, cfn_client, rollback_disabled, length_expected
    ):
        template_with_error = open(
            os.path.join(os.path.dirname(__file__), "../../templates/multiple_bucket.yaml"), "r"
        ).read()

        stack_name = f"stack-{short_uid()}"
        bucket_1_name = f"bucket-{short_uid()}"
        bucket_2_name = f"bucket!#${short_uid()}"

        cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_with_error,
            DisableRollback=rollback_disabled,
            Parameters=[
                {"ParameterKey": "BucketName1", "ParameterValue": bucket_1_name},
                {"ParameterKey": "BucketName2", "ParameterValue": bucket_2_name},
            ],
        )

        assert wait_until(
            lambda _: stack_process_is_finished(cfn_client, stack_name),
            wait=10,
            strategy="exponential",
        )

        resources = cfn_client.describe_stack_resources(StackName=stack_name)["StackResources"]
        created_resources = [
            resource for resource in resources if "CREATE_COMPLETE" in resource["ResourceStatus"]
        ]
        assert len(created_resources) == length_expected

        cfn_client.delete_stack(StackName=stack_name)

    # TODO finish this test
    @pytest.mark.skip(reason="disable rollback not enabled")
    # @pytest.mark.aws_validated
    @pytest.mark.parametrize("rollback_disabled, length_expected", [(False, 2), (True, 1)])
    def test_failure_options_for_stack_update(self, cfn_client, rollback_disabled, length_expected):
        stack_name = f"stack-{short_uid()}"

        cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=open(
                os.path.join(os.path.dirname(__file__), "../../templates/multiple_kms_keys.yaml"),
                "r",
            ).read(),
            Parameters=[
                {"ParameterKey": "Usage", "ParameterValue": "SYMMETRIC_DEFAULT"},
            ],
        )

        assert wait_until(
            lambda _: stack_process_is_finished(cfn_client, stack_name),
        )
        resources = cfn_client.describe_stack_resources(StackName=stack_name)["StackResources"]
        created_resources = [
            resource for resource in resources if "CREATE_COMPLETE" in resource["ResourceStatus"]
        ]
        print(created_resources)

        cfn_client.update_stack(
            StackName=stack_name,
            TemplateBody=open(
                os.path.join(os.path.dirname(__file__), "../../templates/multiple_kms_keys.yaml"),
                "r",
            ).read(),
            DisableRollback=rollback_disabled,
            Parameters=[
                {"ParameterKey": "Usage", "ParameterValue": "Incorrect Value"},
            ],
        )

        assert wait_until(lambda _: stack_process_is_finished(cfn_client, stack_name))

        resources = cfn_client.describe_stack_resources(StackName=stack_name)["StackResources"]
        created_resources = [
            resource for resource in resources if "CREATE_COMPLETE" in resource["ResourceStatus"]
        ]
        print(created_resources)
        # assert len(created_resources) == length_expected

        cfn_client.delete_stack(StackName=stack_name)


def stack_process_is_finished(cfn_client, stack_name):
    return (
        "PROGRESS"
        not in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    )


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not Implemented")
def test_linting_error_during_creation(cfn_client, snapshot):
    stack_name = f"stack-{short_uid()}"
    bad_template = {"Resources": "", "Outputs": ""}

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        cfn_client.create_stack(StackName=stack_name, TemplateBody=json.dumps(bad_template))

    error_response = ex.value.response
    snapshot.match("error", error_response)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="feature not implemented")
def test_notifications(
    sqs_client,
    cfn_client,
    deploy_cfn_template,
    sns_create_topic,
    is_stack_created,
    is_stack_updated,
    sqs_create_queue,
    sns_create_sqs_subscription,
    cleanup_stacks,
):
    stack_name = f"stack-{short_uid()}"
    topic_arn = sns_create_topic()["TopicArn"]
    sqs_url = sqs_create_queue()
    sns_create_sqs_subscription(topic_arn, sqs_url)

    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )
    cfn_client.create_stack(
        StackName=stack_name,
        NotificationARNs=[topic_arn],
        TemplateBody=template,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )
    cleanup_stacks([stack_name])

    assert wait_until(is_stack_created(stack_name))

    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )
    cfn_client.update_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"},
        ],
    )
    assert wait_until(is_stack_updated(stack_name))

    messages = {}

    def _assert_messages():
        sqs_messages = sqs_client.receive_message(QueueUrl=sqs_url)["Messages"]
        for sqs_message in sqs_messages:
            sns_message = json.loads(sqs_message["Body"])
            messages.update({sns_message["MessageId"]: sns_message})

        # Assert notifications of resources created
        assert [message for message in messages.values() if "CREATE_" in message["Message"]]

        # Assert notifications of resources deleted
        assert [message for message in messages.values() if "UPDATE_" in message["Message"]]

        # Assert notifications of resources deleted
        assert [message for message in messages.values() if "DELETE_" in message["Message"]]

    retry(_assert_messages, retries=10, sleep=2)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="feature not implemented")
def test_prevent_stack_update(deploy_cfn_template, cfn_client, snapshot):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )
    stack = deploy_cfn_template(template=template, parameters={"TopicName": f"topic-{short_uid()}"})
    policy = {
        "Statement": [
            {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"},
        ]
    }
    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))

    policy = cfn_client.get_stack_policy(StackName=stack.stack_name)

    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"new-topic-{short_uid()}"}],
    )

    def _assert_failing_update_state():
        events = cfn_client.describe_stack_events(StackName=stack.stack_name)["StackEvents"]
        failed_event_update = [
            event for event in events if event["ResourceStatus"] == "UPDATE_FAILED"
        ]
        assert failed_event_update
        assert "Action denied by stack policy" in failed_event_update[0]["ResourceStatusReason"]

    try:
        retry(_assert_failing_update_state, retries=5, sleep=2, sleep_before=2)
    finally:
        progress_is_finished = False
        while not progress_is_finished:
            status = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0][
                "StackStatus"
            ]
            progress_is_finished = "PROGRESS" not in status
        cfn_client.delete_stack(StackName=stack.stack_name)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="feature not implemented")
def test_prevent_resource_deletion(deploy_cfn_template, cfn_client, sns_client, snapshot):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
    )

    template = template.replace("DeletionPolicy: Delete", "DeletionPolicy: Retain")
    stack = deploy_cfn_template(template=template, parameters={"TopicName": f"topic-{short_uid()}"})
    cfn_client.delete_stack(StackName=stack.stack_name)

    sns_client.get_topic_attributes(TopicArn=stack.outputs["TopicArn"])


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(
    paths=[
        # parameters may be out of order
        "$..Stacks..Parameters",
    ]
)
def test_updating_an_updated_stack_sets_status(deploy_cfn_template, cfn_client, snapshot):
    """
    The status of a stack that has been updated twice should be "UPDATE_COMPLETE"
    """
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    # need multiple templates to support updates to the stack
    template_1 = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/stack_update_1.yaml")
    )
    template_2 = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/stack_update_2.yaml")
    )
    template_3 = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/stack_update_3.yaml")
    )

    topic_1_name = f"topic-1-{short_uid()}"
    topic_2_name = f"topic-2-{short_uid()}"
    topic_3_name = f"topic-3-{short_uid()}"
    snapshot.add_transformers_list(
        [
            snapshot.transform.regex(topic_1_name, "topic-1"),
            snapshot.transform.regex(topic_2_name, "topic-2"),
            snapshot.transform.regex(topic_3_name, "topic-3"),
        ]
    )

    parameters = {
        "Topic1Name": topic_1_name,
        "Topic2Name": topic_2_name,
        "Topic3Name": topic_3_name,
    }

    def wait_for(waiter_type: str) -> None:
        cfn_client.get_waiter(waiter_type).wait(
            StackName=stack.stack_name,
            WaiterConfig={
                "Delay": 5,
                "MaxAttempts": 5,
            },
        )

    stack = deploy_cfn_template(template=template_1, parameters=parameters)
    wait_for("stack_create_complete")

    # update the stack
    deploy_cfn_template(
        template=template_2,
        is_update=True,
        stack_name=stack.stack_name,
        parameters=parameters,
    )
    wait_for("stack_update_complete")

    # update the stack again
    deploy_cfn_template(
        template=template_3,
        is_update=True,
        stack_name=stack.stack_name,
        parameters=parameters,
    )
    wait_for("stack_update_complete")

    res = cfn_client.describe_stacks(StackName=stack.stack_name)
    snapshot.match("describe-result", res)


@pytest.mark.aws_validated
def test_update_termination_protection(deploy_cfn_template, cfn_client, sns_client, snapshot):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("ParameterValue", "parameter-value"))

    # create stack
    api_name = f"test_{short_uid()}"
    template_path = os.path.join(os.path.dirname(__file__), "../../templates/simple_api.yaml")
    stack = deploy_cfn_template(template_path=template_path, parameters={"ApiName": api_name})

    # update termination protection (true)
    cfn_client.update_termination_protection(
        EnableTerminationProtection=True, StackName=stack.stack_name
    )
    res = cfn_client.describe_stacks(StackName=stack.stack_name)
    snapshot.match("describe-stack-1", res)

    # update termination protection (false)
    cfn_client.update_termination_protection(
        EnableTerminationProtection=False, StackName=stack.stack_name
    )
    res = cfn_client.describe_stacks(StackName=stack.stack_name)
    snapshot.match("describe-stack-2", res)
