import json
import os
from collections import OrderedDict
from itertools import permutations

import botocore.exceptions
import pytest
import yaml
from botocore.exceptions import WaiterError
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack.aws.api.cloudformation import Capability
from localstack.services.cloudformation.engine.yaml_parser import parse_yaml
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry, wait_until


class TestStacksApi:
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..ChangeSetId", "$..EnableTerminationProtection"]
    )
    @markers.aws.validated
    def test_stack_lifecycle(self, deploy_cfn_template, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.key_value("ParameterValue", "parameter-value"))
        api_name = f"test_{short_uid()}"
        template_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/simple_api.yaml"
        )

        deployed = deploy_cfn_template(
            template_path=template_path,
            parameters={"ApiName": api_name},
        )
        stack_name = deployed.stack_name
        creation_description = aws_client.cloudformation.describe_stacks(StackName=stack_name)[
            "Stacks"
        ][0]
        snapshot.match("creation", creation_description)

        api_name = f"test_{short_uid()}"
        deploy_cfn_template(
            is_update=True,
            stack_name=deployed.stack_name,
            template_path=template_path,
            parameters={"ApiName": api_name},
        )
        update_description = aws_client.cloudformation.describe_stacks(StackName=stack_name)[
            "Stacks"
        ][0]
        snapshot.match("update", update_description)

        aws_client.cloudformation.delete_stack(
            StackName=stack_name,
        )
        aws_client.cloudformation.get_waiter("stack_delete_complete").wait(StackName=stack_name)

        with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
            aws_client.cloudformation.describe_stacks(StackName=stack_name)
        snapshot.match("describe_deleted_by_name_exc", e.value.response)

        deleted = aws_client.cloudformation.describe_stacks(StackName=deployed.stack_id)["Stacks"][
            0
        ]
        assert "DeletionTime" in deleted
        snapshot.match("deleted", deleted)

    @markers.aws.validated
    def test_stack_description_special_chars(self, deploy_cfn_template, snapshot, aws_client):
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
        response = aws_client.cloudformation.describe_stacks(StackName=deployed.stack_id)["Stacks"][
            0
        ]
        snapshot.match("describe_stack", response)

    @markers.aws.validated
    def test_stack_name_creation(self, deploy_cfn_template, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())

        stack_name = f"*@{short_uid()}_$"

        with pytest.raises(Exception) as e:
            deploy_cfn_template(
                template_path=os.path.join(
                    os.path.dirname(__file__), "../../../templates/sns_topic_template.yaml"
                ),
                stack_name=stack_name,
            )

            snapshot.match("stack_response", e.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize("fileformat", ["yaml", "json"])
    def test_get_template(self, deploy_cfn_template, snapshot, fileformat, aws_client):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())

        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), f"../../../templates/sns_topic_template.{fileformat}"
            )
        )
        topic_name = stack.outputs["TopicName"]
        snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"), priority=-1)

        describe_stacks = aws_client.cloudformation.describe_stacks(StackName=stack.stack_id)
        snapshot.match("describe_stacks", describe_stacks)

        template_original = aws_client.cloudformation.get_template(
            StackName=stack.stack_id, TemplateStage="Original"
        )
        snapshot.match("template_original", template_original)

        template_processed = aws_client.cloudformation.get_template(
            StackName=stack.stack_id, TemplateStage="Processed"
        )
        snapshot.match("template_processed", template_processed)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..ParameterValue", "$..PhysicalResourceId", "$..Capabilities"]
    )
    def test_stack_update_resources(
        self,
        deploy_cfn_template,
        is_change_set_finished,
        is_change_set_created_and_available,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        snapshot.add_transformer(snapshot.transform.key_value("PhysicalResourceId"))

        api_name = f"test_{short_uid()}"

        # create stack
        deployed = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/simple_api.yaml"
            ),
            parameters={"ApiName": api_name},
        )
        stack_name = deployed.stack_name
        stack_id = deployed.stack_id

        # assert snapshot of created stack
        snapshot.match(
            "stack_created",
            aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0],
        )

        # update stack, with one additional resource
        api_name = f"test_{short_uid()}"
        deploy_cfn_template(
            is_update=True,
            stack_name=deployed.stack_name,
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/simple_api.update.yaml"
            ),
            parameters={"ApiName": api_name},
        )

        # assert snapshot of updated stack
        snapshot.match(
            "stack_updated",
            aws_client.cloudformation.describe_stacks(StackName=stack_id)["Stacks"][0],
        )

        # describe stack resources
        resources = aws_client.cloudformation.describe_stack_resources(StackName=stack_name)
        snapshot.match("stack_resources", resources)

    @markers.aws.needs_fixing
    def test_list_stack_resources_for_removed_resource(self, deploy_cfn_template, aws_client):
        template_path = os.path.join(
            os.path.dirname(__file__), "../../../templates/eventbridge_policy.yaml"
        )
        event_bus_name = f"bus-{short_uid()}"
        stack = deploy_cfn_template(
            template_path=template_path,
            parameters={"EventBusName": event_bus_name},
        )

        resources = aws_client.cloudformation.list_stack_resources(StackName=stack.stack_name)[
            "StackResourceSummaries"
        ]
        resources_before = len(resources)
        assert resources_before == 3
        statuses = {res["ResourceStatus"] for res in resources}
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
        resources = aws_client.cloudformation.list_stack_resources(StackName=stack.stack_name)[
            "StackResourceSummaries"
        ]
        assert len(resources) == resources_before - 1
        statuses = {res["ResourceStatus"] for res in resources}
        assert statuses == {"UPDATE_COMPLETE"}

    @markers.aws.validated
    def test_update_stack_with_same_template_withoutchange(
        self, deploy_cfn_template, aws_client, snapshot
    ):
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/simple_no_change.yaml")
        )
        stack = deploy_cfn_template(template=template)

        with pytest.raises(Exception) as ctx:  # TODO: capture proper exception
            aws_client.cloudformation.update_stack(
                StackName=stack.stack_name, TemplateBody=template
            )
            aws_client.cloudformation.get_waiter("stack_update_complete").wait(
                StackName=stack.stack_name
            )

        snapshot.match("no_change_exception", ctx.value.response)

    @markers.aws.validated
    def test_update_stack_with_same_template_withoutchange_transformation(
        self, deploy_cfn_template, aws_client
    ):
        template = load_file(
            os.path.join(
                os.path.dirname(__file__),
                "../../../templates/simple_no_change_with_transformation.yaml",
            )
        )
        stack = deploy_cfn_template(template=template)

        # transformations will always work even if there's no change in the template!
        aws_client.cloudformation.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            Capabilities=["CAPABILITY_AUTO_EXPAND"],
        )
        aws_client.cloudformation.get_waiter("stack_update_complete").wait(
            StackName=stack.stack_name
        )

    @markers.aws.validated
    def test_update_stack_actual_update(self, deploy_cfn_template, aws_client):
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/sqs_queue_update.yml")
        )
        queue_name = f"test-queue-{short_uid()}"
        stack = deploy_cfn_template(
            template=template, parameters={"QueueName": queue_name}, max_wait=360
        )

        queue_arn_1 = aws_client.sqs.get_queue_attributes(
            QueueUrl=stack.outputs["QueueUrl"], AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        assert queue_arn_1

        stack2 = deploy_cfn_template(
            template=template,
            stack_name=stack.stack_name,
            parameters={"QueueName": f"{queue_name}-new"},
            is_update=True,
            max_wait=360,
        )

        queue_arn_2 = aws_client.sqs.get_queue_attributes(
            QueueUrl=stack2.outputs["QueueUrl"], AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        assert queue_arn_2

        assert queue_arn_1 != queue_arn_2

    @markers.snapshot.skip_snapshot_verify(paths=["$..StackEvents"])
    @markers.aws.validated
    def test_list_events_after_deployment(self, deploy_cfn_template, snapshot, aws_client):
        snapshot.add_transformer(SortingTransformer("StackEvents", lambda x: x["Timestamp"]))
        snapshot.add_transformer(snapshot.transform.cloudformation_api())
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/sns_topic_simple.yaml"
            )
        )
        response = aws_client.cloudformation.describe_stack_events(StackName=stack.stack_name)
        snapshot.match("events", response)

    @markers.aws.validated
    @pytest.mark.skip(reason="disable rollback not supported")
    @pytest.mark.parametrize("rollback_disabled, length_expected", [(False, 0), (True, 1)])
    def test_failure_options_for_stack_creation(
        self, rollback_disabled, length_expected, aws_client
    ):
        template_with_error = open(
            os.path.join(os.path.dirname(__file__), "../../../templates/multiple_bucket.yaml"), "r"
        ).read()

        stack_name = f"stack-{short_uid()}"
        bucket_1_name = f"bucket-{short_uid()}"
        bucket_2_name = f"bucket!#${short_uid()}"

        aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template_with_error,
            DisableRollback=rollback_disabled,
            Parameters=[
                {"ParameterKey": "BucketName1", "ParameterValue": bucket_1_name},
                {"ParameterKey": "BucketName2", "ParameterValue": bucket_2_name},
            ],
        )

        assert wait_until(
            lambda _: stack_process_is_finished(aws_client.cloudformation, stack_name),
            wait=10,
            strategy="exponential",
        )

        resources = aws_client.cloudformation.describe_stack_resources(StackName=stack_name)[
            "StackResources"
        ]
        created_resources = [
            resource for resource in resources if "CREATE_COMPLETE" in resource["ResourceStatus"]
        ]
        assert len(created_resources) == length_expected

        aws_client.cloudformation.delete_stack(StackName=stack_name)

    @markers.aws.validated
    @pytest.mark.skipif(reason="disable rollback not enabled", condition=not is_aws_cloud())
    @pytest.mark.parametrize("rollback_disabled, length_expected", [(False, 2), (True, 1)])
    def test_failure_options_for_stack_update(
        self, rollback_disabled, length_expected, aws_client, cleanups
    ):
        stack_name = f"stack-{short_uid()}"
        template = open(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/multiple_bucket_update.yaml"
            ),
            "r",
        ).read()

        aws_client.cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template,
        )
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))

        def _assert_stack_process_finished():
            return stack_process_is_finished(aws_client.cloudformation, stack_name)

        assert wait_until(_assert_stack_process_finished)
        resources = aws_client.cloudformation.describe_stack_resources(StackName=stack_name)[
            "StackResources"
        ]
        created_resources = [
            resource for resource in resources if "CREATE_COMPLETE" in resource["ResourceStatus"]
        ]
        assert len(created_resources) == 2

        aws_client.cloudformation.update_stack(
            StackName=stack_name,
            TemplateBody=template,
            DisableRollback=rollback_disabled,
            Parameters=[
                {"ParameterKey": "Days", "ParameterValue": "-1"},
            ],
        )

        assert wait_until(_assert_stack_process_finished)

        resources = aws_client.cloudformation.describe_stack_resources(StackName=stack_name)[
            "StackResources"
        ]
        updated_resources = [
            resource
            for resource in resources
            if resource["ResourceStatus"] in ["CREATE_COMPLETE", "UPDATE_COMPLETE"]
        ]
        assert len(updated_resources) == length_expected


def stack_process_is_finished(cfn_client, stack_name):
    return (
        "PROGRESS"
        not in cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    )


@markers.aws.validated
@pytest.mark.skip(reason="Not Implemented")
def test_linting_error_during_creation(snapshot, aws_client):
    stack_name = f"stack-{short_uid()}"
    bad_template = {"Resources": "", "Outputs": ""}

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        aws_client.cloudformation.create_stack(
            StackName=stack_name, TemplateBody=json.dumps(bad_template)
        )

    error_response = ex.value.response
    snapshot.match("error", error_response)


@markers.aws.validated
@pytest.mark.skip(reason="feature not implemented")
def test_notifications(
    deploy_cfn_template,
    sns_create_topic,
    is_stack_created,
    is_stack_updated,
    sqs_create_queue,
    sns_create_sqs_subscription,
    cleanup_stacks,
    aws_client,
):
    stack_name = f"stack-{short_uid()}"
    topic_arn = sns_create_topic()["TopicArn"]
    sqs_url = sqs_create_queue()
    sns_create_sqs_subscription(topic_arn, sqs_url)

    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )
    aws_client.cloudformation.create_stack(
        StackName=stack_name,
        NotificationARNs=[topic_arn],
        TemplateBody=template,
        Parameters=[{"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"}],
    )
    cleanup_stacks([stack_name])

    assert wait_until(is_stack_created(stack_name))

    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/sns_topic_parameter.yml")
    )
    aws_client.cloudformation.update_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"},
        ],
    )
    assert wait_until(is_stack_updated(stack_name))

    messages = {}

    def _assert_messages():
        sqs_messages = aws_client.sqs.receive_message(QueueUrl=sqs_url)["Messages"]
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


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # parameters may be out of order
        "$..Stacks..Parameters",
    ]
)
def test_updating_an_updated_stack_sets_status(deploy_cfn_template, snapshot, aws_client):
    """
    The status of a stack that has been updated twice should be "UPDATE_COMPLETE"
    """
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    # need multiple templates to support updates to the stack
    template_1 = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/stack_update_1.yaml")
    )
    template_2 = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/stack_update_2.yaml")
    )
    template_3 = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/stack_update_3.yaml")
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
        aws_client.cloudformation.get_waiter(waiter_type).wait(
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

    res = aws_client.cloudformation.describe_stacks(StackName=stack.stack_name)
    snapshot.match("describe-result", res)


@markers.aws.validated
def test_update_termination_protection(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("ParameterValue", "parameter-value"))

    # create stack
    api_name = f"test_{short_uid()}"
    template_path = os.path.join(os.path.dirname(__file__), "../../../templates/simple_api.yaml")
    stack = deploy_cfn_template(template_path=template_path, parameters={"ApiName": api_name})

    # update termination protection (true)
    aws_client.cloudformation.update_termination_protection(
        EnableTerminationProtection=True, StackName=stack.stack_name
    )
    res = aws_client.cloudformation.describe_stacks(StackName=stack.stack_name)
    snapshot.match("describe-stack-1", res)

    # update termination protection (false)
    aws_client.cloudformation.update_termination_protection(
        EnableTerminationProtection=False, StackName=stack.stack_name
    )
    res = aws_client.cloudformation.describe_stacks(StackName=stack.stack_name)
    snapshot.match("describe-stack-2", res)


@markers.aws.validated
def test_events_resource_types(deploy_cfn_template, snapshot, aws_client):
    template_path = os.path.join(
        os.path.dirname(__file__), "../../../templates/cfn_cdk_sample_app.yaml"
    )
    stack = deploy_cfn_template(template_path=template_path, max_wait=500)
    events = aws_client.cloudformation.describe_stack_events(StackName=stack.stack_name)[
        "StackEvents"
    ]

    resource_types = list({event["ResourceType"] for event in events})
    resource_types.sort()
    snapshot.match("resource_types", resource_types)


@markers.aws.validated
def test_list_parameter_type(aws_client, deploy_cfn_template, cleanups):
    stack_name = f"test-stack-{short_uid()}"
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_parameter_list_type.yaml"
        ),
        parameters={
            "ParamsList": "foo,bar",
        },
    )

    assert stack.outputs["ParamValue"] == "foo|bar"


@markers.aws.validated
@pytest.mark.skipif(condition=not is_aws_cloud(), reason="rollback not implemented")
def test_blocked_stack_deletion(aws_client, cleanups, snapshot):
    """
    uses AWS::IAM::Policy for demonstrating this behavior

    1. create fails
    2. rollback fails even though create didn't even provision anything
    3. trying to delete the stack afterwards also doesn't work
    4. deleting the stack with retain resources works
    """
    cfn = aws_client.cloudformation
    stack_name = f"test-stacks-blocked-{short_uid()}"
    policy_name = f"test-broken-policy-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.regex(policy_name, "<policy-name>"))
    template_body = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/iam_policy_invalid.yaml")
    )
    waiter_config = {"Delay": 1, "MaxAttempts": 20}

    snapshot.add_transformer(snapshot.transform.key_value("PhysicalResourceId"))
    snapshot.add_transformer(
        snapshot.transform.key_value("ResourceStatusReason", reference_replacement=False)
    )

    stack = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": "Name", "ParameterValue": policy_name}],
        Capabilities=[Capability.CAPABILITY_NAMED_IAM],
    )
    stack_id = stack["StackId"]
    cleanups.append(lambda: cfn.delete_stack(StackName=stack_id, RetainResources=["BrokenPolicy"]))
    with pytest.raises(WaiterError):
        cfn.get_waiter("stack_create_complete").wait(StackName=stack_id, WaiterConfig=waiter_config)
    stack_post_create = cfn.describe_stacks(StackName=stack_id)
    snapshot.match("stack_post_create", stack_post_create)

    cfn.delete_stack(StackName=stack_id)
    with pytest.raises(WaiterError):
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_id, WaiterConfig=waiter_config)
    stack_post_fail_delete = cfn.describe_stacks(StackName=stack_id)
    snapshot.match("stack_post_fail_delete", stack_post_fail_delete)

    cfn.delete_stack(StackName=stack_id, RetainResources=["BrokenPolicy"])
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_id, WaiterConfig=waiter_config)
    stack_post_success_delete = cfn.describe_stacks(StackName=stack_id)
    snapshot.match("stack_post_success_delete", stack_post_success_delete)
    stack_events = cfn.describe_stack_events(StackName=stack_id)
    snapshot.match("stack_events", stack_events)


MINIMAL_TEMPLATE = """
Resources:
    SimpleParam:
        Type: AWS::SSM::Parameter
        Properties:
            Value: test
            Type: String
"""


@markers.snapshot.skip_snapshot_verify(
    paths=["$..EnableTerminationProtection", "$..LastUpdatedTime"]
)
@markers.aws.validated
def test_name_conflicts(aws_client, snapshot, cleanups):
    """
    Tests behavior of creating a stack with the same name of one that was previously deleted

    1. Create Stack
    2. Delete Stack
    3. Create Stack with same name as in 1.

    Step 3 should be successful because you can re-use StackNames,
    but only one stack for a given stack name can be `ACTIVE` at one time.

    We didn't exhaustively test yet what is considered as Active by CloudFormation
    For now the assumption is that anything != "DELETE_COMPLETED" is considered "ACTIVE"
    """
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    stack_name = f"repeated-stack-{short_uid()}"
    cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
    stack = aws_client.cloudformation.create_stack(
        StackName=stack_name, TemplateBody=MINIMAL_TEMPLATE
    )
    stack_id = stack["StackId"]
    aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)

    # only one can be active at a time
    with pytest.raises(aws_client.cloudformation.exceptions.AlreadyExistsException) as e:
        aws_client.cloudformation.create_stack(StackName=stack_name, TemplateBody=MINIMAL_TEMPLATE)
    snapshot.match("create_stack_already_exists_exc", e.value.response)

    created_stack_desc = aws_client.cloudformation.describe_stacks(StackName=stack_name)["Stacks"][
        0
    ]["StackStatus"]
    snapshot.match("created_stack_desc", created_stack_desc)

    aws_client.cloudformation.delete_stack(StackName=stack_name)
    aws_client.cloudformation.get_waiter("stack_delete_complete").wait(StackName=stack_name)

    # describe with name fails
    with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
        aws_client.cloudformation.describe_stacks(StackName=stack_name)
    snapshot.match("deleted_stack_not_found_exc", e.value.response)

    # describe events with name fails
    with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
        aws_client.cloudformation.describe_stack_events(StackName=stack_name)
    snapshot.match("deleted_stack_events_not_found_by_name", e.value.response)

    # describe with stack id (ARN) succeeds
    deleted_stack_desc = aws_client.cloudformation.describe_stacks(StackName=stack_id)
    snapshot.match("deleted_stack_desc", deleted_stack_desc)

    # creating a new stack with the same name as the previously deleted one should work
    stack = aws_client.cloudformation.create_stack(
        StackName=stack_name, TemplateBody=MINIMAL_TEMPLATE
    )
    # should issue a new unique stack ID/ARN
    new_stack_id = stack["StackId"]
    assert stack_id != new_stack_id
    aws_client.cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)

    new_stack_desc = aws_client.cloudformation.describe_stacks(StackName=stack_name)
    snapshot.match("new_stack_desc", new_stack_desc)
    assert len(new_stack_desc["Stacks"]) == 1
    assert new_stack_desc["Stacks"][0]["StackId"] == new_stack_id

    # can still access both by using the ARN (stack id)
    # and they should be different from each other
    stack_id_desc = aws_client.cloudformation.describe_stacks(StackName=stack_id)
    new_stack_id_desc = aws_client.cloudformation.describe_stacks(StackName=new_stack_id)
    snapshot.match("stack_id_desc", stack_id_desc)
    snapshot.match("new_stack_id_desc", new_stack_id_desc)

    # check if the describing the stack events return the right stack
    stack_events = aws_client.cloudformation.describe_stack_events(StackName=stack_name)[
        "StackEvents"
    ]
    assert all(stack_event["StackId"] == new_stack_id for stack_event in stack_events)
    # describing events by the old stack id should still yield the old events
    stack_events = aws_client.cloudformation.describe_stack_events(StackName=stack_id)[
        "StackEvents"
    ]
    assert all(stack_event["StackId"] == stack_id for stack_event in stack_events)

    # deleting the stack by name should delete the new, not already deleted stack
    aws_client.cloudformation.delete_stack(StackName=stack_name)
    aws_client.cloudformation.get_waiter("stack_delete_complete").wait(StackName=stack_name)
    # describe with stack id returns stack deleted
    deleted_stack_desc = aws_client.cloudformation.describe_stacks(StackName=new_stack_id)
    snapshot.match("deleted_second_stack_desc", deleted_stack_desc)


@markers.aws.validated
def test_describe_stack_events_errors(aws_client, snapshot):
    with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
        aws_client.cloudformation.describe_stack_events()
    snapshot.match("describe_stack_events_no_stack_name", e.value.response)
    with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
        aws_client.cloudformation.describe_stack_events(StackName="does-not-exist")
    snapshot.match("describe_stack_events_stack_not_found", e.value.response)


TEMPLATE_ORDER_CASES = list(permutations(["A", "B", "C"]))


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..StackId",
        # TODO
        "$..PhysicalResourceId",
        # TODO
        "$..ResourceProperties",
    ]
)
@pytest.mark.parametrize(
    "deploy_order", TEMPLATE_ORDER_CASES, ids=["-".join(vals) for vals in TEMPLATE_ORDER_CASES]
)
def test_stack_deploy_order(deploy_cfn_template, aws_client, snapshot, deploy_order: tuple[str]):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("EventId"))
    resources = {
        "A": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {
                "Type": "String",
                "Value": "root",
            },
        },
        "B": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {
                "Type": "String",
                "Value": {
                    "Ref": "A",
                },
            },
        },
        "C": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {
                "Type": "String",
                "Value": {
                    "Ref": "B",
                },
            },
        },
    }

    resources = OrderedDict(
        [
            (logical_resource_id, resources[logical_resource_id])
            for logical_resource_id in deploy_order
        ]
    )
    assert len(resources) == 3

    stack = deploy_cfn_template(
        template=json.dumps(
            {
                "Resources": resources,
            }
        )
    )

    stack.destroy()

    events = aws_client.cloudformation.describe_stack_events(
        StackName=stack.stack_id,
    )["StackEvents"]

    filtered_events = []
    for event in events:
        # only the resources we care about
        if event["LogicalResourceId"] not in deploy_order:
            continue

        # only _COMPLETE events
        if not event["ResourceStatus"].endswith("_COMPLETE"):
            continue

        filtered_events.append(event)

    # sort by event time
    filtered_events.sort(key=lambda e: e["Timestamp"])

    snapshot.match("events", filtered_events)
